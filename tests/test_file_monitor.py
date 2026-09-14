from pathlib import Path
from types import SimpleNamespace

import pytest

from app.file_monitor import FileMonitor, MonitorStatus, _WatchdogHandler
from app.hashing import normalize_path
from app.models import ScanSource, ScanType

class FakeClock:
    def __init__(self) -> None: self.value = 100.0
    def __call__(self) -> float: return self.value
    def sleep(self, seconds: float) -> None: self.value += seconds

class FakeScanner:
    def __init__(self) -> None: self.calls = []
    def scan_file(self, path, source=None, *, scan_type=None): self.calls.append((normalize_path(path), source, scan_type)); return SimpleNamespace(path=str(path))

class FakeObserver:
    def __init__(self) -> None: self.scheduled = []; self.alive = False
    def schedule(self, event_handler, path, recursive=True) -> None: self.scheduled.append((event_handler, normalize_path(path), recursive))
    def start(self) -> None: self.alive = True
    def stop(self) -> None: self.alive = False
    def join(self, timeout=None) -> None: pass
    def is_alive(self) -> bool: return self.alive

def build_monitor(tmp_path, **overrides):
    downloads, desktop, documents, quarantine, database = tmp_path / "Downloads", tmp_path / "Desktop", tmp_path / "Documents", tmp_path / "AutoGuardData" / "quarantine", tmp_path / "AutoGuardData" / "database"
    for path in (downloads, desktop, documents, quarantine, database): path.mkdir(parents=True, exist_ok=True)
    clock, scanner = overrides.pop("clock", FakeClock()), overrides.pop("scanner", FakeScanner())
    monitor = FileMonitor(scanner, (downloads, desktop, documents), ignored_paths=(quarantine, database), debounce_seconds=overrides.pop("debounce_seconds", 1.0), stability_period_seconds=overrides.pop("stability_period_seconds", 0.5), stability_poll_seconds=overrides.pop("stability_poll_seconds", 0.25), stability_timeout_seconds=overrides.pop("stability_timeout_seconds", 2.0), clock=clock, sleep=overrides.pop("sleep", clock.sleep), **overrides)
    return monitor, scanner, clock, downloads, desktop, documents, quarantine, database

def test_event_filtering_for_created_modified_and_moved_files(tmp_path):
    monitor, _, _, downloads, desktop, _, _, _ = build_monitor(tmp_path)
    created, modified, moved = downloads / "created.bin", downloads / "modified.bin", desktop / "finished-download.exe"
    assert monitor.handle_event("created", created); assert monitor.handle_event("modified", modified); assert monitor.handle_event("moved", downloads / "part.tmp", dest_path=moved)
    assert not monitor.handle_event("deleted", downloads / "gone.bin"); assert not monitor.handle_event("created", downloads / "folder", is_directory=True); assert not monitor.handle_event("created", tmp_path / "Outside" / "outside.bin")
    assert monitor.health().events_queued == 3

def test_watchdog_handler_only_queues_and_uses_move_destination(tmp_path):
    monitor, _, _, downloads, desktop, _, _, _ = build_monitor(tmp_path); handler = _WatchdogHandler(monitor)
    handler.on_created(SimpleNamespace(src_path=str(downloads / "a.bin"), is_directory=False)); handler.on_modified(SimpleNamespace(src_path=str(downloads / "b.bin"), is_directory=False)); handler.on_moved(SimpleNamespace(src_path=str(downloads / "partial.tmp"), dest_path=str(desktop / "complete.bin"), is_directory=False))
    assert monitor.health().events_queued == 3

def test_debounce_prevents_duplicate_pending_and_recent_scans(tmp_path):
    monitor, scanner, clock, downloads, _, _, _, _ = build_monitor(tmp_path); path = downloads / "burst.bin"; path.write_bytes(b"stable")
    assert monitor.queue_path(path); assert not monitor.queue_path(path, event_type="modified"); assert monitor.process_pending_once(); assert len(scanner.calls) == 1
    assert not monitor.queue_path(path); clock.value += 1.01; assert monitor.queue_path(path); assert monitor.health().events_debounced == 2

def test_stability_check_waits_for_unchanged_size_and_mtime(tmp_path):
    clock, sequence = FakeClock(), iter([SimpleNamespace(st_size=10, st_mtime_ns=1, st_mode=0o100644), SimpleNamespace(st_size=20, st_mtime_ns=2, st_mode=0o100644), SimpleNamespace(st_size=20, st_mtime_ns=2, st_mode=0o100644), SimpleNamespace(st_size=20, st_mtime_ns=2, st_mode=0o100644)])
    monitor, _, _, downloads, _, _, _, _ = build_monitor(tmp_path, clock=clock, sleep=clock.sleep, stat_func=lambda path: next(sequence), stability_period_seconds=0.5, stability_poll_seconds=0.25)
    result = monitor.check_stability(downloads / "downloading.bin")
    assert result.stable; assert result.size_bytes == 20 and result.mtime_ns == 2; assert clock.value >= 100.75

def test_stability_timeout_is_not_falsely_reported_as_ready(tmp_path):
    clock, counter = FakeClock(), {"n": 0}
    def changing_stat(path): counter["n"] += 1; return SimpleNamespace(st_size=counter["n"], st_mtime_ns=counter["n"], st_mode=0o100644)
    monitor, _, _, downloads, _, _, _, _ = build_monitor(tmp_path, clock=clock, sleep=clock.sleep, stat_func=changing_stat, stability_period_seconds=0.5, stability_poll_seconds=0.25, stability_timeout_seconds=0.75)
    result = monitor.check_stability(downloads / "never-stable.bin")
    assert not result.stable; assert "did not become stable" in result.reason

def test_ignored_application_directories_never_queue(tmp_path):
    monitor, _, _, _, _, _, quarantine, database = build_monitor(tmp_path)
    assert not monitor.queue_path(quarantine / "abc.agq"); assert not monitor.queue_path(database / "autoguard.db"); assert not monitor.handle_event("modified", database / "autoguard.db-wal")
    assert monitor.health().events_queued == 0

def test_scan_dispatch_uses_real_time_file_monitor_pipeline(tmp_path):
    monitor, scanner, _, downloads, _, _, _, _ = build_monitor(tmp_path); path = downloads / "ready.bin"; path.write_bytes(b"ready")
    assert monitor.queue_path(path); assert monitor.process_pending_once()
    assert scanner.calls == [(normalize_path(path), ScanSource.FILE_MONITOR, ScanType.REAL_TIME)]
    health = monitor.health(); assert health.scans_dispatched == 1; assert health.scan_failures == 0

def test_missing_file_is_reported_as_stability_failure_without_scan(tmp_path):
    monitor, scanner, _, downloads, _, _, _, _ = build_monitor(tmp_path); path = downloads / "disappeared.bin"
    assert monitor.queue_path(path); assert monitor.process_pending_once(); assert scanner.calls == []
    health = monitor.health(); assert health.stability_failures == 1; assert "no longer exists" in health.last_error

def test_start_stop_health_and_scheduled_paths_with_fake_observer(tmp_path):
    observer = FakeObserver()
    monitor, _, _, downloads, desktop, documents, _, _ = build_monitor(tmp_path, observer_factory=lambda: observer)
    health = monitor.start()
    assert health.status is MonitorStatus.RUNNING; assert health.observer_alive and health.workers_alive == 1
    assert {path for _, path, recursive in observer.scheduled if recursive} == {normalize_path(downloads), normalize_path(desktop), normalize_path(documents)}
    stopped = monitor.stop()
    assert stopped.status is MonitorStatus.STOPPED; assert not stopped.running

def test_start_rejects_configuration_when_no_monitored_directory_exists(tmp_path):
    monitor = FileMonitor(FakeScanner(), (tmp_path / "missing-a", tmp_path / "missing-b"), observer_factory=FakeObserver)
    with pytest.raises(ValueError, match="None of the configured"): monitor.start()