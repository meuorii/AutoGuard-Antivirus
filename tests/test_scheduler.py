import threading
import time
from pathlib import Path
from types import SimpleNamespace

from app.models import ScanSource, ScanType
from app.scheduler import (
    DispatchStatus,
    ScanKind,
    ScanScheduler,
    ScheduleSettings,
)


class FakeBackend:
    def __init__(self):
        self.jobs = []
        self.started = False
        self.shutdown_calls = []

    def add_job(self, func, trigger, **kwargs):
        self.jobs.append((func, trigger, kwargs))

    def start(self):
        self.started = True

    def shutdown(self, wait=True):
        self.shutdown_calls.append(wait)
        self.started = False


class RecordingScanner:
    def __init__(self):
        self.calls = []

    def scan(self, path, source, *, scan_type, interrupt_check=None):
        self.calls.append((Path(path), source, scan_type, interrupt_check))
        return SimpleNamespace(session_id=f"session-{len(self.calls)}")


class BlockingScanner(RecordingScanner):
    def __init__(self):
        super().__init__()
        self.entered = threading.Event()
        self.release = threading.Event()

    def scan(self, path, source, *, scan_type, interrupt_check=None):
        self.calls.append((Path(path), source, scan_type, interrupt_check))
        self.entered.set()
        while not self.release.wait(0.01):
            if interrupt_check is not None and interrupt_check():
                break
        return SimpleNamespace(session_id="blocking-session")


def wait_until(predicate, timeout=2.0):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return True
        time.sleep(0.01)
    return bool(predicate())


def test_schedule_defaults_are_24_hours_and_7_days(tmp_path):
    backend = FakeBackend()
    scanner = RecordingScanner()
    scheduler = ScanScheduler(
        scanner,
        quick_paths=(tmp_path,),
        full_paths=(tmp_path,),
        scheduler_factory=lambda: backend,
    )

    health = scheduler.start()

    assert health.running and backend.started
    jobs = {kwargs["id"]: (trigger, kwargs) for _, trigger, kwargs in backend.jobs}
    quick_trigger, quick = jobs[ScanScheduler.QUICK_JOB_ID]
    full_trigger, full = jobs[ScanScheduler.FULL_JOB_ID]
    assert quick_trigger == full_trigger == "interval"
    assert quick["hours"] == 24.0
    assert full["days"] == 7.0
    assert quick["max_instances"] == full["max_instances"] == 1
    assert quick["coalesce"] is True and full["coalesce"] is True
    scheduler.stop()


def test_custom_scheduling_configuration_is_forwarded_to_apscheduler(tmp_path):
    backend = FakeBackend()
    settings = ScheduleSettings(quick_interval_hours=6, full_interval_days=3)
    scheduler = ScanScheduler(
        RecordingScanner(), quick_paths=(tmp_path,), full_paths=(tmp_path,),
        settings=settings, scheduler_factory=lambda: backend,
    )
    scheduler.start()
    jobs = {kwargs["id"]: kwargs for _, _, kwargs in backend.jobs}
    assert jobs[ScanScheduler.QUICK_JOB_ID]["hours"] == 6
    assert jobs[ScanScheduler.FULL_JOB_ID]["days"] == 3
    scheduler.stop()


def test_startup_scan_is_dispatched_in_background_with_startup_history_metadata(tmp_path):
    scanner = RecordingScanner()
    scheduler = ScanScheduler(scanner, quick_paths=(tmp_path,), full_paths=(tmp_path,))

    dispatch = scheduler.dispatch_startup_scan()

    assert dispatch.status is DispatchStatus.DISPATCHED
    assert wait_until(lambda: len(scanner.calls) == 1)
    path, source, scan_type, _ = scanner.calls[0]
    assert path == tmp_path
    assert source is ScanSource.STARTUP
    assert scan_type is ScanType.STARTUP
    assert wait_until(lambda: not scheduler.health().quick_scan_running)


def test_duplicate_quick_scan_is_prevented_while_startup_quick_scan_runs(tmp_path):
    scanner = BlockingScanner()
    scheduler = ScanScheduler(scanner, quick_paths=(tmp_path,), full_paths=(tmp_path,))

    first = scheduler.dispatch_startup_scan()
    assert first.accepted and scanner.entered.wait(1.0)

    duplicate = scheduler.dispatch_quick_scan()
    assert duplicate.status is DispatchStatus.SKIPPED_ALREADY_RUNNING
    assert len(scanner.calls) == 1

    scanner.release.set()
    assert wait_until(lambda: not scheduler.health().quick_scan_running)


def test_quick_and_full_scans_may_run_independently(tmp_path):
    scanner = BlockingScanner()
    scheduler = ScanScheduler(scanner, quick_paths=(tmp_path,), full_paths=(tmp_path,))

    quick = scheduler.dispatch_quick_scan()
    assert quick.accepted and scanner.entered.wait(1.0)
    full = scheduler.dispatch_full_scan()
    assert full.accepted
    assert wait_until(lambda: len(scanner.calls) == 2)

    scanner.release.set()
    assert wait_until(
        lambda: not scheduler.health().quick_scan_running
        and not scheduler.health().full_scan_running
    )


def test_scheduled_quick_scan_uses_scheduled_source_and_quick_scan_type(tmp_path):
    scanner = RecordingScanner()
    scheduler = ScanScheduler(scanner, quick_paths=(tmp_path,), full_paths=(tmp_path,))

    assert scheduler.dispatch_quick_scan().accepted
    assert wait_until(lambda: len(scanner.calls) == 1)
    _, source, scan_type, _ = scanner.calls[0]
    assert source is ScanSource.SCHEDULED
    assert scan_type is ScanType.QUICK


def test_scheduler_stop_shuts_down_backend_and_requests_worker_interrupt(tmp_path):
    backend = FakeBackend()
    scanner = BlockingScanner()
    scheduler = ScanScheduler(
        scanner, quick_paths=(tmp_path,), full_paths=(tmp_path,),
        scheduler_factory=lambda: backend,
    )
    scheduler.start()
    scheduler.dispatch_startup_scan()
    assert scanner.entered.wait(1.0)

    health = scheduler.stop(wait=True, timeout=1.0)

    assert backend.shutdown_calls == [True]
    assert not health.running
    assert wait_until(lambda: not scheduler.health().quick_scan_running)


def test_scheduler_exposes_backend_next_run_times_for_tray(tmp_path):
    from datetime import datetime, timedelta, timezone

    class IntrospectableBackend(FakeBackend):
        def __init__(self):
            super().__init__()
            self.next_by_id = {}

        def add_job(self, func, trigger, **kwargs):
            super().add_job(func, trigger, **kwargs)
            now = datetime.now(timezone.utc)
            if kwargs["id"] == ScanScheduler.QUICK_JOB_ID:
                self.next_by_id[kwargs["id"]] = now + timedelta(hours=kwargs["hours"])
            else:
                self.next_by_id[kwargs["id"]] = now + timedelta(days=kwargs["days"])

        def get_job(self, job_id):
            value = self.next_by_id.get(job_id)
            return SimpleNamespace(next_run_time=value) if value is not None else None

    backend = IntrospectableBackend()
    scheduler = ScanScheduler(
        RecordingScanner(), quick_paths=(tmp_path,), full_paths=(tmp_path,),
        scheduler_factory=lambda: backend,
    )
    scheduler.start()
    times = scheduler.next_run_times()
    try:
        assert times["quick"] is not None
        assert times["full"] is not None
        assert times["full"] > times["quick"]
    finally:
        scheduler.stop()