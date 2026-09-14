import sqlite3, threading, time
from pathlib import Path

from app.config import AppConfig
from app.models import ScanSource, ScanType
from app.scheduler import DispatchStatus, ScanDispatch, ScanKind, ScanScheduler
from app.startup import AutoGuardStartup, StartupSettings


class FakeBackend:
    def __init__(self): self.jobs, self.started, self.stopped = [], False, False
    def add_job(self, func, trigger, **kwargs): self.jobs.append((func, trigger, kwargs))
    def start(self): self.started = True
    def shutdown(self, wait=True): self.stopped, self.started = True, False


class FakeMonitor:
    def __init__(self, *args, log=None, name="monitor", **kwargs): self.log, self.name, self.started, self.stopped = log, name, False, False
    def start(self):
        self.started = True
        if self.log is not None: self.log.append(f"{self.name}:start")
        return self
    def stop(self, timeout=5.0):
        self.stopped = True
        if self.log is not None: self.log.append(f"{self.name}:stop")
        return self


class OrderedScheduler:
    def __init__(self, *args, log=None, **kwargs): self.log, self.settings, self.stopped = log, kwargs.get("settings"), False
    def start(self): self.log.append("scheduler:start"); return self
    def dispatch_startup_scan(self): self.log.append("startup:dispatch"); return ScanDispatch(DispatchStatus.DISPATCHED, ScanKind.QUICK, "fake-startup")
    def stop(self, wait=True, timeout=5.0): self.stopped = True; self.log.append("scheduler:stop"); return self


def wait_until(predicate, timeout=3.0):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate(): return True
        time.sleep(0.01)
    return bool(predicate())


def test_initialize_creates_runtime_storage_database_and_services(tmp_path):
    runtime, config, backend = tmp_path / "runtime", AppConfig(data_dir=tmp_path / "runtime"), FakeBackend()
    application = AutoGuardStartup(config, StartupSettings(file_monitor_enabled=False, usb_monitor_enabled=False), apscheduler_factory=lambda: backend)
    services = application.initialize()
    assert config.database_path.exists() and config.quarantine_dir.is_dir() and config.logs_dir.is_dir()
    assert len(services.signatures) >= 1 and services.scanner.threat_trail is services.threat_trail
    with sqlite3.connect(config.database_path) as connection:
        names = {row[0] for row in connection.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    assert {"scan_sessions", "threat_incidents", "quarantine_items"} <= names


def test_startup_service_order_opens_interface_after_scan_dispatch(tmp_path):
    log = []
    file_factory = lambda *args, **kwargs: FakeMonitor(*args, log=log, name="file", **kwargs)
    usb_factory = lambda *args, **kwargs: FakeMonitor(*args, log=log, name="usb", **kwargs)
    scheduler_factory = lambda *args, **kwargs: OrderedScheduler(*args, log=log, **kwargs)
    settings = StartupSettings(monitor_paths=(tmp_path,), quick_scan_paths=(tmp_path,), full_scan_paths=(tmp_path,), usb_monitor_enabled=True)
    application = AutoGuardStartup(AppConfig(data_dir=tmp_path / "runtime"), settings, file_monitor_factory=file_factory, usb_monitor_factory=usb_factory, scheduler_factory=scheduler_factory)
    application.start(lambda services: log.append("interface:open"))
    assert log[:5] == ["file:start", "usb:start", "scheduler:start", "startup:dispatch", "interface:open"]
    application.shutdown()


def test_real_startup_scan_does_not_block_interface_and_is_stored_in_history(tmp_path):
    protected = tmp_path / "protected"
    protected.mkdir()
    for index in range(20): (protected / f"file-{index}.txt").write_bytes((b"safe-content-" + str(index).encode()) * 100)
    backend, settings = FakeBackend(), StartupSettings(file_monitor_enabled=False, usb_monitor_enabled=False, monitor_paths=(protected,), quick_scan_paths=(protected,), full_scan_paths=(protected,))
    application = AutoGuardStartup(AppConfig(data_dir=tmp_path / "runtime"), settings, apscheduler_factory=lambda: backend)
    interface_called, returned = threading.Event(), threading.Event()
    def interface(_services): interface_called.set(); returned.set()
    services = application.start(interface)
    assert interface_called.is_set() and returned.is_set()
    assert services.startup_dispatch is not None and services.startup_dispatch.accepted
    assert wait_until(lambda: not services.scheduler.health().quick_scan_running)
    scans = services.scanner.history.recent_scans(10)
    assert scans and all(scan.scan_type is ScanType.STARTUP for scan in scans) and all(scan.source is ScanSource.STARTUP for scan in scans)
    application.shutdown()


def test_shutdown_stops_scheduler_usb_and_file_monitor(tmp_path):
    log = []
    file_factory = lambda *args, **kwargs: FakeMonitor(*args, log=log, name="file", **kwargs)
    usb_factory = lambda *args, **kwargs: FakeMonitor(*args, log=log, name="usb", **kwargs)
    scheduler_factory = lambda *args, **kwargs: OrderedScheduler(*args, log=log, **kwargs)
    application = AutoGuardStartup(AppConfig(data_dir=tmp_path / "runtime"), StartupSettings(monitor_paths=(tmp_path,), quick_scan_paths=(tmp_path,), full_scan_paths=(tmp_path,), usb_monitor_enabled=True), file_monitor_factory=file_factory, usb_monitor_factory=usb_factory, scheduler_factory=scheduler_factory)
    services = application.start()
    report = application.shutdown()
    assert report.scheduler_stopped and report.usb_monitor_stopped and report.file_monitor_stopped and report.errors == ()
    assert services.file_monitor.stopped and services.usb_monitor.stopped and services.scheduler.stopped
    assert log[-3:] == ["scheduler:stop", "usb:stop", "file:stop"]


def test_scheduler_can_be_disabled_while_startup_scan_still_dispatches(tmp_path):
    protected = tmp_path / "protected"
    protected.mkdir()
    (protected / "safe.txt").write_text("safe", encoding="utf-8")
    backend = FakeBackend()
    application = AutoGuardStartup(AppConfig(data_dir=tmp_path / "runtime"), StartupSettings(scheduler_enabled=False, file_monitor_enabled=False, usb_monitor_enabled=False, monitor_paths=(protected,), quick_scan_paths=(protected,), full_scan_paths=(protected,)), apscheduler_factory=lambda: backend)
    services = application.start()
    assert not backend.started and services.startup_dispatch is not None and services.startup_dispatch.accepted
    assert wait_until(lambda: not services.scheduler.health().quick_scan_running)
    application.shutdown()


def test_scheduled_quick_scan_is_persisted_in_scan_history(tmp_path):
    protected = tmp_path / "protected"
    protected.mkdir()
    (protected / "scheduled-safe.txt").write_text("scheduled safe content", encoding="utf-8")
    application = AutoGuardStartup(AppConfig(data_dir=tmp_path / "runtime"), StartupSettings(startup_quick_scan_enabled=False, scheduler_enabled=False, file_monitor_enabled=False, usb_monitor_enabled=False, monitor_paths=(protected,), quick_scan_paths=(protected,), full_scan_paths=(protected,)), apscheduler_factory=lambda: FakeBackend())
    services = application.initialize()
    dispatch = services.scheduler.dispatch_quick_scan()
    assert dispatch.accepted and wait_until(lambda: not services.scheduler.health().quick_scan_running)
    scans = services.scanner.history.recent_scans(5)
    assert len(scans) == 1 and scans[0].scan_type is ScanType.QUICK and scans[0].source is ScanSource.SCHEDULED
    application.shutdown()