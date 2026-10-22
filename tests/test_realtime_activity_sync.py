from __future__ import annotations

from app.database import Database
from app.file_monitor import FileMonitor
from app.hashing import normalize_path
from app.models import DetectionResult, DetectionStatus, ScanSource, ScanType
from app.scan_history import ScanHistory
from app.scanner import Scanner
from app.threat_trail import ThreatTrail


class SafeDetector:
    def detect_inspection(self, inspection):
        fingerprint = inspection.fingerprint
        return DetectionResult(
            DetectionStatus.NO_DETECTION, 0.0, "Test content is safe.",
            "test-safe", fingerprint.sha256, fingerprint.path,
        )


def test_realtime_monitor_persists_actual_scan_events_once_and_activity_reads_only(tmp_path):
    database = Database(tmp_path / "activity.db")
    database.initialize()
    history = ScanHistory(database)
    trail = ThreatTrail(database)
    scanner = Scanner(SafeDetector(), trail, history=history)
    monitored = tmp_path / "Downloads"
    monitored.mkdir()
    file_path = monitored / "日本語-파일-資料.txt"
    file_path.write_text("first version", encoding="utf-8")
    clock = {"value": 10.0}
    monitor = FileMonitor(
        scanner, (monitored,), debounce_seconds=1.0,
        stability_period_seconds=0.0, clock=lambda: clock["value"],
        sleep=lambda _seconds: None,
    )

    assert history.scan_date_page()["total"] == 0
    assert monitor.queue_path(file_path)
    assert not monitor.queue_path(file_path, event_type="modified")
    assert monitor.process_pending_once()

    with database.connection() as connection:
        rows = connection.execute(
            """SELECT ss.scan_type, ss.source, ss.status, ss.discovered_files,
                      sr.path, sr.session_id
               FROM scan_results sr JOIN scan_sessions ss ON ss.id = sr.session_id"""
        ).fetchall()
    assert len(rows) == 1
    assert rows[0]["scan_type"] == ScanType.REAL_TIME.value
    assert rows[0]["source"] == ScanSource.FILE_MONITOR.value
    assert rows[0]["path"] == str(normalize_path(file_path))
    assert rows[0]["status"] == "COMPLETED"
    assert rows[0]["discovered_files"] == 1
    assert rows[0]["session_id"]
    with database.connection() as connection:
        assert connection.execute("PRAGMA foreign_key_check").fetchall() == []

    # Activity reads, including repeated redraw requests, do not create evidence.
    local_day = history.scan_date_page()["items"][0]["local_date"]
    for _ in range(4):
        assert history.daily_results_page(local_day)["summary"]["total"] == 1
    with database.connection() as connection:
        assert connection.execute("SELECT COUNT(*) FROM scan_results").fetchone()[0] == 1

    # A later real filesystem change is a new scan-result event, even at the same path.
    file_path.write_text("changed version", encoding="utf-8")
    clock["value"] += 1.1
    assert monitor.queue_path(file_path, event_type="modified")
    assert monitor.process_pending_once()
    assert history.daily_results_page(local_day)["summary"]["total"] == 2


def test_monitor_health_reports_current_background_scan_path(tmp_path):
    import threading
    from types import SimpleNamespace

    class BlockingScanner:
        def __init__(self):
            self.started = threading.Event()
            self.release = threading.Event()

        def scan_file(self, path, source=None, *, scan_type=None):
            self.started.set()
            self.release.wait(2)
            return SimpleNamespace(path=str(path))

    monitored = tmp_path / "Downloads"
    monitored.mkdir()
    target = monitored / "active.txt"
    target.write_text("test", encoding="utf-8")
    scanner = BlockingScanner()
    monitor = FileMonitor(scanner, (monitored,), stability_period_seconds=0.0)
    assert monitor.queue_path(target)
    worker = threading.Thread(target=monitor.process_pending_once)
    worker.start()
    try:
        assert scanner.started.wait(1)
        assert monitor.health().active_paths == (str(normalize_path(target)),)
    finally:
        scanner.release.set()
        worker.join(2)
    assert monitor.health().active_paths == ()


def test_usb_monitor_health_reports_active_usb_scan(tmp_path):
    import threading
    from types import SimpleNamespace

    from app.usb_monitor import RemovableDrive, USBMonitor

    class Discovery:
        def list_drives(self):
            return (RemovableDrive(tmp_path / "USB", "test-device"),)

    class BlockingScanner:
        def __init__(self):
            self.started = threading.Event()
            self.release = threading.Event()

        def scan_directory(self, path, source=None, *, scan_type=None, interrupt_check=None):
            self.started.set()
            self.release.wait(2)
            return SimpleNamespace(session_id="usb-test-session")

    root = tmp_path / "USB"
    root.mkdir()
    scanner = BlockingScanner()
    monitor = USBMonitor(scanner, discovery=Discovery())
    monitor.poll_once()
    worker = threading.Thread(target=monitor.process_pending_once)
    worker.start()
    try:
        assert scanner.started.wait(1)
        assert monitor.health().active_roots == (str(normalize_path(root)),)
    finally:
        scanner.release.set()
        worker.join(2)
    assert monitor.health().active_roots == ()
