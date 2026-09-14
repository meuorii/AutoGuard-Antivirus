from pathlib import Path
from types import SimpleNamespace

from app.cleanup_verifier import CleanupVerifier
from app.config import AppConfig
from app.database import Database
from app.detector import Detector
from app.hashing import normalize_path
from app.incidents import IncidentService, IncidentStatus
from app.matching_cleanup import MatchingCopyCleanup
from app.models import ScanSessionStatus, ScanSource, ScanType
from app.quarantine import QuarantineService
from app.reappearance import ReappearanceWatch
from app.scan_history import ScanHistory
from app.scanner import ScanInterruptedError, Scanner
from app.signatures import AUTOGUARD_TEST_CONTENT, load_signatures
from app.threat_trail import ThreatTrail
from app.usb_monitor import RemovableDrive, USBEventType, USBMonitor


class FakeDiscovery:
    def __init__(self, drives=()): self.drives, self.calls = tuple(drives), 0
    def list_drives(self): self.calls += 1; return self.drives


class FakeScanner:
    def __init__(self): self.calls = []
    def scan_directory(self, path, source=None, *, scan_type=None, interrupt_check=None):
        self.calls.append((normalize_path(path), source, scan_type, interrupt_check))
        return SimpleNamespace(session_id=f"session-{len(self.calls)}")


class InterruptingFakeScanner(FakeScanner):
    def scan_directory(self, path, source=None, *, scan_type=None, interrupt_check=None):
        self.calls.append((normalize_path(path), source, scan_type, interrupt_check))
        raise ScanInterruptedError("simulated drive removal", session_id="usb-session")


def make_drive(root: Path, device_id="usb-test-1"):
    root.mkdir(parents=True, exist_ok=True); return RemovableDrive(root, device_id, "TEST USB")


def test_newly_detected_drive_is_queued_and_records_detection_event(tmp_path):
    drive = make_drive(tmp_path / "USB"); discovery = FakeDiscovery((drive,)); monitor = USBMonitor(FakeScanner(), discovery)
    present = monitor.poll_once()
    assert present == (drive,) and monitor.health().drives_detected == 1 and monitor.health().scans_queued == 1
    events = monitor.recent_events()
    assert [e.event_type for e in events] == [USBEventType.USB_DETECTED] and "does not establish an infection origin" in events[0].message


def test_same_insertion_does_not_trigger_duplicate_full_scan(tmp_path):
    drive = make_drive(tmp_path / "USB"); discovery = FakeDiscovery((drive,)); scanner = FakeScanner(); monitor = USBMonitor(scanner, discovery)
    monitor.poll_once(); monitor.poll_once(); monitor.poll_once()
    assert monitor.health().scans_queued == 1 and monitor.process_pending_once() and len(scanner.calls) == 1
    monitor.poll_once()
    assert monitor.health().scans_queued == 1 and not monitor.process_pending_once()


def test_removal_and_reinsertion_create_new_insertion_and_new_scan(tmp_path):
    drive = make_drive(tmp_path / "USB"); discovery = FakeDiscovery((drive,)); scanner = FakeScanner(); monitor = USBMonitor(scanner, discovery)
    monitor.poll_once(); monitor.process_pending_once(); discovery.drives = (); monitor.poll_once(); discovery.drives = (drive,); monitor.poll_once(); monitor.process_pending_once()
    assert len(scanner.calls) == 2 and monitor.health().drives_detected == 2 and monitor.health().devices_removed == 1
    detected = [e for e in monitor.recent_events() if e.event_type is USBEventType.USB_DETECTED]
    assert [e.insertion_number for e in detected] == [1, 2] and any(e.event_type is USBEventType.DEVICE_REMOVED for e in monitor.recent_events())


def test_removed_before_scan_is_reported_interrupted_without_dispatch(tmp_path):
    drive = make_drive(tmp_path / "USB"); discovery = FakeDiscovery((drive,)); scanner = FakeScanner(); monitor = USBMonitor(scanner, discovery)
    monitor.poll_once(); discovery.drives = (); monitor.poll_once()
    assert monitor.process_pending_once() and scanner.calls == [] and monitor.recent_scan_outcomes()[-1].status is ScanSessionStatus.INCOMPLETE
    types = [e.event_type for e in monitor.recent_events()]
    assert USBEventType.DEVICE_REMOVED in types and USBEventType.SCAN_INTERRUPTED in types and monitor.health().scans_interrupted == 1


def test_scan_dispatch_uses_usb_source_and_usb_scan_type(tmp_path):
    drive = make_drive(tmp_path / "USB"); scanner = FakeScanner(); monitor = USBMonitor(scanner, FakeDiscovery((drive,)))
    monitor.poll_once()
    assert monitor.process_pending_once() and len(scanner.calls) == 1
    path, source, scan_type, interrupt_check = scanner.calls[0]
    assert path == normalize_path(drive.root) and source is ScanSource.USB and scan_type is ScanType.USB and callable(interrupt_check)
    assert [e.event_type for e in monitor.recent_events()] == [USBEventType.USB_DETECTED, USBEventType.SCAN_STARTED, USBEventType.SCAN_COMPLETED]


def test_worker_interruption_is_reported_without_crashing_monitor(tmp_path):
    drive = make_drive(tmp_path / "USB"); scanner = InterruptingFakeScanner(); monitor = USBMonitor(scanner, FakeDiscovery((drive,)))
    monitor.poll_once()
    assert monitor.process_pending_once()
    outcome = monitor.recent_scan_outcomes()[-1]
    assert outcome.status is ScanSessionStatus.INCOMPLETE and outcome.session_id == "usb-session" and monitor.health().scans_interrupted == 1 and monitor.health().scan_failures == 0 and monitor.recent_events()[-1].event_type is USBEventType.SCAN_INTERRUPTED


def test_real_scanner_external_interrupt_creates_incomplete_usb_session(tmp_path):
    config = AppConfig(data_dir=tmp_path / "runtime"); config.create_directories()
    database = Database(config.database_path); database.initialize()
    scanner = Scanner(Detector(load_signatures()), ThreatTrail(database))
    drive = tmp_path / "USB"; drive.mkdir(); (drive / "file.txt").write_bytes(b"ordinary content")
    try:
        scanner.scan_directory(drive, ScanSource.USB, scan_type=ScanType.USB, interrupt_check=lambda: True)
    except ScanInterruptedError as error:
        assert error.session_id is not None; saved = scanner.history.get_scan(error.session_id)
    else: raise AssertionError("USB scan should have been interrupted")
    assert saved is not None and saved.session.scan_type is ScanType.USB and saved.session.source is ScanSource.USB and saved.session.status is ScanSessionStatus.INCOMPLETE and "interrupted" in (saved.session.error or "").lower()


def test_clean_usb_scan_completes_through_existing_scanner_pipeline(tmp_path):
    config = AppConfig(data_dir=tmp_path / "runtime"); config.create_directories()
    database = Database(config.database_path); database.initialize()
    scanner = Scanner(Detector(load_signatures()), ThreatTrail(database))
    drive = make_drive(tmp_path / "USB"); (drive.root / "clean.txt").write_bytes(b"ordinary harmless USB content"); monitor = USBMonitor(scanner, FakeDiscovery((drive,)))
    monitor.poll_once()
    assert monitor.process_pending_once()
    outcome = monitor.recent_scan_outcomes()[-1]
    assert outcome.status is ScanSessionStatus.COMPLETED and outcome.session_id is not None
    details = scanner.history.get_scan(outcome.session_id)
    assert details.session.scan_type is ScanType.USB and details.session.source is ScanSource.USB and details.session.status is ScanSessionStatus.COMPLETED and details.session.counters["scanned_files"] == 1 and details.session.counters["dangerous_detections"] == 0 and monitor.recent_events()[-1].event_type is USBEventType.SCAN_COMPLETED


def test_explicit_repeat_configuration_can_rescan_same_mounted_drive(tmp_path):
    drive = make_drive(tmp_path / "USB"); scanner = FakeScanner(); monitor = USBMonitor(scanner, FakeDiscovery((drive,)), scan_once_per_insertion=False)
    monitor.poll_once(); monitor.process_pending_once(); monitor.poll_once(); monitor.process_pending_once()
    assert len(scanner.calls) == 2


def test_high_confidence_usb_detection_uses_existing_security_pipeline(tmp_path):
    config = AppConfig(data_dir=tmp_path / "runtime"); config.create_directories()
    database = Database(config.database_path); database.initialize()
    incidents = IncidentService(database); quarantine = QuarantineService(database, config.quarantine_dir, incidents); trail = ThreatTrail(database)
    drive = make_drive(tmp_path / "USB")
    matching_cleanup = MatchingCopyCleanup(database, incidents, quarantine, trail, monitored_locations=(drive.root,))
    verifier = CleanupVerifier(database, incidents, quarantine, monitored_locations=(drive.root,))
    scanner = Scanner(Detector(load_signatures()), trail, incidents=incidents, quarantine=quarantine, matching_cleanup=matching_cleanup, cleanup_verifier=verifier, reappearance=ReappearanceWatch(database, incidents))
    threat = drive.root / "harmless-autoguard-test.bin"; threat.write_bytes(AUTOGUARD_TEST_CONTENT); monitor = USBMonitor(scanner, FakeDiscovery((drive,)))
    monitor.poll_once()
    assert monitor.process_pending_once()
    outcome = monitor.recent_scan_outcomes()[-1]
    assert outcome.status is ScanSessionStatus.COMPLETED and not threat.exists()
    quarantine_items = quarantine.list_quarantined_items()
    assert len(quarantine_items) == 1 and quarantine_items[0].original_source is ScanSource.USB
    active = incidents.get_active_incidents()
    assert len(active) == 1 and active[0].status is IncidentStatus.CONTAINED
    details = scanner.history.get_scan(outcome.session_id)
    assert details.session.source is ScanSource.USB and details.session.counters["dangerous_detections"] == 1 and scanner.last_cleanup_verification_results[-1].remaining_matching_copies == 0