from pathlib import Path; import pytest; from app.config import AppConfig; from app.database import Database; from app.detector import Detector; from app.hashing import normalize_path; from app.incidents import IncidentEventType, IncidentService, IncidentStatus; from app.models import DetectionStatus, ScanSource; from app.scanner import Scanner; from app.signatures import AUTOGUARD_TEST_CONTENT, AUTOGUARD_TEST_SHA256, load_signatures; from app.threat_trail import ThreatTrail

@pytest.fixture
def setup(tmp_path):
    config = AppConfig(data_dir=tmp_path / "runtime"); config.create_directories(); database = Database(config.database_path); database.initialize(); service = IncidentService(database); files = tmp_path / "files"; files.mkdir(); detector = Detector(load_signatures())
    return service, database, detector, files

def high_detection(detector: Detector, path: Path):
    path.write_bytes(AUTOGUARD_TEST_CONTENT); result = detector.detect_file(path)
    assert result.status is DetectionStatus.HIGH_CONFIDENCE
    return result

def test_database_initializes_incident_tables(setup):
    _, database, _, _ = setup
    with database.connection() as connection:
        names = {row["name"] for row in connection.execute("SELECT name FROM sqlite_master WHERE type = 'table'")}
    assert {"threat_incidents", "incident_files", "incident_events"} <= names

def test_incident_creation_records_first_observed_location(setup):
    service, _, detector, files = setup; path = files / "first.txt"; detection = high_detection(detector, path); incident = service.record_high_confidence_detection(detection, ScanSource.MANUAL); details = service.get_incident(incident.id)
    assert details is not None; assert details.incident.sha256 == AUTOGUARD_TEST_SHA256; assert details.incident.status is IncidentStatus.OPEN; assert details.incident.first_observed_path == str(normalize_path(path)); assert details.incident.detection_count == 1; assert len(details.files) == 1; assert details.files[0].path == str(normalize_path(path)); assert details.files[0].first_source is ScanSource.MANUAL; assert details.files[0].last_source is ScanSource.MANUAL; assert details.files[0].seen_count == 1; assert details.files[0].first_detection_reason == detection.reason; assert len(details.events) == 1; assert details.events[0].event_type is IncidentEventType.FIRST_OBSERVED; assert details.events[0].path == str(normalize_path(path)); assert details.events[0].source is ScanSource.MANUAL; assert details.events[0].detection_reason == detection.reason

def test_matching_locations_share_one_incident_by_sha256(setup):
    service, _, detector, files = setup; first = high_detection(detector, files / "first.txt"); second = high_detection(detector, files / "usb-copy.txt"); one = service.record_high_confidence_detection(first, ScanSource.MANUAL); two = service.record_high_confidence_detection(second, ScanSource.USB); details = service.get_incident(one.id)
    assert two.id == one.id; assert details.incident.detection_count == 2; assert {item.path for item in details.files} == {str(normalize_path(files / "first.txt")), str(normalize_path(files / "usb-copy.txt"))}; assert [event.event_type for event in details.events] == [IncidentEventType.FIRST_OBSERVED, IncidentEventType.MATCHING_LOCATION_OBSERVED]; assert details.events[-1].source is ScanSource.USB

def test_repeated_detection_refreshes_same_location(setup):
    service, _, detector, files = setup; path = files / "repeat.txt"; detection = high_detection(detector, path); first = service.record_high_confidence_detection(detection, ScanSource.MANUAL); second = service.record_high_confidence_detection(detection, ScanSource.SCHEDULED); details = service.get_incident(first.id)
    assert second.id == first.id; assert details.incident.detection_count == 2; assert len(details.files) == 1; assert details.files[0].seen_count == 2; assert details.files[0].first_source is ScanSource.MANUAL; assert details.files[0].last_source is ScanSource.SCHEDULED; assert details.files[0].last_seen >= details.files[0].first_seen; assert details.events[-1].event_type is IncidentEventType.REPEATED_DETECTION; assert details.events[-1].source is ScanSource.SCHEDULED

def test_status_updates_are_recorded_and_resolved_is_not_active(setup):
    service, _, detector, files = setup; detection = high_detection(detector, files / "status.txt"); incident = service.record_high_confidence_detection(detection, ScanSource.MANUAL); service.change_status(incident.id, IncidentStatus.INVESTIGATING, reason="Analyst review"); service.change_status(incident.id, IncidentStatus.CONTAINED, reason="Contained for testing")
    assert service.get_active_incidents()[0].status is IncidentStatus.CONTAINED
    service.change_status(incident.id, IncidentStatus.RESOLVED, reason="Review complete")
    assert all(item.id != incident.id for item in service.get_active_incidents())
    details = service.get_incident(incident.id); transitions = [e for e in details.events if e.event_type is IncidentEventType.STATUS_CHANGED]
    assert [(e.old_status, e.new_status) for e in transitions] == [(IncidentStatus.OPEN, IncidentStatus.INVESTIGATING), (IncidentStatus.INVESTIGATING, IncidentStatus.CONTAINED), (IncidentStatus.CONTAINED, IncidentStatus.RESOLVED)]

@pytest.mark.parametrize("prior_status", [IncidentStatus.CONTAINED, IncidentStatus.RESTORED])
def test_detection_after_contained_or_restored_marks_incident_reappeared(setup, prior_status):
    service, _, detector, files = setup; path = files / "return.txt"; detection = high_detection(detector, path); incident = service.record_high_confidence_detection(detection, ScanSource.MANUAL); service.change_status(incident.id, prior_status); updated = service.record_high_confidence_detection(detection, ScanSource.FILE_MONITOR); details = service.get_incident(incident.id)
    assert updated.status is IncidentStatus.REAPPEARED; assert details.incident.detection_count == 2; assert any(event.event_type is IncidentEventType.STATUS_CHANGED and event.old_status is prior_status and event.new_status is IncidentStatus.REAPPEARED for event in details.events); assert details.events[-1].event_type is IncidentEventType.REPEATED_DETECTION; assert details.events[-1].source is ScanSource.FILE_MONITOR

def test_new_detection_after_resolved_creates_new_incident(setup):
    service, _, detector, files = setup; detection = high_detection(detector, files / "same-content.txt"); old = service.record_high_confidence_detection(detection, ScanSource.MANUAL); service.change_status(old.id, IncidentStatus.RESOLVED); new = service.record_high_confidence_detection(detection, ScanSource.MANUAL)
    assert new.id != old.id; assert new.sha256 == old.sha256; assert new.status is IncidentStatus.OPEN; assert service.get_incident(old.id).incident.status is IncidentStatus.RESOLVED

def test_public_create_attach_and_append_methods(setup):
    service, _, _, files = setup; first = files / "first-location.bin"; second = files / "second-location.bin"; reason = "Known malicious test hash."; incident = service.create_incident("a" * 64, first, ScanSource.MANUAL, reason); attached = service.attach_matching_file(incident.id, second, ScanSource.USB, "Matching SHA-256 observed on USB."); custom = service.append_event(incident.id, IncidentEventType.STATUS_CHANGED, detection_reason="Manual investigation started.", old_status=IncidentStatus.OPEN, new_status=IncidentStatus.INVESTIGATING); details = service.get_incident(incident.id)
    assert attached.path == str(normalize_path(second)); assert attached.seen_count == 1; assert custom.event_type is IncidentEventType.STATUS_CHANGED; assert len(details.files) == 2; assert len(details.events) == 3

def test_low_confidence_cannot_be_recorded_as_incident(setup):
    service, _, detector, files = setup; path = files / "invoice.pdf.exe"; path.write_bytes(b"harmless heuristic fixture"); detection = detector.detect_file(path)
    assert detection.status is DetectionStatus.LOW_CONFIDENCE
    with pytest.raises(ValueError, match="HIGH_CONFIDENCE"): service.record_high_confidence_detection(detection, ScanSource.MANUAL)
    assert service.get_active_incidents() == []

def test_scanner_integration_records_only_high_confidence_and_never_quarantines(setup):
    service, database, detector, files = setup; dangerous = files / "dangerous-test.txt"; clean = files / "clean.txt"; dangerous.write_bytes(AUTOGUARD_TEST_CONTENT); clean.write_bytes(b"ordinary content"); scanner = Scanner(detector, ThreatTrail(database), incidents=service); summary = scanner.scan_directory(files, ScanSource.MANUAL)
    assert summary.counts["dangerous_detections"] == 1; assert len(service.get_active_incidents()) == 1
    details = service.get_incident(service.get_active_incidents()[0].id)
    assert details.incident.sha256 == AUTOGUARD_TEST_SHA256; assert dangerous.exists() and dangerous.read_bytes() == AUTOGUARD_TEST_CONTENT; assert clean.exists() and clean.read_bytes() == b"ordinary content"

def test_list_incidents_returns_active_and_resolved_without_changing_status(setup):
    service, _, detector, files = setup; first = service.record_high_confidence_detection(high_detection(detector, files / "older.txt"), ScanSource.MANUAL); service.change_status(first.id, IncidentStatus.RESOLVED, reason="Finished"); second = service.record_high_confidence_detection(high_detection(detector, files / "newer.txt"), ScanSource.USB); rows = service.list_incidents(10)
    assert {item.id for item in rows} == {first.id, second.id}; assert next(item for item in rows if item.id == first.id).status is IncidentStatus.RESOLVED; assert next(item for item in rows if item.id == second.id).status is IncidentStatus.OPEN
    with pytest.raises(ValueError, match="positive integer"): service.list_incidents(0)