from pathlib import Path; import pytest
from app.config import AppConfig; from app.database import Database; from app.detector import Detector
from app.hashing import hash_file, normalize_path; from app.incidents import IncidentEventType, IncidentService, IncidentStatus
from app.matching_cleanup import MatchingCopyCleanup; from app.models import DetectionStatus, ScanSource
from app.quarantine import QuarantineService, QuarantineState; from app.scanner import Scanner
from app.signatures import AUTOGUARD_TEST_CONTENT, AUTOGUARD_TEST_SHA256, load_signatures; from app.threat_trail import ThreatTrail

@pytest.fixture
def setup(tmp_path):
    config = AppConfig(data_dir=tmp_path / "runtime"); config.create_directories()
    database = Database(config.database_path); database.initialize()
    incidents, trail = IncidentService(database), ThreatTrail(database)
    quarantine = QuarantineService(database, config.quarantine_dir, incidents); detector = Detector(load_signatures())
    downloads, desktop, documents, usb = tmp_path / "Downloads", tmp_path / "Desktop", tmp_path / "Documents", tmp_path / "USB"
    for root in (downloads, desktop, documents, usb): root.mkdir()
    cleanup = MatchingCopyCleanup(database, incidents, quarantine, trail, monitored_locations=(downloads, desktop, documents, usb))
    return (config, database, incidents, trail, quarantine, detector, cleanup, downloads, desktop, documents, usb)

def confirmed_incident(tmp_path, incidents, quarantine, detector):
    seed_dir = tmp_path / "seed"; seed_dir.mkdir(exist_ok=True); seed = seed_dir / "confirmed-threat.bin"; seed.write_bytes(AUTOGUARD_TEST_CONTENT)
    detection = detector.detect_file(seed); assert detection.status is DetectionStatus.HIGH_CONFIDENCE
    incident = incidents.record_high_confidence_detection(detection, ScanSource.MANUAL)
    item = quarantine.quarantine_detection(detection, incident.id, ScanSource.MANUAL, original_size=len(AUTOGUARD_TEST_CONTENT))
    assert item.state is QuarantineState.QUARANTINED; return incident

def test_identical_content_with_different_filenames_is_quarantined(setup, tmp_path):
    _, _, incidents, _, quarantine, detector, cleanup, downloads, desktop, documents, _ = setup
    incident = confirmed_incident(tmp_path, incidents, quarantine, detector)
    first, second, near = downloads / "invoice-final.pdf", desktop / "totally-different-name.dat", documents / "invoice-final.pdf"
    first.write_bytes(AUTOGUARD_TEST_CONTENT); second.write_bytes(AUTOGUARD_TEST_CONTENT); near.write_bytes(AUTOGUARD_TEST_CONTENT[:-1] + b"X")
    result = cleanup.cleanup_incident(incident.id)
    assert result.sha256 == AUTOGUARD_TEST_SHA256 and len(result.locations_searched) == 4 and result.candidates_examined == 3
    assert result.exact_matches_found == 2 and result.matches_quarantined == 2 and result.already_contained_matches == 0
    assert result.failures == () and result.inaccessible_files == () and not first.exists() and not second.exists()
    assert near.exists() and near.read_bytes() != AUTOGUARD_TEST_CONTENT
    stored = [item for item in quarantine.list_quarantined_items() if item.incident_id == incident.id]
    assert len([item for item in stored if item.state is QuarantineState.QUARANTINED]) == 3

def test_near_match_is_never_cleaned_by_name_extension_or_path_similarity(setup, tmp_path):
    _, _, incidents, _, quarantine, detector, cleanup, downloads, _, _, _ = setup
    incident = confirmed_incident(tmp_path, incidents, quarantine, detector)
    misleading = downloads / "confirmed-threat.bin"; misleading.write_bytes(b"harmless bytes with a matching-looking filename")
    result = cleanup.cleanup_incident(incident.id)
    assert result.candidates_examined == 1 and result.exact_matches_found == 0 and result.matches_quarantined == 0 and misleading.exists()

def test_multiple_monitored_locations_are_searched_and_reported(setup, tmp_path):
    _, _, incidents, _, quarantine, detector, cleanup, downloads, desktop, documents, usb = setup
    incident = confirmed_incident(tmp_path, incidents, quarantine, detector)
    paths = [downloads / "a.bin", desktop / "b.exe", documents / "c.txt", usb / "d.payload"]
    for path in paths: path.write_bytes(AUTOGUARD_TEST_CONTENT)
    result = cleanup.cleanup_incident(incident.id)
    assert set(result.locations_searched) == {str(normalize_path(downloads)), str(normalize_path(desktop)), str(normalize_path(documents)), str(normalize_path(usb))}
    assert result.exact_matches_found == 4 and result.matches_quarantined == 4 and all(not path.exists() for path in paths)

def test_threat_trail_candidate_is_revalidated_and_not_processed_twice(setup, tmp_path):
    _, _, incidents, trail, quarantine, detector, cleanup, downloads, _, _, _ = setup
    incident = confirmed_incident(tmp_path, incidents, quarantine, detector)
    copy = downloads / "known-from-trail.bin"; copy.write_bytes(AUTOGUARD_TEST_CONTENT)
    observation = trail.record_file(copy, ScanSource.USB); assert observation.sha256 == AUTOGUARD_TEST_SHA256
    result = cleanup.cleanup_incident(incident.id)
    assert result.candidates_examined == 1 and result.exact_matches_found == 1 and result.matches_quarantined == 1 and not copy.exists()

def test_stale_threat_trail_observation_is_not_trusted_without_current_hash(setup, tmp_path):
    _, _, incidents, trail, quarantine, detector, cleanup, downloads, _, _, _ = setup
    incident = confirmed_incident(tmp_path, incidents, quarantine, detector)
    path = downloads / "changed-after-observation.bin"; path.write_bytes(AUTOGUARD_TEST_CONTENT)
    trail.record_file(path, ScanSource.USB); path.write_bytes(b"content changed after historical observation")
    result = cleanup.cleanup_incident(incident.id)
    assert result.candidates_examined == 1 and result.exact_matches_found == 0 and result.matches_quarantined == 0 and path.exists()

def test_already_quarantined_copy_is_reported_as_already_contained(setup, tmp_path):
    _, _, incidents, _, quarantine, detector, cleanup, downloads, _, _, _ = setup
    incident = confirmed_incident(tmp_path, incidents, quarantine, detector)
    path = downloads / "already-contained.bin"; path.write_bytes(AUTOGUARD_TEST_CONTENT)
    item = quarantine.quarantine_file(incident.id, path, AUTOGUARD_TEST_SHA256, "Pre-contained exact copy for test.", ScanSource.MATCHING_COPY, expected_size=len(AUTOGUARD_TEST_CONTENT))
    assert item.state is QuarantineState.QUARANTINED and not path.exists()
    result = cleanup.cleanup_incident(incident.id)
    assert result.already_contained_matches == 1 and result.candidates_examined == 0 and result.matches_quarantined == 0
    details = incidents.get_incident(incident.id)
    assert any(event.event_type is IncidentEventType.MATCHING_COPY_ALREADY_CONTAINED and event.path == str(normalize_path(path)) for event in details.events)

def test_inaccessible_candidate_is_reported_without_cleanup(setup, tmp_path, monkeypatch):
    _, _, incidents, _, quarantine, detector, cleanup, downloads, _, _, _ = setup
    incident = confirmed_incident(tmp_path, incidents, quarantine, detector)
    locked = downloads / "locked.bin"; locked.write_bytes(AUTOGUARD_TEST_CONTENT); real_hash = hash_file
    def deny_hash(path, *args, **kwargs):
        if normalize_path(path) == normalize_path(locked): raise PermissionError("simulated access denied")
        return real_hash(path, *args, **kwargs)
    monkeypatch.setattr("app.matching_cleanup.hash_file", deny_hash)
    result = cleanup.cleanup_incident(incident.id)
    assert result.candidates_examined == 1 and result.exact_matches_found == 0 and len(result.inaccessible_files) == 1
    assert result.inaccessible_files[0].path == str(normalize_path(locked)) and "Permission denied" in result.inaccessible_files[0].reason and locked.exists()

def test_quarantine_failure_is_returned_in_structured_failures(setup, tmp_path, monkeypatch):
    _, _, incidents, _, quarantine, detector, cleanup, downloads, _, _, _ = setup
    incident = confirmed_incident(tmp_path, incidents, quarantine, detector)
    path = downloads / "quarantine-failure.bin"; path.write_bytes(AUTOGUARD_TEST_CONTENT)
    monkeypatch.setattr(quarantine, "quarantine_file", lambda *a, **kw: (_ for _ in ()).throw(OSError("simulated quarantine backend failure")))
    result = cleanup.cleanup_incident(incident.id)
    assert result.exact_matches_found == 1 and result.matches_quarantined == 0 and len(result.failures) == 1
    assert "simulated quarantine backend failure" in result.failures[0].reason and path.exists()

def test_cleanup_events_and_incident_locations_are_recorded(setup, tmp_path):
    _, _, incidents, _, quarantine, detector, cleanup, downloads, _, _, _ = setup
    incident = confirmed_incident(tmp_path, incidents, quarantine, detector)
    copy = downloads / "copy.bin"; copy.write_bytes(AUTOGUARD_TEST_CONTENT)
    cleanup.cleanup_incident(incident.id)
    details = incidents.get_incident(incident.id); event_types = [event.event_type for event in details.events]
    assert str(normalize_path(copy)) in {item.path for item in details.files}
    assert IncidentEventType.MATCHING_CLEANUP_STARTED in event_types and IncidentEventType.MATCHING_COPY_FOUND in event_types
    assert IncidentEventType.MATCHING_COPY_QUARANTINED in event_types and IncidentEventType.MATCHING_CLEANUP_FINISHED in event_types
    assert details.incident.status is IncidentStatus.CONTAINED

def test_scanner_defers_and_runs_matching_cleanup_after_high_confidence_scan(setup, tmp_path):
    _, database, incidents, trail, quarantine, detector, _, downloads, _, _, _ = setup
    matching_copy = downloads / "matching-copy.bin"; matching_copy.write_bytes(AUTOGUARD_TEST_CONTENT)
    cleanup = MatchingCopyCleanup(database, incidents, quarantine, trail, monitored_locations=(downloads,))
    scanner = Scanner(detector, trail, incidents=incidents, quarantine=quarantine, matching_cleanup=cleanup)
    seed = tmp_path / "manual-detection.bin"; seed.write_bytes(AUTOGUARD_TEST_CONTENT)
    result = scanner.scan_file(seed, ScanSource.MANUAL)
    assert result.detection.status is DetectionStatus.HIGH_CONFIDENCE and not seed.exists() and not matching_copy.exists()
    assert len(scanner.last_matching_cleanup_results) == 1
    cleanup_result = scanner.last_matching_cleanup_results[0]
    assert cleanup_result.exact_matches_found == 1 and cleanup_result.matches_quarantined == 1

def test_same_path_can_be_quarantined_again_only_when_content_is_currently_present(setup, tmp_path):
    _, _, incidents, _, quarantine, detector, cleanup, downloads, _, _, _ = setup
    incident = confirmed_incident(tmp_path, incidents, quarantine, detector)
    path = downloads / "same-path.bin"; path.write_bytes(AUTOGUARD_TEST_CONTENT)
    first = cleanup.cleanup_incident(incident.id)
    assert first.matches_quarantined == 1 and not path.exists(); item_count = len(quarantine.list_quarantined_items())
    second = cleanup.cleanup_incident(incident.id)
    assert second.already_contained_matches == 1 and len(quarantine.list_quarantined_items()) == item_count
    path.write_bytes(AUTOGUARD_TEST_CONTENT); third = cleanup.cleanup_incident(incident.id)
    assert third.exact_matches_found == 1 and third.matches_quarantined == 1 and not path.exists() and len(quarantine.list_quarantined_items()) == item_count + 1