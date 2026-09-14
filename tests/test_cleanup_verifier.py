from pathlib import Path
import pytest
from app.cleanup_verifier import CleanupVerifier, VerificationStatus
from app.config import AppConfig
from app.database import Database
from app.detector import Detector
from app.hashing import hash_file, normalize_path
from app.incidents import IncidentEventType, IncidentService, IncidentStatus
from app.matching_cleanup import MatchingCopyCleanup
from app.models import DetectionStatus, ScanSource
from app.quarantine import QuarantineService, QuarantineState
from app.scanner import Scanner
from app.signatures import AUTOGUARD_TEST_CONTENT, AUTOGUARD_TEST_SHA256, load_signatures
from app.threat_trail import ThreatTrail

@pytest.fixture
def setup(tmp_path):
    config = AppConfig(data_dir=tmp_path / "runtime"); config.create_directories()
    database = Database(config.database_path); database.initialize()
    incidents, trail = IncidentService(database), ThreatTrail(database)
    quarantine, detector = QuarantineService(database, config.quarantine_dir, incidents), Detector(load_signatures())
    downloads, desktop, documents = tmp_path / "Downloads", tmp_path / "Desktop", tmp_path / "Documents"
    for r in (downloads, desktop, documents): r.mkdir()
    verifier = CleanupVerifier(database, incidents, quarantine, monitored_locations=(downloads, desktop, documents))
    cleanup = MatchingCopyCleanup(database, incidents, quarantine, trail, monitored_locations=(downloads, desktop, documents))
    return (config, database, incidents, trail, quarantine, detector, cleanup, verifier, downloads, desktop, documents)

def quarantined_incident(tmp_path, incidents, quarantine, detector):
    seed = tmp_path / "seed-threat.bin"; seed.write_bytes(AUTOGUARD_TEST_CONTENT)
    detection = detector.detect_file(seed)
    assert detection.status is DetectionStatus.HIGH_CONFIDENCE
    incident = incidents.record_high_confidence_detection(detection, ScanSource.MANUAL)
    item = quarantine.quarantine_detection(detection, incident.id, ScanSource.MANUAL, original_size=len(AUTOGUARD_TEST_CONTENT))
    assert item.state is QuarantineState.QUARANTINED and not seed.exists() and incidents.get_incident(incident.id).incident.status is IncidentStatus.OPEN
    return incident, item

def test_database_initializes_cleanup_verification_table(setup):
    _, database, *_ = setup
    with database.connection() as conn: names = {r["name"] for r in conn.execute("SELECT name FROM sqlite_master WHERE type = 'table'")}
    assert "cleanup_verifications" in names

def test_fully_verified_cleanup_marks_incident_contained(setup, tmp_path):
    _, _, incidents, _, quarantine, detector, _, verifier, *_ = setup
    incident, item = quarantined_incident(tmp_path, incidents, quarantine, detector)
    result = verifier.verify_incident(incident.id)
    assert result.status is VerificationStatus.VERIFIED and result.sha256 == AUTOGUARD_TEST_SHA256
    assert result.quarantined_copies == 1 and result.verified_quarantine_objects == 1 and result.remaining_matching_copies == 0
    assert result.inaccessible_locations == 0 and result.verification_errors == 0 and Path(item.stored_path).exists()
    assert incidents.get_incident(incident.id).incident.status is IncidentStatus.CONTAINED
    assert verifier.get_verification(result.verification_id) == result and verifier.list_verifications(incident.id) == [result]
    event_types = [e.event_type for e in incidents.get_incident(incident.id).events]
    assert IncidentEventType.CLEANUP_VERIFICATION_STARTED in event_types and IncidentEventType.CLEANUP_VERIFIED in event_types

def test_remaining_exact_copy_returns_partial_and_prevents_containment(setup, tmp_path):
    _, _, incidents, _, quarantine, detector, _, verifier, downloads, *_ = setup
    incident, _ = quarantined_incident(tmp_path, incidents, quarantine, detector)
    remaining = downloads / "different-name.dat"; remaining.write_bytes(AUTOGUARD_TEST_CONTENT)
    result = verifier.verify_incident(incident.id)
    assert result.status is VerificationStatus.PARTIAL and result.quarantined_copies == 1 and result.verified_quarantine_objects == 1
    assert result.remaining_matching_copies == 1 and result.remaining_paths == (str(normalize_path(remaining)),) and remaining.exists()
    assert incidents.get_incident(incident.id).incident.status is IncidentStatus.OPEN
    assert any(e.event_type is IncidentEventType.CLEANUP_VERIFICATION_PARTIAL for e in incidents.get_incident(incident.id).events)

def test_corrupted_quarantine_content_returns_failed(setup, tmp_path):
    _, _, incidents, _, quarantine, detector, _, verifier, *_ = setup
    incident, item = quarantined_incident(tmp_path, incidents, quarantine, detector)
    Path(item.stored_path).write_bytes(b"corrupted quarantine content")
    result = verifier.verify_incident(incident.id)
    assert result.status is VerificationStatus.FAILED and result.quarantined_copies == 1 and result.verified_quarantine_objects == 0
    assert result.verification_errors >= 1 and incidents.get_incident(incident.id).incident.status is IncidentStatus.INVESTIGATING
    assert any(e.event_type is IncidentEventType.CLEANUP_VERIFICATION_FAILED for e in incidents.get_incident(incident.id).events)

def test_inaccessible_location_is_partial_not_false_success(setup, tmp_path, monkeypatch):
    _, _, incidents, _, quarantine, detector, _, verifier, downloads, *_ = setup
    incident, _ = quarantined_incident(tmp_path, incidents, quarantine, detector)
    locked = downloads / "locked.bin"; locked.write_bytes(AUTOGUARD_TEST_CONTENT)
    real_hash = hash_file
    def deny_hash(p, *args, **kwargs):
        if normalize_path(p) == normalize_path(locked): raise PermissionError("simulated verification access denied")
        return real_hash(p, *args, **kwargs)
    monkeypatch.setattr("app.cleanup_verifier.hash_file", deny_hash)
    result = verifier.verify_incident(incident.id)
    assert result.status is VerificationStatus.PARTIAL and result.remaining_matching_copies == 0 and result.inaccessible_locations == 1
    assert result.verification_errors == 0 and result.inaccessible[0].path == str(normalize_path(locked))
    assert "Permission denied" in result.inaccessible[0].reason and incidents.get_incident(incident.id).incident.status is IncidentStatus.OPEN

def test_partial_cleanup_with_verified_quarantine_and_remaining_copy(setup, tmp_path):
    _, _, incidents, trail, quarantine, detector, _, verifier, _, desktop, _ = setup
    incident, _ = quarantined_incident(tmp_path, incidents, quarantine, detector)
    copy = desktop / "historical-and-current.bin"; copy.write_bytes(AUTOGUARD_TEST_CONTENT)
    trail.record_file(copy, ScanSource.USB)
    incidents.attach_matching_file(incident.id, copy, ScanSource.USB, "Exact malicious content observed before verification.")
    result = verifier.verify_incident(incident.id)
    assert result.status is VerificationStatus.PARTIAL and result.verified_quarantine_objects == result.quarantined_copies == 1
    assert result.remaining_matching_copies == 1 and result.inaccessible_locations == 0 and result.verification_errors == 0 and copy.exists()

def test_benign_near_match_does_not_block_verified_cleanup(setup, tmp_path):
    _, _, incidents, _, quarantine, detector, _, verifier, _, _, documents = setup
    incident, _ = quarantined_incident(tmp_path, incidents, quarantine, detector)
    near = documents / "seed-threat.bin"; near.write_bytes(AUTOGUARD_TEST_CONTENT[:-1] + b"X")
    result = verifier.verify_incident(incident.id)
    assert result.status is VerificationStatus.VERIFIED and result.remaining_matching_copies == 0 and near.exists()
    assert incidents.get_incident(incident.id).incident.status is IncidentStatus.CONTAINED

def test_verified_incident_reopens_if_later_verification_is_partial(setup, tmp_path):
    _, _, incidents, _, quarantine, detector, _, verifier, downloads, *_ = setup
    incident, _ = quarantined_incident(tmp_path, incidents, quarantine, detector)
    assert verifier.verify_incident(incident.id).status is VerificationStatus.VERIFIED
    assert incidents.get_incident(incident.id).incident.status is IncidentStatus.CONTAINED
    remaining = downloads / "later-current-copy.bin"; remaining.write_bytes(AUTOGUARD_TEST_CONTENT)
    second = verifier.verify_incident(incident.id)
    assert second.status is VerificationStatus.PARTIAL and second.remaining_matching_copies == 1
    assert incidents.get_incident(incident.id).incident.status is IncidentStatus.INVESTIGATING

def test_scanner_runs_cleanup_then_verification(setup, tmp_path):
    _, database, incidents, trail, quarantine, detector, cleanup, verifier, downloads, *_ = setup
    matching, seed = downloads / "matching-copy.bin", tmp_path / "manual-seed.bin"
    matching.write_bytes(AUTOGUARD_TEST_CONTENT); seed.write_bytes(AUTOGUARD_TEST_CONTENT)
    scanner = Scanner(detector, trail, incidents=incidents, quarantine=quarantine, matching_cleanup=cleanup, cleanup_verifier=verifier)
    result = scanner.scan_file(seed, ScanSource.MANUAL)
    assert result.detection.status is DetectionStatus.HIGH_CONFIDENCE and not seed.exists() and not matching.exists()
    assert len(scanner.last_matching_cleanup_results) == 1 and scanner.last_matching_cleanup_results[0].matches_quarantined == 1
    assert len(scanner.last_cleanup_verification_results) == 1
    verification = scanner.last_cleanup_verification_results[0]
    assert verification.status is VerificationStatus.VERIFIED and verification.quarantined_copies == 2
    assert verification.verified_quarantine_objects == 2 and verification.remaining_matching_copies == 0
    active = incidents.get_active_incidents()
    assert len(active) == 1 and active[0].status is IncidentStatus.CONTAINED