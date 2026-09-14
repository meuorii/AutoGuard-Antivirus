from pathlib import Path

import pytest

from app.cleanup_verifier import CleanupVerifier, VerificationStatus
from app.config import AppConfig
from app.database import Database
from app.detector import Detector
from app.hashing import normalize_path
from app.incidents import IncidentEventType, IncidentService, IncidentStatus
from app.models import (DetectionResult, DetectionStatus, ScanSource,
                        Signature, SignatureKind)
from app.quarantine import QuarantineService, QuarantineState
from app.reappearance import REAPPEARANCE_EXPLANATION, ReappearanceWatch
from app.scanner import Scanner
from app.signatures import (AUTOGUARD_TEST_CONTENT, AUTOGUARD_TEST_SHA256,
                            load_signatures)
from app.threat_trail import ThreatTrail


@pytest.fixture
def setup(tmp_path):
    config = AppConfig(data_dir=tmp_path / "runtime"); config.create_directories()
    database = Database(config.database_path); database.initialize()
    incidents, trail = IncidentService(database), ThreatTrail(database)
    quarantine = QuarantineService(database, config.quarantine_dir, incidents)
    detector, watch = Detector(load_signatures()), ReappearanceWatch(database, incidents)
    monitored = tmp_path / "monitored"; monitored.mkdir()
    verifier = CleanupVerifier(database, incidents, quarantine, monitored_locations=(monitored,))
    return (config, database, incidents, trail, quarantine, detector, watch, verifier, monitored)


def make_contained_incident(tmp_path, incidents, quarantine, detector, verifier):
    seed = tmp_path / "initial-threat.bin"; seed.write_bytes(AUTOGUARD_TEST_CONTENT)
    detection = detector.detect_file(seed)
    assert detection.status is DetectionStatus.HIGH_CONFIDENCE
    incident = incidents.record_high_confidence_detection(detection, ScanSource.MANUAL)
    item = quarantine.quarantine_detection(detection, incident.id, ScanSource.MANUAL, original_size=len(AUTOGUARD_TEST_CONTENT))
    assert item.state is QuarantineState.QUARANTINED
    assert verifier.verify_incident(incident.id).status is VerificationStatus.VERIFIED
    contained = incidents.get_incident(incident.id).incident
    assert contained.status is IncidentStatus.CONTAINED and contained.reappearance_count == 0
    return contained


def detect_test_copy(detector, path):
    path.write_bytes(AUTOGUARD_TEST_CONTENT)
    detection = detector.detect_file(path)
    assert detection.status is DetectionStatus.HIGH_CONFIDENCE
    return detection


def test_database_initializes_phase9_reappearance_fields(setup):
    _, database, *_ = setup
    with database.connection() as connection:
        incident_columns = {row["name"] for row in connection.execute("PRAGMA table_info(threat_incidents)")}
        event_columns = {row["name"] for row in connection.execute("PRAGMA table_info(incident_events)")}
        event_sql = connection.execute("SELECT sql FROM sqlite_master WHERE type='table' AND name='incident_events'").fetchone()["sql"]
    assert "reappearance_count" in incident_columns and "reappearance_count" in event_columns and "REAPPEARANCE" in event_sql


def test_contained_threat_reappears_in_same_incident(setup, tmp_path):
    _, _, incidents, _, quarantine, detector, watch, verifier, monitored = setup
    original = make_contained_incident(tmp_path, incidents, quarantine, detector, verifier)
    new_path = monitored / "returned-under-new-name.dat"
    result = watch.check_detection(detect_test_copy(detector, new_path), ScanSource.FILE_MONITOR)

    assert result.detected and result.incident is not None and result.event is not None
    assert result.incident.id == original.id and result.incident.status is IncidentStatus.REAPPEARED
    assert result.reappearance_count == 1 and result.incident.reappearance_count == 1
    assert result.event.event_type is IncidentEventType.REAPPEARANCE
    assert result.event.path == str(normalize_path(new_path)) and result.event.source is ScanSource.FILE_MONITOR
    assert result.event.reappearance_count == 1 and result.event.detection_reason == REAPPEARANCE_EXPLANATION
    assert "may be recreating it" in result.explanation


def test_multiple_reappearances_increment_monotonically(setup, tmp_path):
    _, _, incidents, _, quarantine, detector, watch, verifier, monitored = setup
    original = make_contained_incident(tmp_path, incidents, quarantine, detector, verifier)

    counts = []
    for number, source in enumerate((ScanSource.FILE_MONITOR, ScanSource.USB, ScanSource.STARTUP), start=1):
        result = watch.check_detection(detect_test_copy(detector, monitored / f"return-{number}.bin"), source)
        assert result.detected and result.incident.id == original.id
        counts.append(result.reappearance_count)

    details = incidents.get_incident(original.id)
    events = [e for e in details.events if e.event_type is IncidentEventType.REAPPEARANCE]
    assert counts == [1, 2, 3] and [e.reappearance_count for e in events] == [1, 2, 3]
    assert details.incident.reappearance_count == 3 and details.incident.detection_count == 4


def test_unrelated_high_confidence_hash_is_not_reappearance(setup, tmp_path):
    _, _, incidents, _, quarantine, detector, watch, verifier, _ = setup
    original = make_contained_incident(tmp_path, incidents, quarantine, detector, verifier)
    unrelated_sha256 = "a" * 64
    unrelated_signature = Signature(name="Unit.Test.Unrelated", sha256=unrelated_sha256, kind=SignatureKind.KNOWN_MALICIOUS, description="Harmless synthetic unit-test signature.")
    detection = DetectionResult(status=DetectionStatus.HIGH_CONFIDENCE, confidence=1.0, reason="Synthetic unrelated exact-hash test detection.", rule_name="known_malicious_sha256", sha256=unrelated_sha256, path=str(tmp_path / "unrelated.bin"), matched_signature=unrelated_signature)

    result = watch.check_detection(detection, ScanSource.MANUAL)
    assert not result.detected and result.incident is None and result.event is None
    assert incidents.get_incident(original.id).incident.reappearance_count == 0


def test_previous_hash_without_cleanup_evidence_is_not_called_reappearance(setup, tmp_path):
    _, _, incidents, _, _, detector, watch, _, monitored = setup
    incident = incidents.record_high_confidence_detection(detect_test_copy(detector, tmp_path / "still-being-handled.bin"), ScanSource.MANUAL)
    result = watch.check_detection(detect_test_copy(detector, monitored / "another-observation.bin"), ScanSource.FILE_MONITOR)

    assert not result.detected and incidents.get_incident(incident.id).incident.reappearance_count == 0


def test_resolved_cleaned_incident_is_reused_and_reopened(setup, tmp_path):
    _, _, incidents, _, quarantine, detector, watch, verifier, monitored = setup
    original = make_contained_incident(tmp_path, incidents, quarantine, detector, verifier)
    incidents.change_status(original.id, IncidentStatus.RESOLVED, reason="Closed after review")
    result = watch.check_detection(detect_test_copy(detector, monitored / "after-resolution.bin"), ScanSource.USB)

    assert result.detected and result.incident.id == original.id and result.incident.status is IncidentStatus.REAPPEARED
    assert len(incidents.get_active_incidents()) == 1 and incidents.get_active_incidents()[0].id == original.id


def test_scanner_reuses_incident_and_shows_evidence_based_explanation(setup, tmp_path):
    _, database, incidents, trail, quarantine, detector, watch, verifier, monitored = setup
    original = make_contained_incident(tmp_path, incidents, quarantine, detector, verifier)
    returned = monitored / "returned.bin"; returned.write_bytes(AUTOGUARD_TEST_CONTENT)
    scanner = Scanner(detector, trail, incidents=incidents, reappearance=watch)

    scan_result = scanner.scan_file(returned, ScanSource.FILE_MONITOR)
    details = incidents.get_incident(original.id)

    assert len(incidents.get_active_incidents()) == 1 and details.incident.id == original.id
    assert details.incident.status is IncidentStatus.REAPPEARED and details.incident.reappearance_count == 1
    assert returned.exists() and REAPPEARANCE_EXPLANATION in scan_result.reason
    assert len(scanner.last_reappearance_results) == 1 and scanner.last_reappearance_results[0].incident.id == original.id


def test_automatic_quarantine_and_verification_recontain_reappearance(setup, tmp_path):
    _, _, incidents, trail, quarantine, detector, watch, verifier, monitored = setup
    original = make_contained_incident(tmp_path, incidents, quarantine, detector, verifier)
    returned = monitored / "auto-recontained.bin"; returned.write_bytes(AUTOGUARD_TEST_CONTENT)
    scanner = Scanner(detector, trail, incidents=incidents, quarantine=quarantine, cleanup_verifier=verifier, reappearance=watch)

    scan_result = scanner.scan_file(returned, ScanSource.FILE_MONITOR)
    details = incidents.get_incident(original.id)

    assert scan_result.status.value == "SCANNED" and not returned.exists()
    assert details.incident.id == original.id and details.incident.reappearance_count == 1 and details.incident.status is IncidentStatus.CONTAINED
    assert len(scanner.last_reappearance_results) == 1 and len(scanner.last_cleanup_verification_results) == 1
    verification = scanner.last_cleanup_verification_results[0]
    assert verification.status is VerificationStatus.VERIFIED and verification.quarantined_copies == 2 and verification.verified_quarantine_objects == 2


def test_reappearance_event_is_careful_about_unknown_cause(setup, tmp_path):
    _, _, incidents, _, quarantine, detector, watch, verifier, monitored = setup
    original = make_contained_incident(tmp_path, incidents, quarantine, detector, verifier)
    result = watch.check_detection(detect_test_copy(detector, monitored / "unknown-origin.bin"), ScanSource.USB)

    text = result.event.detection_reason
    assert text == REAPPEARANCE_EXPLANATION and "may be recreating it" in text
    assert "caused by" not in text.lower() and "created by" not in text.lower()