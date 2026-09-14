from pathlib import Path

import pytest

from app.config import AppConfig
from app.database import Database
from app.detector import Detector
from app.hashing import normalize_path
from app.incidents import IncidentEventType, IncidentService, IncidentStatus
from app.models import DetectionStatus, ScanSource
from app.quarantine import QuarantineIntegrityStatus, QuarantineService, QuarantineState
from app.scanner import Scanner
from app.signatures import AUTOGUARD_TEST_CONTENT, AUTOGUARD_TEST_SHA256, load_signatures
from app.threat_trail import ThreatTrail


@pytest.fixture
def setup(tmp_path):
    config = AppConfig(data_dir=tmp_path / "runtime"); config.create_directories()
    database = Database(config.database_path); database.initialize()
    incidents = IncidentService(database)
    quarantine = QuarantineService(database, config.quarantine_dir, incidents)
    detector = Detector(load_signatures())
    files = tmp_path / "files"; files.mkdir()
    return config, database, incidents, quarantine, detector, files


def detected_incident(incidents, detector, path, source=ScanSource.MANUAL):
    path.write_bytes(AUTOGUARD_TEST_CONTENT)
    detection = detector.detect_file(path)
    assert detection.status is DetectionStatus.HIGH_CONFIDENCE
    incident = incidents.record_high_confidence_detection(detection, source)
    return detection, incident


def test_database_initializes_quarantine_metadata(setup):
    _, database, _, _, _, _ = setup
    with database.connection() as connection:
        columns = {row["name"] for row in connection.execute("PRAGMA table_info(quarantine_items)")}
    assert {"quarantine_id", "incident_id", "original_path", "stored_path", "sha256", "original_size", "quarantined_at", "reason", "original_source", "state", "integrity_status", "verified_sha256", "verified_size", "verified_at", "original_removed", "failure_reason"} <= columns


def test_successful_quarantine_uses_internal_agq_name_without_premature_containment(setup):
    config, _, incidents, quarantine, detector, files = setup
    path = files / "dangerous-test.exe"
    detection, incident = detected_incident(incidents, detector, path)

    item = quarantine.quarantine_detection(detection, incident.id, ScanSource.MANUAL, original_size=len(AUTOGUARD_TEST_CONTENT))

    assert item.state is QuarantineState.QUARANTINED
    assert item.integrity_status is QuarantineIntegrityStatus.VERIFIED
    assert item.sha256 == AUTOGUARD_TEST_SHA256
    assert item.verified_sha256 == AUTOGUARD_TEST_SHA256
    assert item.original_size == item.verified_size == len(AUTOGUARD_TEST_CONTENT)
    assert item.quarantined_at is not None and item.original_removed
    assert Path(item.stored_path).parent == normalize_path(config.quarantine_dir)
    assert Path(item.stored_path).name == f"{item.quarantine_id}.agq"
    assert "dangerous-test" not in Path(item.stored_path).name
    assert Path(item.stored_path).read_bytes() == AUTOGUARD_TEST_CONTENT
    assert not path.exists()
    assert quarantine.original_location_exists(item.quarantine_id) is False

    details = incidents.get_incident(incident.id)
    assert details.incident.status is IncidentStatus.OPEN
    event_types = [event.event_type for event in details.events]
    assert IncidentEventType.QUARANTINE_STARTED in event_types
    assert IncidentEventType.QUARANTINE_SUCCEEDED in event_types


def test_verify_integrity_rehashes_quarantined_content(setup):
    _, _, incidents, quarantine, detector, files = setup
    path = files / "verify.exe"
    detection, incident = detected_incident(incidents, detector, path)
    item = quarantine.quarantine_detection(detection, incident.id, ScanSource.MANUAL, original_size=len(AUTOGUARD_TEST_CONTENT))

    result = quarantine.verify_integrity(item.quarantine_id)
    refreshed = quarantine.get_item(item.quarantine_id)

    assert result.verified
    assert result.actual_sha256 == AUTOGUARD_TEST_SHA256
    assert result.actual_size == len(AUTOGUARD_TEST_CONTENT)
    assert refreshed.integrity_status is QuarantineIntegrityStatus.VERIFIED


def test_missing_source_persists_failed_state_without_containment(setup):
    _, _, incidents, quarantine, _, files = setup
    missing = files / "already-gone.exe"
    incident = incidents.create_incident(AUTOGUARD_TEST_SHA256, missing, ScanSource.MANUAL, "Known signature detection.")

    item = quarantine.quarantine_file(incident.id, missing, AUTOGUARD_TEST_SHA256, "Known signature detection.", ScanSource.MANUAL, expected_size=len(AUTOGUARD_TEST_CONTENT))

    assert item.state is QuarantineState.FAILED
    assert item.integrity_status is QuarantineIntegrityStatus.FAILED
    assert item.quarantined_at is None and not item.original_removed
    assert "no longer exists" in item.failure_reason
    assert not Path(item.stored_path).exists()
    assert incidents.get_incident(incident.id).incident.status is IncidentStatus.OPEN
    assert incidents.get_incident(incident.id).events[-1].event_type is IncidentEventType.QUARANTINE_FAILED


def test_duplicate_successful_quarantine_attempt_is_idempotent(setup):
    _, _, incidents, quarantine, detector, files = setup
    path = files / "duplicate.exe"
    detection, incident = detected_incident(incidents, detector, path)

    first = quarantine.quarantine_detection(detection, incident.id, ScanSource.MANUAL, original_size=len(AUTOGUARD_TEST_CONTENT))
    second = quarantine.quarantine_detection(detection, incident.id, ScanSource.MANUAL, original_size=len(AUTOGUARD_TEST_CONTENT))

    assert second == first
    assert len(quarantine.list_quarantined_items()) == 1
    assert len(list(Path(first.stored_path).parent.glob("*.agq"))) == 1


def test_quarantine_metadata_survives_reopening_database(setup):
    config, database, incidents, quarantine, detector, files = setup
    path = files / "persist.exe"
    detection, incident = detected_incident(incidents, detector, path, ScanSource.USB)
    saved = quarantine.quarantine_detection(detection, incident.id, ScanSource.USB, original_size=len(AUTOGUARD_TEST_CONTENT))

    reopened_db = Database(database.path); reopened_db.initialize()
    reopened = QuarantineService(reopened_db, config.quarantine_dir)
    item = reopened.get_item(saved.quarantine_id)

    assert item == saved
    assert reopened.list_quarantined_items() == [saved]


def test_hash_verification_failure_keeps_original_and_incident_open(setup, monkeypatch):
    _, _, incidents, quarantine, detector, files = setup
    path = files / "mismatch.exe"
    detection, incident = detected_incident(incidents, detector, path)

    def corrupt_copy(src, dst): Path(dst).write_bytes(b"not the detected bytes"); return str(dst)

    monkeypatch.setattr("app.quarantine.shutil.copyfile", corrupt_copy)
    item = quarantine.quarantine_detection(detection, incident.id, ScanSource.MANUAL, original_size=len(AUTOGUARD_TEST_CONTENT))

    assert item.state is QuarantineState.FAILED
    assert item.integrity_status is QuarantineIntegrityStatus.FAILED
    assert "mismatch" in item.failure_reason.lower()
    assert path.exists() and path.read_bytes() == AUTOGUARD_TEST_CONTENT
    assert not Path(item.stored_path).exists()
    assert incidents.get_incident(incident.id).incident.status is IncidentStatus.OPEN


def test_original_removal_failure_preserves_verified_copy_but_not_contained(setup, monkeypatch):
    _, _, incidents, quarantine, detector, files = setup
    path = files / "locked.exe"
    detection, incident = detected_incident(incidents, detector, path)
    normalized, real_unlink = normalize_path(path), Path.unlink

    def deny_original_unlink(self, *args, **kwargs):
        if normalize_path(self) == normalized: raise PermissionError("simulated lock")
        return real_unlink(self, *args, **kwargs)

    monkeypatch.setattr(Path, "unlink", deny_original_unlink)
    item = quarantine.quarantine_detection(detection, incident.id, ScanSource.MANUAL, original_size=len(AUTOGUARD_TEST_CONTENT))

    assert item.state is QuarantineState.FAILED
    assert item.integrity_status is QuarantineIntegrityStatus.VERIFIED
    assert Path(item.stored_path).exists()
    assert path.exists()
    assert not item.original_removed
    assert incidents.get_incident(incident.id).incident.status is IncidentStatus.OPEN


def test_low_confidence_detection_cannot_use_quarantine_detection(setup):
    _, _, incidents, quarantine, detector, files = setup
    path = files / "invoice.pdf.exe"; path.write_bytes(b"harmless heuristic fixture")
    detection = detector.detect_file(path)
    assert detection.status is DetectionStatus.LOW_CONFIDENCE
    incident = incidents.create_incident("a" * 64, path, ScanSource.MANUAL, "Synthetic incident for API validation.")

    with pytest.raises(ValueError, match="HIGH_CONFIDENCE"):
        quarantine.quarantine_detection(detection, incident.id, ScanSource.MANUAL)
    assert path.exists()
    assert quarantine.list_quarantined_items() == []


def test_scanner_auto_quarantines_signature_detection_when_engine_is_enabled(setup):
    _, database, incidents, quarantine, detector, files = setup
    dangerous = files / "dangerous.exe"; dangerous.write_bytes(AUTOGUARD_TEST_CONTENT)

    scanner = Scanner(detector, ThreatTrail(database), incidents=incidents, quarantine=quarantine)
    result = scanner.scan_file(dangerous, ScanSource.MANUAL)

    assert result.detection.status is DetectionStatus.HIGH_CONFIDENCE
    assert not dangerous.exists()
    items = quarantine.list_quarantined_items()
    assert len(items) == 1 and items[0].state is QuarantineState.QUARANTINED
    assert incidents.get_incident(items[0].incident_id).incident.status is IncidentStatus.OPEN


def test_scanner_does_not_auto_quarantine_low_confidence_heuristics(setup):
    _, database, incidents, quarantine, detector, files = setup
    suspicious = files / "invoice.pdf.exe"; suspicious.write_bytes(b"ordinary bytes with suspicious filename only")

    scanner = Scanner(detector, ThreatTrail(database), incidents=incidents, quarantine=quarantine)
    result = scanner.scan_file(suspicious, ScanSource.MANUAL)

    assert result.detection.status is DetectionStatus.LOW_CONFIDENCE
    assert suspicious.exists()
    assert quarantine.list_quarantined_items() == []
    assert incidents.get_active_incidents() == []


def test_tampered_quarantine_fails_later_integrity_check_and_reopens_review(setup):
    _, _, incidents, quarantine, detector, files = setup
    path = files / "tamper.exe"
    detection, incident = detected_incident(incidents, detector, path)
    item = quarantine.quarantine_detection(detection, incident.id, ScanSource.MANUAL, original_size=len(AUTOGUARD_TEST_CONTENT))
    assert incidents.get_incident(incident.id).incident.status is IncidentStatus.OPEN

    Path(item.stored_path).write_bytes(b"tampered quarantine bytes")
    result = quarantine.verify_integrity(item.quarantine_id)
    refreshed = quarantine.get_item(item.quarantine_id)
    details = incidents.get_incident(incident.id)

    assert not result.verified
    assert refreshed.state is QuarantineState.FAILED
    assert refreshed.integrity_status is QuarantineIntegrityStatus.FAILED
    assert details.incident.status is IncidentStatus.INVESTIGATING
    assert any(event.event_type is IncidentEventType.QUARANTINE_INTEGRITY_FAILED for event in details.events)


def test_known_other_location_prevents_false_contained_status(setup):
    _, _, incidents, quarantine, detector, files = setup
    first, second = files / "first.exe", files / "second.exe"
    first.write_bytes(AUTOGUARD_TEST_CONTENT); second.write_bytes(AUTOGUARD_TEST_CONTENT)
    first_detection, second_detection = detector.detect_file(first), detector.detect_file(second)
    incident = incidents.record_high_confidence_detection(first_detection, ScanSource.MANUAL)
    incidents.record_high_confidence_detection(second_detection, ScanSource.USB)

    item = quarantine.quarantine_detection(first_detection, incident.id, ScanSource.MANUAL, original_size=len(AUTOGUARD_TEST_CONTENT))

    assert item.state is QuarantineState.QUARANTINED
    assert not first.exists() and second.exists()
    assert incidents.get_incident(incident.id).incident.status is IncidentStatus.OPEN