from pathlib import Path
import pytest
from app.config import AppConfig
from app.database import Database
from app.detector import Detector
from app.incidents import IncidentEventType, IncidentService, IncidentStatus
from app.models import DetectionStatus, ScanSource
from app.quarantine import QuarantineService, QuarantineState
from app.recovery import RecoveryConflictOption, RecoveryService, RecoveryStatus
from app.signatures import AUTOGUARD_TEST_CONTENT, SignatureStore, load_signatures

@pytest.fixture
def setup(tmp_path):
    config = AppConfig(data_dir=tmp_path / "runtime"); config.create_directories()
    database = Database(config.database_path); database.initialize()
    incidents, signature_detector = IncidentService(database), Detector(load_signatures())
    quarantine = QuarantineService(database, config.quarantine_dir, incidents)
    source = tmp_path / "downloads" / "sample.txt"; source.parent.mkdir(); source.write_bytes(AUTOGUARD_TEST_CONTENT)
    detection = signature_detector.detect_file(source)
    assert detection.status is DetectionStatus.HIGH_CONFIDENCE
    incident = incidents.record_high_confidence_detection(detection, ScanSource.MANUAL)
    item = quarantine.quarantine_detection(detection, incident.id, ScanSource.MANUAL, original_size=len(AUTOGUARD_TEST_CONTENT))
    assert item.state is QuarantineState.QUARANTINED
    incidents.change_status(incident.id, IncidentStatus.CONTAINED, reason="Fixture cleanup verified.")
    return database, incidents, quarantine, item, source, signature_detector

def safe_recovery(database, incidents, quarantine):
    return RecoveryService(database, quarantine, Detector(SignatureStore()), incidents)

def test_successful_recovery_verifies_and_restores_without_removing_quarantine_evidence(setup):
    database, incidents, quarantine, item, source, _ = setup
    service = safe_recovery(database, incidents, quarantine)
    result = service.restore(item.quarantine_id)
    assert result.status is RecoveryStatus.RESTORED and result.restored
    assert source.read_bytes() == AUTOGUARD_TEST_CONTENT and Path(item.stored_path).read_bytes() == AUTOGUARD_TEST_CONTENT
    assert incidents.get_incident(item.incident_id).incident.status is IncidentStatus.RESTORED
    attempts = service.list_attempts(item.quarantine_id)
    assert len(attempts) == 1 and attempts[0].restored_path == str(source.absolute())
    events = incidents.get_incident(item.incident_id).events
    assert any(e.event_type is IncidentEventType.RECOVERY_ATTEMPTED for e in events) and any(e.event_type is IncidentEventType.RECOVERY_SUCCEEDED for e in events)

def test_integrity_failure_blocks_restore_and_marks_incident_investigating(setup):
    database, incidents, quarantine, item, source, _ = setup
    Path(item.stored_path).write_bytes(b"corrupted quarantine content")
    service = safe_recovery(database, incidents, quarantine)
    result = service.restore(item.quarantine_id)
    assert result.status is RecoveryStatus.INTEGRITY_FAILED and not source.exists()
    assert incidents.get_incident(item.incident_id).incident.status is IncidentStatus.INVESTIGATING
    assert service.list_attempts(item.quarantine_id)[0].status is RecoveryStatus.INTEGRITY_FAILED

def test_destination_collision_never_overwrites_existing_content(setup):
    database, incidents, quarantine, item, source, _ = setup
    existing = b"important existing user data"; source.write_bytes(existing)
    service = safe_recovery(database, incidents, quarantine)
    result = service.restore(item.quarantine_id)
    assert result.status is RecoveryStatus.DESTINATION_CONFLICT and source.read_bytes() == existing
    assert result.conflict_options == (RecoveryConflictOption.RESTORE_TO_ANOTHER_FILENAME, RecoveryConflictOption.CHOOSE_ANOTHER_DESTINATION, RecoveryConflictOption.CANCEL)
    assert incidents.get_incident(item.incident_id).incident.status is IncidentStatus.CONTAINED

def test_missing_quarantine_object_is_safe_failure(setup):
    database, incidents, quarantine, item, source, _ = setup
    Path(item.stored_path).unlink()
    service = safe_recovery(database, incidents, quarantine)
    result = service.restore(item.quarantine_id)
    assert result.status is RecoveryStatus.MISSING_QUARANTINE_OBJECT and not source.exists()
    assert incidents.get_incident(item.incident_id).incident.status is IncidentStatus.INVESTIGATING

def test_restore_to_user_selected_alternative_location(setup, tmp_path):
    database, incidents, quarantine, item, source, _ = setup
    destination = tmp_path / "chosen" / "safe-copy.txt"
    service = safe_recovery(database, incidents, quarantine)
    result = service.restore(item.quarantine_id, destination)
    assert result.status is RecoveryStatus.RESTORED and destination.read_bytes() == AUTOGUARD_TEST_CONTENT
    assert not source.exists() and result.restored_path == str(destination.absolute())
    assert incidents.get_incident(item.incident_id).incident.status is IncidentStatus.RESTORED

def test_current_dangerous_detection_returns_strong_block_and_writes_nothing(setup):
    database, incidents, quarantine, item, source, signature_detector = setup
    service = RecoveryService(database, quarantine, signature_detector, incidents)
    result = service.restore(item.quarantine_id)
    assert result.status is RecoveryStatus.DANGEROUS_BLOCKED and result.detection is not None
    assert result.detection.status is DetectionStatus.HIGH_CONFIDENCE
    assert "still classifies this file as dangerous" in result.warning
    assert not source.exists() and Path(item.stored_path).exists()
    assert incidents.get_incident(item.incident_id).incident.status is IncidentStatus.CONTAINED
    assert service.list_attempts(item.quarantine_id)[0].status is RecoveryStatus.DANGEROUS_BLOCKED

def test_recovery_attempt_metadata_persists_after_reopening_database(setup, tmp_path):
    database, incidents, quarantine, item, _, _ = setup
    destination = tmp_path / "restored.txt"
    service = safe_recovery(database, incidents, quarantine)
    result = service.restore(item.quarantine_id, destination)
    reopened_db = Database(database.path); reopened_db.initialize()
    reopened = RecoveryService(reopened_db, QuarantineService(reopened_db, quarantine.quarantine_dir, IncidentService(reopened_db)), Detector(SignatureStore()), IncidentService(reopened_db))
    attempts = reopened.list_attempts(item.quarantine_id)
    assert len(attempts) == 1 and attempts[0].id == result.attempt.id
    assert attempts[0].status is RecoveryStatus.RESTORED and attempts[0].restored_path == str(destination.absolute())

def test_unknown_quarantine_id_is_explicit_error(setup):
    database, incidents, quarantine, _, _, _ = setup
    service = safe_recovery(database, incidents, quarantine)
    with pytest.raises(KeyError, match="Unknown quarantine item"): service.restore("does-not-exist")