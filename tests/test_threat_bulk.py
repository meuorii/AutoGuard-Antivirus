from __future__ import annotations

import pytest

from app.database import Database
from app.incidents import IncidentEventType, IncidentService, IncidentStatus
from app.models import ScanSource


@pytest.fixture
def incident_service(tmp_path):
    database = Database(tmp_path / "autoguard.db")
    database.initialize()
    service = IncidentService(database)
    incident = service.create_incident(
        "a" * 64, tmp_path / "sample.bin", ScanSource.MANUAL, "Fixture detection"
    )
    return database, service, incident


def _record_verified_cleanup(database, incident_id):
    timestamp = "2026-01-01T00:00:00+00:00"
    with database.connection() as connection:
        connection.execute(
            """INSERT INTO cleanup_verifications
               (id, incident_id, sha256, status, started_at, finished_at,
                locations_searched, quarantined_copies, verified_quarantine_objects,
                remaining_matching_copies, inaccessible_locations, verification_errors, details_json)
               VALUES (?, ?, ?, 'VERIFIED', ?, ?, 1, 1, 1, 0, 0, 0, '{}')""",
            ("verification-1", incident_id, "a" * 64, timestamp, timestamp),
        )


def test_resolution_requires_containment_and_latest_verified_cleanup(incident_service):
    database, service, incident = incident_service
    with pytest.raises(ValueError, match="contained"):
        service.resolve_verified(incident.id, reason="Resolve fixture")

    service.change_status(incident.id, IncidentStatus.CONTAINED)
    with pytest.raises(ValueError, match="cleanup verification"):
        service.resolve_verified(incident.id, reason="Resolve fixture")

    _record_verified_cleanup(database, incident.id)
    resolved = service.resolve_verified(incident.id, reason="Verified cleanup complete")
    assert resolved.status is IncidentStatus.RESOLVED
    events = service.get_incident(incident.id).events
    transition = next(event for event in reversed(events) if event.event_type is IncidentEventType.STATUS_CHANGED)
    assert transition.old_status is IncidentStatus.CONTAINED
    assert transition.new_status is IncidentStatus.RESOLVED
    assert transition.detection_reason == "Verified cleanup complete"


def test_resolved_archive_hides_entry_but_retains_incident_evidence(incident_service):
    database, service, incident = incident_service
    service.change_status(incident.id, IncidentStatus.RESOLVED, reason="Fixture resolution")
    archived_at = service.archive_resolved(incident.id)

    assert archived_at
    assert incident.id not in {item.id for item in service.list_incidents()}
    assert incident.id not in {item.incident.id for item in service.list_incident_details()}
    history = service.get_incident(incident.id)
    assert history is not None
    assert history.incident.status is IncidentStatus.RESOLVED
    assert any(event.detection_reason == "Fixture resolution" for event in history.events)
    with database.connection() as connection:
        assert connection.execute("PRAGMA foreign_key_check").fetchall() == []
