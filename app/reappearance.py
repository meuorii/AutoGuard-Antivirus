from dataclasses import dataclass
from pathlib import Path

from app.database import Database
from app.incidents import IncidentEvent, IncidentService, ThreatIncident
from app.models import DetectionResult, DetectionStatus, ScanSource

REAPPEARANCE_EXPLANATION = ("This threat has reappeared after cleanup. Another application, archive, " "synchronization process, removable drive, or other source may be recreating it.")


@dataclass(frozen=True)
class ReappearanceResult:
    detected: bool
    incident: ThreatIncident | None
    event: IncidentEvent | None
    reappearance_count: int
    explanation: str | None


class ReappearanceWatch:
    """Link new exact-hash detections back to previously handled incidents."""

    def __init__(self, database: Database, incidents: IncidentService | None = None) -> None:
        self.database = database
        self.incidents = incidents if incidents is not None else IncidentService(database)

    def check_detection(self, detection: DetectionResult, source: ScanSource) -> ReappearanceResult:
        """Record and return a reappearance when prior cleanup evidence exists.

        Low-confidence/clean results never qualify.  A high-confidence hash that
        was merely seen before but was never successfully quarantined or
        contained is left to the normal incident flow.
        """
        if detection.status is not DetectionStatus.HIGH_CONFIDENCE: return ReappearanceResult(False, None, None, 0, None)

        source = ScanSource(source)
        incident_id = self._find_prior_handled_incident(detection.sha256)
        if incident_id is None: return ReappearanceResult(False, None, None, 0, None)

        incident, event = self.incidents.record_reappearance(incident_id, detection, source, explanation=REAPPEARANCE_EXPLANATION)
        return ReappearanceResult(True, incident, event, incident.reappearance_count, REAPPEARANCE_EXPLANATION)

    def _find_prior_handled_incident(self, sha256: str) -> str | None:
        normalized = _sha256(sha256)
        with self.database.connection() as connection:
            active = connection.execute(
                """SELECT ti.id, ti.status,
                          EXISTS(
                              SELECT 1 FROM quarantine_items q
                              WHERE q.incident_id = ti.id
                                AND q.sha256 = ti.sha256
                                AND q.state = 'QUARANTINED'
                          ) AS was_quarantined,
                          EXISTS(
                              SELECT 1 FROM cleanup_verifications v
                              WHERE v.incident_id = ti.id
                                AND v.sha256 = ti.sha256
                                AND v.status = 'VERIFIED'
                          ) AS was_verified
                   FROM threat_incidents ti
                   WHERE ti.sha256 = ? AND ti.status <> 'RESOLVED'
                   ORDER BY ti.updated_at DESC, ti.rowid DESC
                   LIMIT 1""",
                (normalized,),
            ).fetchone()
            if active is not None:
                if active["status"] in ("CONTAINED", "REAPPEARED", "RESTORED") or bool(active["was_quarantined"]) or bool(active["was_verified"]):
                    return active["id"]
                return None
            historical = connection.execute(
                """SELECT ti.id
                   FROM threat_incidents ti
                   WHERE ti.sha256 = ? AND ti.status = 'RESOLVED'
                     AND (
                         EXISTS(
                             SELECT 1 FROM quarantine_items q
                             WHERE q.incident_id = ti.id
                               AND q.sha256 = ti.sha256
                               AND q.state = 'QUARANTINED'
                         )
                         OR EXISTS(
                             SELECT 1 FROM cleanup_verifications v
                             WHERE v.incident_id = ti.id
                               AND v.sha256 = ti.sha256
                               AND v.status = 'VERIFIED'
                         )
                         OR EXISTS(
                             SELECT 1 FROM incident_events e
                             WHERE e.incident_id = ti.id
                               AND e.event_type = 'STATUS_CHANGED'
                               AND e.new_status = 'CONTAINED'
                         )
                     )
                   ORDER BY ti.updated_at DESC, ti.rowid DESC
                   LIMIT 1""",
                (normalized,),
            ).fetchone()
        return historical["id"] if historical is not None else None


def _sha256(value: str) -> str:
    normalized = value.strip().lower()
    if len(normalized) != 64 or any(ch not in "0123456789abcdef" for ch in normalized): raise ValueError("sha256 must be exactly 64 hexadecimal characters.")
    return normalized