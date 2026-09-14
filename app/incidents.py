"""Threat incidents grouped by identical malicious content (SHA-256).

Incidents record observations, status transitions, quarantine events, matching-copy cleanup, cleanup verification, and Phase 9 reappearance evidence.
Restore remains outside this phase.
"""

import sqlite3
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from uuid import uuid4

from app.database import Database
from app.hashing import normalize_path
from app.models import DetectionResult, DetectionStatus, ScanSource


class IncidentStatus(str, Enum):
    OPEN = "OPEN"; INVESTIGATING = "INVESTIGATING"; CONTAINED = "CONTAINED"; REAPPEARED = "REAPPEARED"; RESTORED = "RESTORED"; RESOLVED = "RESOLVED"


class IncidentEventType(str, Enum):
    FIRST_OBSERVED = "FIRST_OBSERVED"; MATCHING_LOCATION_OBSERVED = "MATCHING_LOCATION_OBSERVED"; REPEATED_DETECTION = "REPEATED_DETECTION"; STATUS_CHANGED = "STATUS_CHANGED"; QUARANTINE_STARTED = "QUARANTINE_STARTED"; QUARANTINE_SUCCEEDED = "QUARANTINE_SUCCEEDED"; QUARANTINE_FAILED = "QUARANTINE_FAILED"; QUARANTINE_INTEGRITY_FAILED = "QUARANTINE_INTEGRITY_FAILED"; MATCHING_CLEANUP_STARTED = "MATCHING_CLEANUP_STARTED"; MATCHING_COPY_FOUND = "MATCHING_COPY_FOUND"; MATCHING_COPY_QUARANTINED = "MATCHING_COPY_QUARANTINED"; MATCHING_COPY_ALREADY_CONTAINED = "MATCHING_COPY_ALREADY_CONTAINED"; MATCHING_CLEANUP_FAILED = "MATCHING_CLEANUP_FAILED"; MATCHING_CLEANUP_FINISHED = "MATCHING_CLEANUP_FINISHED"; CLEANUP_VERIFICATION_STARTED = "CLEANUP_VERIFICATION_STARTED"; CLEANUP_VERIFIED = "CLEANUP_VERIFIED"; CLEANUP_VERIFICATION_PARTIAL = "CLEANUP_VERIFICATION_PARTIAL"; CLEANUP_VERIFICATION_FAILED = "CLEANUP_VERIFICATION_FAILED"; REAPPEARANCE = "REAPPEARANCE"


@dataclass(frozen=True)
class ThreatIncident:
    id: str; sha256: str; status: IncidentStatus; first_observed_path: str; created_at: datetime; updated_at: datetime; last_observed_at: datetime; detection_count: int; reappearance_count: int


@dataclass(frozen=True)
class IncidentFile:
    id: int; incident_id: str; path: str; first_seen: datetime; last_seen: datetime; seen_count: int; first_source: ScanSource; last_source: ScanSource; first_detection_reason: str; last_detection_reason: str


@dataclass(frozen=True)
class IncidentEvent:
    id: int; incident_id: str; event_type: IncidentEventType; occurred_at: datetime; path: str | None; source: ScanSource | None; detection_reason: str | None; old_status: IncidentStatus | None; new_status: IncidentStatus | None; reappearance_count: int | None


@dataclass(frozen=True)
class IncidentDetails:
    incident: ThreatIncident; files: tuple[IncidentFile, ...]; events: tuple[IncidentEvent, ...]


def _utc_now() -> str: return datetime.now(timezone.utc).isoformat(timespec="microseconds")


def _sha256(value: str) -> str:
    normalized = value.strip().lower()
    if len(normalized) != 64 or any(ch not in "0123456789abcdef" for ch in normalized): raise ValueError("sha256 must be exactly 64 lowercase hexadecimal characters.")
    return normalized


def _incident(row: sqlite3.Row) -> ThreatIncident:
    return ThreatIncident(id=row["id"], sha256=row["sha256"], status=IncidentStatus(row["status"]), first_observed_path=row["first_observed_path"], created_at=datetime.fromisoformat(row["created_at"]), updated_at=datetime.fromisoformat(row["updated_at"]), last_observed_at=datetime.fromisoformat(row["last_observed_at"]), detection_count=row["detection_count"], reappearance_count=row["reappearance_count"])


def _file(row: sqlite3.Row) -> IncidentFile:
    return IncidentFile(id=row["id"], incident_id=row["incident_id"], path=row["path"], first_seen=datetime.fromisoformat(row["first_seen"]), last_seen=datetime.fromisoformat(row["last_seen"]), seen_count=row["seen_count"], first_source=ScanSource(row["first_source"]), last_source=ScanSource(row["last_source"]), first_detection_reason=row["first_detection_reason"], last_detection_reason=row["last_detection_reason"])


def _event(row: sqlite3.Row) -> IncidentEvent:
    return IncidentEvent(id=row["id"], incident_id=row["incident_id"], event_type=IncidentEventType(row["event_type"]), occurred_at=datetime.fromisoformat(row["occurred_at"]), path=row["path"], source=ScanSource(row["source"]) if row["source"] else None, detection_reason=row["detection_reason"], old_status=IncidentStatus(row["old_status"]) if row["old_status"] else None, new_status=IncidentStatus(row["new_status"]) if row["new_status"] else None, reappearance_count=row["reappearance_count"])


class IncidentService:
    """Persist incident state and timeline evidence without taking file actions."""

    def __init__(self, database: Database) -> None: self.database = database

    def create_incident(self, sha256: str, path: str | Path, source: ScanSource, detection_reason: str) -> ThreatIncident:
        """Create one OPEN incident with its first observed location."""
        sha256 = _sha256(sha256); path = str(normalize_path(path)); source = ScanSource(source)
        if not detection_reason: raise ValueError("detection_reason must not be empty.")
        incident_id, now = str(uuid4()), _utc_now()
        with self.database.connection() as connection:
            connection.execute("BEGIN IMMEDIATE")
            connection.execute("INSERT INTO threat_incidents (id, sha256, status, first_observed_path, created_at, updated_at, last_observed_at, detection_count) VALUES (?, ?, ?, ?, ?, ?, ?, 1)", (incident_id, sha256, IncidentStatus.OPEN.value, path, now, now, now))
            self._insert_file(connection, incident_id, path, source, detection_reason, now)
            self._insert_event(connection, incident_id, IncidentEventType.FIRST_OBSERVED, now, path=path, source=source, detection_reason=detection_reason)
            row = connection.execute("SELECT * FROM threat_incidents WHERE id = ?", (incident_id,)).fetchone()
        return _incident(row)

    def attach_matching_file(self, incident_id: str, path: str | Path, source: ScanSource, detection_reason: str) -> IncidentFile:
        """Attach or refresh an observed location and append its detection event."""
        path = str(normalize_path(path)); source = ScanSource(source)
        if not detection_reason: raise ValueError("detection_reason must not be empty.")
        now = _utc_now()
        with self.database.connection() as connection:
            connection.execute("BEGIN IMMEDIATE")
            incident = self._require_active(connection, incident_id)
            existing = connection.execute("SELECT * FROM incident_files WHERE incident_id = ? AND path = ?", (incident_id, path)).fetchone()
            event_type = IncidentEventType.REPEATED_DETECTION if existing is not None else IncidentEventType.MATCHING_LOCATION_OBSERVED
            self._upsert_file(connection, incident_id, path, source, detection_reason, now)
            self._mark_detection(connection, incident, now, path, source, detection_reason)
            self._insert_event(connection, incident_id, event_type, now, path=path, source=source, detection_reason=detection_reason)
            row = connection.execute("SELECT * FROM incident_files WHERE incident_id = ? AND path = ?", (incident_id, path)).fetchone()
        return _file(row)

    def append_event(self, incident_id: str, event_type: IncidentEventType, *, path: str | Path | None = None, source: ScanSource | None = None, detection_reason: str | None = None, old_status: IncidentStatus | None = None, new_status: IncidentStatus | None = None, reappearance_count: int | None = None) -> IncidentEvent:
        """Append a timeline event without changing incident/file counters."""
        event_type = IncidentEventType(event_type)
        normalized_path = str(normalize_path(path)) if path is not None else None
        normalized_source = ScanSource(source) if source is not None else None
        old, new = IncidentStatus(old_status) if old_status is not None else None, IncidentStatus(new_status) if new_status is not None else None
        if reappearance_count is not None and (type(reappearance_count) is not int or reappearance_count < 1): raise ValueError("reappearance_count must be a positive integer or None.")
        now = _utc_now()
        with self.database.connection() as connection:
            connection.execute("BEGIN IMMEDIATE")
            self._require_incident(connection, incident_id)
            cursor = self._insert_event(connection, incident_id, event_type, now, path=normalized_path, source=normalized_source, detection_reason=detection_reason, old_status=old, new_status=new, reappearance_count=reappearance_count)
            row = connection.execute("SELECT * FROM incident_events WHERE id = ?", (cursor.lastrowid,)).fetchone()
        return _event(row)

    def get_incident(self, incident_id: str) -> IncidentDetails | None:
        """Return the incident plus all known locations and ordered timeline events."""
        with self.database.connection() as connection:
            connection.execute("BEGIN")
            row = connection.execute("SELECT * FROM threat_incidents WHERE id = ?", (incident_id,)).fetchone()
            if row is None: return None
            files = connection.execute("SELECT * FROM incident_files WHERE incident_id = ? ORDER BY first_seen, id", (incident_id,)).fetchall()
            events = connection.execute("SELECT * FROM incident_events WHERE incident_id = ? ORDER BY occurred_at, id", (incident_id,)).fetchall()
        return IncidentDetails(incident=_incident(row), files=tuple(_file(item) for item in files), events=tuple(_event(item) for item in events))

    def get_active_incidents(self) -> list[ThreatIncident]:
        """Return every non-RESOLVED incident, newest observation first."""
        with self.database.connection() as connection:
            rows = connection.execute("SELECT * FROM threat_incidents WHERE status <> ? ORDER BY last_observed_at DESC, rowid DESC", (IncidentStatus.RESOLVED.value,)).fetchall()
        return [_incident(row) for row in rows]

    def change_status(self, incident_id: str, status: IncidentStatus, *, reason: str | None = None) -> ThreatIncident:
        """Change incident status and record the transition in the timeline."""
        status, now = IncidentStatus(status), _utc_now()
        with self.database.connection() as connection:
            connection.execute("BEGIN IMMEDIATE")
            row = self._require_incident(connection, incident_id)
            old = IncidentStatus(row["status"])
            if old is status: return _incident(row)
            connection.execute("UPDATE threat_incidents SET status = ?, updated_at = ? WHERE id = ?", (status.value, now, incident_id))
            self._insert_event(connection, incident_id, IncidentEventType.STATUS_CHANGED, now, detection_reason=reason, old_status=old, new_status=status)
            row = connection.execute("SELECT * FROM threat_incidents WHERE id = ?", (incident_id,)).fetchone()
        return _incident(row)

    def record_high_confidence_detection(self, detection: DetectionResult, source: ScanSource) -> ThreatIncident:
        """Create or update the active incident for a high-confidence SHA-256."""
        if detection.status is not DetectionStatus.HIGH_CONFIDENCE: raise ValueError("Only HIGH_CONFIDENCE detections create or update incidents.")
        sha256, path, source, reason = _sha256(detection.sha256), str(normalize_path(detection.path)), ScanSource(source), detection.reason
        if not reason: raise ValueError("High-confidence detection reason must not be empty.")
        now = _utc_now()
        with self.database.connection() as connection:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute("SELECT * FROM threat_incidents WHERE sha256 = ? AND status <> ? ORDER BY created_at DESC, rowid DESC LIMIT 1", (sha256, IncidentStatus.RESOLVED.value)).fetchone()
            if row is None:
                incident_id = str(uuid4())
                connection.execute("INSERT INTO threat_incidents (id, sha256, status, first_observed_path, created_at, updated_at, last_observed_at, detection_count) VALUES (?, ?, ?, ?, ?, ?, ?, 1)", (incident_id, sha256, IncidentStatus.OPEN.value, path, now, now, now))
                self._insert_file(connection, incident_id, path, source, reason, now)
                self._insert_event(connection, incident_id, IncidentEventType.FIRST_OBSERVED, now, path=path, source=source, detection_reason=reason)
            else:
                incident_id = row["id"]
                existing_file = connection.execute("SELECT id FROM incident_files WHERE incident_id = ? AND path = ?", (incident_id, path)).fetchone()
                event_type = IncidentEventType.REPEATED_DETECTION if existing_file is not None else IncidentEventType.MATCHING_LOCATION_OBSERVED
                self._upsert_file(connection, incident_id, path, source, reason, now)
                self._mark_detection(connection, row, now, path, source, reason)
                self._insert_event(connection, incident_id, event_type, now, path=path, source=source, detection_reason=reason)
            current = connection.execute("SELECT * FROM threat_incidents WHERE id = ?", (incident_id,)).fetchone()
        return _incident(current)

    def record_reappearance(self, incident_id: str, detection: DetectionResult, source: ScanSource, *, explanation: str) -> tuple[ThreatIncident, IncidentEvent]:
        """Reuse a previously handled incident and record one reappearance."""
        if detection.status is not DetectionStatus.HIGH_CONFIDENCE: raise ValueError("Only HIGH_CONFIDENCE detections can be reappearances.")
        if not explanation: raise ValueError("explanation must not be empty.")
        source, path, sha256, now = ScanSource(source), str(normalize_path(detection.path)), _sha256(detection.sha256), _utc_now()
        with self.database.connection() as connection:
            connection.execute("BEGIN IMMEDIATE")
            row = self._require_incident(connection, incident_id)
            if row["sha256"] != sha256: raise ValueError("Reappearance SHA-256 does not match the incident SHA-256.")
            old, count = IncidentStatus(row["status"]), row["reappearance_count"] + 1
            self._upsert_file(connection, incident_id, path, source, detection.reason, now)
            connection.execute("UPDATE threat_incidents SET status = ?, updated_at = ?, last_observed_at = ?, detection_count = detection_count + 1, reappearance_count = ? WHERE id = ?", (IncidentStatus.REAPPEARED.value, now, now, count, incident_id))
            if old is not IncidentStatus.REAPPEARED:
                self._insert_event(connection, incident_id, IncidentEventType.STATUS_CHANGED, now, detection_reason=f"Exact SHA-256 reappearance detected; containment is pending. {explanation}", old_status=old, new_status=IncidentStatus.REAPPEARED)
            event_cursor = self._insert_event(connection, incident_id, IncidentEventType.REAPPEARANCE, now, path=path, source=source, detection_reason=explanation, reappearance_count=count)
            incident_row = connection.execute("SELECT * FROM threat_incidents WHERE id = ?", (incident_id,)).fetchone()
            event_row = connection.execute("SELECT * FROM incident_events WHERE id = ?", (event_cursor.lastrowid,)).fetchone()
        return _incident(incident_row), _event(event_row)

    @staticmethod
    def _require_incident(connection: sqlite3.Connection, incident_id: str) -> sqlite3.Row:
        row = connection.execute("SELECT * FROM threat_incidents WHERE id = ?", (incident_id,)).fetchone()
        if row is None: raise KeyError(f"Unknown threat incident: {incident_id}")
        return row

    @classmethod
    def _require_active(cls, connection: sqlite3.Connection, incident_id: str) -> sqlite3.Row:
        row = cls._require_incident(connection, incident_id)
        if row["status"] == IncidentStatus.RESOLVED.value: raise ValueError("Cannot attach detections to a RESOLVED incident.")
        return row

    @staticmethod
    def _insert_file(connection: sqlite3.Connection, incident_id: str, path: str, source: ScanSource, reason: str, occurred_at: str) -> sqlite3.Cursor:
        return connection.execute("INSERT INTO incident_files (incident_id, path, first_seen, last_seen, seen_count, first_source, last_source, first_detection_reason, last_detection_reason) VALUES (?, ?, ?, ?, 1, ?, ?, ?, ?)", (incident_id, path, occurred_at, occurred_at, source.value, source.value, reason, reason))

    @classmethod
    def _upsert_file(cls, connection: sqlite3.Connection, incident_id: str, path: str, source: ScanSource, reason: str, occurred_at: str) -> None:
        row = connection.execute("SELECT id FROM incident_files WHERE incident_id = ? AND path = ?", (incident_id, path)).fetchone()
        if row is None: cls._insert_file(connection, incident_id, path, source, reason, occurred_at); return
        connection.execute("UPDATE incident_files SET last_seen = ?, seen_count = seen_count + 1, last_source = ?, last_detection_reason = ? WHERE id = ?", (occurred_at, source.value, reason, row["id"]))

    @classmethod
    def _mark_detection(cls, connection: sqlite3.Connection, incident: sqlite3.Row, occurred_at: str, path: str, source: ScanSource, reason: str) -> None:
        old = IncidentStatus(incident["status"])
        new = IncidentStatus.REAPPEARED if old in (IncidentStatus.CONTAINED, IncidentStatus.RESTORED) else old
        connection.execute("UPDATE threat_incidents SET status = ?, updated_at = ?, last_observed_at = ?, detection_count = detection_count + 1 WHERE id = ?", (new.value, occurred_at, occurred_at, incident["id"]))
        if new is not old: cls._insert_event(connection, incident["id"], IncidentEventType.STATUS_CHANGED, occurred_at, path=path, source=source, detection_reason=reason, old_status=old, new_status=new)

    @staticmethod
    def _insert_event(connection: sqlite3.Connection, incident_id: str, event_type: IncidentEventType, occurred_at: str, *, path: str | None = None, source: ScanSource | None = None, detection_reason: str | None = None, old_status: IncidentStatus | None = None, new_status: IncidentStatus | None = None, reappearance_count: int | None = None) -> sqlite3.Cursor:
        return connection.execute("INSERT INTO incident_events (incident_id, event_type, occurred_at, path, source, detection_reason, reappearance_count, old_status, new_status) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)", (incident_id, IncidentEventType(event_type).value, occurred_at, path, source.value if source is not None else None, detection_reason, reappearance_count, old_status.value if old_status is not None else None, new_status.value if new_status is not None else None))