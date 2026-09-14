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
    OPEN, INVESTIGATING, CONTAINED, REAPPEARED, RESTORED, RESOLVED = (
        "OPEN",
        "INVESTIGATING",
        "CONTAINED",
        "REAPPEARED",
        "RESTORED",
        "RESOLVED",
    )


class IncidentEventType(str, Enum):
    (
        FIRST_OBSERVED,
        MATCHING_LOCATION_OBSERVED,
        REPEATED_DETECTION,
        STATUS_CHANGED,
        QUARANTINE_STARTED,
        QUARANTINE_SUCCEEDED,
        QUARANTINE_FAILED,
        QUARANTINE_INTEGRITY_FAILED,
        MATCHING_CLEANUP_STARTED,
        MATCHING_COPY_FOUND,
        MATCHING_COPY_QUARANTINED,
        MATCHING_COPY_ALREADY_CONTAINED,
        MATCHING_CLEANUP_FAILED,
        MATCHING_CLEANUP_FINISHED,
        CLEANUP_VERIFICATION_STARTED,
        CLEANUP_VERIFIED,
        CLEANUP_VERIFICATION_PARTIAL,
        CLEANUP_VERIFICATION_FAILED,
    ) = (
        "FIRST_OBSERVED",
        "MATCHING_LOCATION_OBSERVED",
        "REPEATED_DETECTION",
        "STATUS_CHANGED",
        "QUARANTINE_STARTED",
        "QUARANTINE_SUCCEEDED",
        "QUARANTINE_FAILED",
        "QUARANTINE_INTEGRITY_FAILED",
        "MATCHING_CLEANUP_STARTED",
        "MATCHING_COPY_FOUND",
        "MATCHING_COPY_QUARANTINED",
        "MATCHING_COPY_ALREADY_CONTAINED",
        "MATCHING_CLEANUP_FAILED",
        "MATCHING_CLEANUP_FINISHED",
        "CLEANUP_VERIFICATION_STARTED",
        "CLEANUP_VERIFIED",
        "CLEANUP_VERIFICATION_PARTIAL",
        "CLEANUP_VERIFICATION_FAILED",
    )


@dataclass(frozen=True)
class ThreatIncident:
    id: str
    sha256: str
    status: IncidentStatus
    first_observed_path: str
    created_at: datetime
    updated_at: datetime
    last_observed_at: datetime
    detection_count: int


@dataclass(frozen=True)
class IncidentFile:
    id: int
    incident_id: str
    path: str
    first_seen: datetime
    last_seen: datetime
    seen_count: int
    first_source: ScanSource
    last_source: ScanSource
    first_detection_reason: str
    last_detection_reason: str


@dataclass(frozen=True)
class IncidentEvent:
    id: int
    incident_id: str
    event_type: IncidentEventType
    occurred_at: datetime
    path: str | None
    source: ScanSource | None
    detection_reason: str | None
    old_status: IncidentStatus | None
    new_status: IncidentStatus | None


@dataclass(frozen=True)
class IncidentDetails:
    incident: ThreatIncident
    files: tuple[IncidentFile, ...]
    events: tuple[IncidentEvent, ...]


def _utc_now() -> str: return datetime.now(timezone.utc).isoformat(timespec="microseconds")


def _sha256(v: str) -> str:
    n = v.strip().lower()
    if len(n) != 64 or any(c not in "0123456789abcdef" for c in n): raise ValueError("sha256 must be exactly 64 lowercase hexadecimal characters.")
    return n


def _incident(r: sqlite3.Row) -> ThreatIncident: return ThreatIncident(id=r["id"], sha256=r["sha256"], status=IncidentStatus(r["status"]), first_observed_path=r["first_observed_path"], created_at=datetime.fromisoformat(r["created_at"]), updated_at=datetime.fromisoformat(r["updated_at"]), last_observed_at=datetime.fromisoformat(r["last_observed_at"]), detection_count=r["detection_count"])
def _file(r: sqlite3.Row) -> IncidentFile: return IncidentFile(id=r["id"], incident_id=r["incident_id"], path=r["path"], first_seen=datetime.fromisoformat(r["first_seen"]), last_seen=datetime.fromisoformat(r["last_seen"]), seen_count=r["seen_count"], first_source=ScanSource(r["first_source"]), last_source=ScanSource(r["last_source"]), first_detection_reason=r["first_detection_reason"], last_detection_reason=r["last_detection_reason"])
def _event(r: sqlite3.Row) -> IncidentEvent: return IncidentEvent(id=r["id"], incident_id=r["incident_id"], event_type=IncidentEventType(r["event_type"]), occurred_at=datetime.fromisoformat(r["occurred_at"]), path=r["path"], source=ScanSource(r["source"]) if r["source"] else None, detection_reason=r["detection_reason"], old_status=IncidentStatus(r["old_status"]) if r["old_status"] else None, new_status=IncidentStatus(r["new_status"]) if r["new_status"] else None)


class IncidentService:
    def __init__(self, database: Database) -> None: self.database = database

    def create_incident(self, sha256: str, path: str | Path, source: ScanSource, detection_reason: str) -> ThreatIncident:
        sha256, path, source, iid, now = _sha256(sha256), str(normalize_path(path)), ScanSource(source), str(uuid4()), _utc_now()
        if not detection_reason: raise ValueError("detection_reason must not be empty.")
        with self.database.connection() as c:
            c.execute("BEGIN IMMEDIATE")
            c.execute("INSERT INTO threat_incidents (id, sha256, status, first_observed_path, created_at, updated_at, last_observed_at, detection_count) VALUES (?, ?, ?, ?, ?, ?, ?, 1)", (iid, sha256, IncidentStatus.OPEN.value, path, now, now, now))
            self._insert_file(c, iid, path, source, detection_reason, now)
            self._insert_event(c, iid, IncidentEventType.FIRST_OBSERVED, now, path=path, source=source, detection_reason=detection_reason)
            return _incident(c.execute("SELECT * FROM threat_incidents WHERE id = ?", (iid,)).fetchone())

    def attach_matching_file(self, incident_id: str, path: str | Path, source: ScanSource, detection_reason: str) -> IncidentFile:
        path, source, now = str(normalize_path(path)), ScanSource(source), _utc_now()
        if not detection_reason: raise ValueError("detection_reason must not be empty.")
        with self.database.connection() as c:
            c.execute("BEGIN IMMEDIATE")
            inc = self._require_active(c, incident_id)
            ex = c.execute("SELECT * FROM incident_files WHERE incident_id = ? AND path = ?", (incident_id, path)).fetchone()
            et = IncidentEventType.REPEATED_DETECTION if ex else IncidentEventType.MATCHING_LOCATION_OBSERVED
            self._upsert_file(c, incident_id, path, source, detection_reason, now)
            self._mark_detection(c, inc, now, path, source, detection_reason)
            self._insert_event(c, incident_id, et, now, path=path, source=source, detection_reason=detection_reason)
            return _file(c.execute("SELECT * FROM incident_files WHERE incident_id = ? AND path = ?", (incident_id, path)).fetchone())

    def append_event(self, incident_id: str, event_type: IncidentEventType, *, path: str | Path | None = None, source: ScanSource | None = None, detection_reason: str | None = None, old_status: IncidentStatus | None = None, new_status: IncidentStatus | None = None) -> IncidentEvent:
        et, p, s, o, n, now = IncidentEventType(event_type), str(normalize_path(path)) if path else None, ScanSource(source) if source else None, IncidentStatus(old_status) if old_status else None, IncidentStatus(new_status) if new_status else None, _utc_now()
        with self.database.connection() as c:
            c.execute("BEGIN IMMEDIATE")
            self._require_incident(c, incident_id)
            cur = self._insert_event(c, incident_id, et, now, path=p, source=s, detection_reason=detection_reason, old_status=o, new_status=n)
            return _event(c.execute("SELECT * FROM incident_events WHERE id = ?", (cur.lastrowid,)).fetchone())

    def get_incident(self, incident_id: str) -> IncidentDetails | None:
        with self.database.connection() as c:
            c.execute("BEGIN")
            r = c.execute("SELECT * FROM threat_incidents WHERE id = ?", (incident_id,)).fetchone()
            if not r: return None
            f = c.execute("SELECT * FROM incident_files WHERE incident_id = ? ORDER BY first_seen, id", (incident_id,)).fetchall()
            e = c.execute("SELECT * FROM incident_events WHERE incident_id = ? ORDER BY occurred_at, id", (incident_id,)).fetchall()
            return IncidentDetails(incident=_incident(r), files=tuple(_file(x) for x in f), events=tuple(_event(x) for x in e))

    def get_active_incidents(self) -> list[ThreatIncident]:
        with self.database.connection() as c:
            rows = c.execute("SELECT * FROM threat_incidents WHERE status <> ? ORDER BY last_observed_at DESC, rowid DESC", (IncidentStatus.RESOLVED.value,)).fetchall()
            return [_incident(r) for r in rows]

    def change_status(self, incident_id: str, status: IncidentStatus, *, reason: str | None = None) -> ThreatIncident:
        st, now = IncidentStatus(status), _utc_now()
        with self.database.connection() as c:
            c.execute("BEGIN IMMEDIATE")
            r = self._require_incident(c, incident_id)
            old = IncidentStatus(r["status"])
            if old is st: return _incident(r)
            c.execute("UPDATE threat_incidents SET status = ?, updated_at = ? WHERE id = ?", (st.value, now, incident_id))
            self._insert_event(c, incident_id, IncidentEventType.STATUS_CHANGED, now, detection_reason=reason, old_status=old, new_status=st)
            return _incident(c.execute("SELECT * FROM threat_incidents WHERE id = ?", (incident_id,)).fetchone())

    def record_high_confidence_detection(self, detection: DetectionResult, source: ScanSource) -> ThreatIncident:
        if detection.status is not DetectionStatus.HIGH_CONFIDENCE: raise ValueError("Only HIGH_CONFIDENCE detections create or update incidents.")
        if not detection.reason: raise ValueError("High-confidence detection reason must not be empty.")
        s256, p, s, r, now = _sha256(detection.sha256), str(normalize_path(detection.path)), ScanSource(source), detection.reason, _utc_now()
        with self.database.connection() as c:
            c.execute("BEGIN IMMEDIATE")
            row = c.execute("SELECT * FROM threat_incidents WHERE sha256 = ? AND status <> ? ORDER BY created_at DESC, rowid DESC LIMIT 1", (s256, IncidentStatus.RESOLVED.value)).fetchone()
            if row is None:
                iid = str(uuid4())
                c.execute("INSERT INTO threat_incidents (id, sha256, status, first_observed_path, created_at, updated_at, last_observed_at, detection_count) VALUES (?, ?, ?, ?, ?, ?, ?, 1)", (iid, s256, IncidentStatus.OPEN.value, p, now, now, now))
                self._insert_file(c, iid, p, s, r, now)
                self._insert_event(c, iid, IncidentEventType.FIRST_OBSERVED, now, path=p, source=s, detection_reason=r)
            else:
                iid = row["id"]
                ex = c.execute("SELECT id FROM incident_files WHERE incident_id = ? AND path = ?", (iid, p)).fetchone()
                et = IncidentEventType.REPEATED_DETECTION if ex else IncidentEventType.MATCHING_LOCATION_OBSERVED
                self._upsert_file(c, iid, p, s, r, now)
                self._mark_detection(c, row, now, p, s, r)
                self._insert_event(c, iid, et, now, path=p, source=s, detection_reason=r)
            return _incident(c.execute("SELECT * FROM threat_incidents WHERE id = ?", (iid,)).fetchone())

    @staticmethod
    def _require_incident(c: sqlite3.Connection, iid: str) -> sqlite3.Row:
        r = c.execute("SELECT * FROM threat_incidents WHERE id = ?", (iid,)).fetchone()
        if not r: raise KeyError(f"Unknown threat incident: {iid}")
        return r

    @classmethod
    def _require_active(cls, c: sqlite3.Connection, iid: str) -> sqlite3.Row:
        r = cls._require_incident(c, iid)
        if r["status"] == IncidentStatus.RESOLVED.value: raise ValueError("Cannot attach detections to a RESOLVED incident.")
        return r

    @staticmethod
    def _insert_file(c: sqlite3.Connection, iid: str, p: str, s: ScanSource, r: str, now: str) -> sqlite3.Cursor:
        return c.execute("INSERT INTO incident_files (incident_id, path, first_seen, last_seen, seen_count, first_source, last_source, first_detection_reason, last_detection_reason) VALUES (?, ?, ?, ?, 1, ?, ?, ?, ?)", (iid, p, now, now, s.value, s.value, r, r))

    @classmethod
    def _upsert_file(cls, c: sqlite3.Connection, iid: str, p: str, s: ScanSource, r: str, now: str) -> None:
        row = c.execute("SELECT id FROM incident_files WHERE incident_id = ? AND path = ?", (iid, p)).fetchone()
        if not row: cls._insert_file(c, iid, p, s, r, now); return
        c.execute("UPDATE incident_files SET last_seen = ?, seen_count = seen_count + 1, last_source = ?, last_detection_reason = ? WHERE id = ?", (now, s.value, r, row["id"]))

    @classmethod
    def _mark_detection(cls, c: sqlite3.Connection, inc: sqlite3.Row, now: str, p: str, s: ScanSource, r: str) -> None:
        old = IncidentStatus(inc["status"])
        new = IncidentStatus.REAPPEARED if old in (IncidentStatus.CONTAINED, IncidentStatus.RESTORED) else old
        c.execute("UPDATE threat_incidents SET status = ?, updated_at = ?, last_observed_at = ?, detection_count = detection_count + 1 WHERE id = ?", (new.value, now, now, inc["id"]))
        if new is not old: cls._insert_event(c, inc["id"], IncidentEventType.STATUS_CHANGED, now, path=p, source=s, detection_reason=r, old_status=old, new_status=new)

    @staticmethod
    def _insert_event(c: sqlite3.Connection, iid: str, et: IncidentEventType, now: str, *, path: str | None = None, source: ScanSource | None = None, detection_reason: str | None = None, old_status: IncidentStatus | None = None, new_status: IncidentStatus | None = None) -> sqlite3.Cursor:
        return c.execute("INSERT INTO incident_events (incident_id, event_type, occurred_at, path, source, detection_reason, old_status, new_status) VALUES (?, ?, ?, ?, ?, ?, ?, ?)", (iid, IncidentEventType(et).value, now, path, source.value if source else None, detection_reason, old_status.value if old_status else None, new_status.value if new_status else None))