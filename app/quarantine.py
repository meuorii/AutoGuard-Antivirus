import os, shutil, sqlite3
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from uuid import uuid4

from app.database import Database
from app.hashing import normalize_path
from app.incidents import IncidentEventType, IncidentService, IncidentStatus
from app.models import DetectionResult, DetectionStatus, ScanSource
from app.quarantine_integrity import IntegrityResult, verify_quarantine_file


class QuarantineState(str, Enum):
    PENDING, QUARANTINED, FAILED = "PENDING", "QUARANTINED", "FAILED"


class QuarantineIntegrityStatus(str, Enum):
    PENDING, VERIFIED, FAILED = "PENDING", "VERIFIED", "FAILED"


@dataclass(frozen=True)
class QuarantineItem:
    quarantine_id: str
    incident_id: str
    original_path: str
    stored_path: str
    sha256: str
    original_size: int | None
    created_at: datetime
    quarantined_at: datetime | None
    reason: str
    original_source: ScanSource
    state: QuarantineState
    integrity_status: QuarantineIntegrityStatus
    verified_sha256: str | None
    verified_size: int | None
    verified_at: datetime | None
    original_removed: bool
    failure_reason: str | None


def _item(r: sqlite3.Row) -> QuarantineItem:
    return QuarantineItem(quarantine_id=r["quarantine_id"], incident_id=r["incident_id"], original_path=r["original_path"], stored_path=r["stored_path"], sha256=r["sha256"], original_size=r["original_size"], created_at=datetime.fromisoformat(r["created_at"]), quarantined_at=datetime.fromisoformat(r["quarantined_at"]) if r["quarantined_at"] else None, reason=r["reason"], original_source=ScanSource(r["original_source"]), state=QuarantineState(r["state"]), integrity_status=QuarantineIntegrityStatus(r["integrity_status"]), verified_sha256=r["verified_sha256"], verified_size=r["verified_size"], verified_at=datetime.fromisoformat(r["verified_at"]) if r["verified_at"] else None, original_removed=bool(r["original_removed"]), failure_reason=r["failure_reason"])


def _sha256(v: str) -> str:
    n = v.strip().lower()
    if len(n) != 64 or any(c not in "0123456789abcdef" for c in n): raise ValueError("expected_sha256 must be exactly 64 hexadecimal characters.")
    return n


def _utc_now() -> str: return datetime.now(timezone.utc).isoformat(timespec="microseconds")


def _safe_unlink(p: Path) -> None:
    try: p.unlink(missing_ok=True)
    except OSError: pass


def _restrict_permissions(p: Path) -> None:
    try: p.chmod(0o600)
    except OSError: pass


class QuarantineService:
    def __init__(self, database: Database, quarantine_dir: str | Path, incidents: IncidentService | None = None) -> None:
        self.database, self.quarantine_dir = database, normalize_path(quarantine_dir)
        self.quarantine_dir.mkdir(parents=True, exist_ok=True)
        self.incidents = incidents if incidents is not None else IncidentService(database)

    def quarantine_detection(self, detection: DetectionResult, incident_id: str, source: ScanSource, *, original_size: int | None = None) -> QuarantineItem:
        if detection.status is not DetectionStatus.HIGH_CONFIDENCE: raise ValueError("Automatic quarantine requires a HIGH_CONFIDENCE detection.")
        if detection.matched_signature is None: raise ValueError("Automatic quarantine requires known-signature evidence.")
        return self.quarantine_file(incident_id=incident_id, path=detection.path, expected_sha256=detection.sha256, reason=detection.reason, source=source, expected_size=original_size)

    def quarantine_file(self, incident_id: str, path: str | Path, expected_sha256: str, reason: str, source: ScanSource, *, expected_size: int | None = None) -> QuarantineItem:
        orig_p, sha, src = normalize_path(path), _sha256(expected_sha256), ScanSource(source)
        orig_text = str(orig_p)
        if not reason: raise ValueError("reason must not be empty.")
        if expected_size is not None and (type(expected_size) is not int or expected_size < 0): raise ValueError("expected_size must be a nonnegative integer or None.")
        existing = self._existing_success(incident_id, orig_text, sha)
        if existing is not None: return existing
        self._validate_incident(incident_id, sha)
        if expected_size is None:
            try: expected_size = orig_p.stat().st_size
            except OSError: expected_size = None
        qid = str(uuid4())
        stored_p, temp_p, now = normalize_path(self.quarantine_dir / f"{qid}.agq"), normalize_path(self.quarantine_dir / f".{qid}.part"), _utc_now()
        self._insert_pending(qid, incident_id, orig_text, str(stored_p), sha, expected_size, now, reason, src)
        self.incidents.append_event(incident_id, IncidentEventType.QUARANTINE_STARTED, path=orig_p, source=src, detection_reason=f"Quarantine {qid} started: {reason}")
        if not orig_p.exists(): return self._fail(qid, incident_id, orig_p, src, "Source file no longer exists; quarantine was not performed.")
        copied_int: IntegrityResult | None = None
        final_int: IntegrityResult | None = None
        try:
            shutil.copyfile(orig_p, temp_p)
            _restrict_permissions(temp_p)
            copied_int = verify_quarantine_file(temp_p, sha, expected_size)
            if not copied_int.verified:
                _safe_unlink(temp_p)
                return self._fail(qid, incident_id, orig_p, src, copied_int.error or "Copied quarantine content failed verification.", integrity=copied_int)
            os.replace(temp_p, stored_p)
            _restrict_permissions(stored_p)
            final_int = verify_quarantine_file(stored_p, sha, expected_size)
            if not final_int.verified:
                _safe_unlink(stored_p)
                return self._fail(qid, incident_id, orig_p, src, final_int.error or "Final quarantine content failed verification.", integrity=final_int)
            if orig_p.exists():
                src_int = verify_quarantine_file(orig_p, sha, expected_size)
                if not src_int.verified: return self._fail(qid, incident_id, orig_p, src, "Original file changed after detection; it was left in place. " + (src_int.error or ""), integrity=final_int)
                try: orig_p.unlink()
                except OSError as e: return self._fail(qid, incident_id, orig_p, src, f"Verified quarantine copy exists, but original could not be removed: {type(e).__name__}: {e}", integrity=final_int)
            q_at = _utc_now()
            self._mark_success(qid, final_int, q_at)
            self.incidents.append_event(incident_id, IncidentEventType.QUARANTINE_SUCCEEDED, path=orig_p, source=src, detection_reason=f"Quarantine {qid} verified and original location removed.")
            return self.get_item(qid)  # type: ignore[return-value]
        except Exception as e:
            _safe_unlink(temp_p)
            return self._fail(qid, incident_id, orig_p, src, f"Quarantine operation failed: {type(e).__name__}: {e}", integrity=final_int or copied_int)

    def list_quarantined_items(self) -> list[QuarantineItem]:
        with self.database.connection() as c: return [_item(r) for r in c.execute("SELECT * FROM quarantine_items ORDER BY created_at DESC, rowid DESC").fetchall()]

    def get_item(self, quarantine_id: str) -> QuarantineItem | None:
        with self.database.connection() as c:
            r = c.execute("SELECT * FROM quarantine_items WHERE quarantine_id = ?", (quarantine_id,)).fetchone()
            return _item(r) if r is not None else None

    def get_metadata(self, quarantine_id: str) -> QuarantineItem | None: return self.get_item(quarantine_id)

    def verify_integrity(self, quarantine_id: str) -> IntegrityResult:
        item = self.get_item(quarantine_id)
        if item is None: raise KeyError(f"Unknown quarantine item: {quarantine_id}")
        res = verify_quarantine_file(item.stored_path, item.sha256, item.original_size)
        with self.database.connection() as c:
            c.execute("BEGIN IMMEDIATE")
            c.execute("UPDATE quarantine_items SET integrity_status = ?, verified_sha256 = ?, verified_size = ?, verified_at = ?, state = CASE WHEN ? THEN state ELSE 'FAILED' END, failure_reason = CASE WHEN ? THEN failure_reason ELSE ? END WHERE quarantine_id = ?", (QuarantineIntegrityStatus.VERIFIED.value if res.verified else QuarantineIntegrityStatus.FAILED.value, res.actual_sha256, res.actual_size, res.checked_at.isoformat(timespec="microseconds"), 1 if res.verified else 0, 1 if res.verified else 0, res.error or "Quarantine integrity verification failed.", quarantine_id))
        if not res.verified:
            self.incidents.append_event(item.incident_id, IncidentEventType.QUARANTINE_INTEGRITY_FAILED, path=item.original_path, source=item.original_source, detection_reason=f"Quarantine {quarantine_id} integrity check failed: {res.error or 'unknown integrity error'}")
            dt = self.incidents.get_incident(item.incident_id)
            if dt is not None and dt.incident.status not in (IncidentStatus.INVESTIGATING, IncidentStatus.RESOLVED):
                self.incidents.change_status(item.incident_id, IncidentStatus.INVESTIGATING, reason=f"Quarantine {quarantine_id} failed a later integrity check.")
        return res

    def original_location_exists(self, quarantine_id: str) -> bool:
        item = self.get_item(quarantine_id)
        if item is None: raise KeyError(f"Unknown quarantine item: {quarantine_id}")
        return Path(item.original_path).exists()

    def _existing_success(self, incident_id: str, original_path: str, sha256: str) -> QuarantineItem | None:
        with self.database.connection() as c:
            r = c.execute("SELECT * FROM quarantine_items WHERE incident_id = ? AND original_path = ? AND sha256 = ? AND state = 'QUARANTINED' ORDER BY quarantined_at DESC, rowid DESC LIMIT 1", (incident_id, original_path, sha256)).fetchone()
        if r is None or Path(original_path).exists(): return None
        return _item(r)

    def _validate_incident(self, incident_id: str, sha256: str) -> None:
        dt = self.incidents.get_incident(incident_id)
        if dt is None: raise KeyError(f"Unknown threat incident: {incident_id}")
        if dt.incident.status is IncidentStatus.RESOLVED: raise ValueError("Cannot quarantine content for a RESOLVED incident.")
        if dt.incident.sha256 != sha256: raise ValueError("Quarantine SHA-256 does not match the incident SHA-256.")

    def _insert_pending(self, qid: str, iid: str, orig_p: str, store_p: str, sha: str, orig_sz: int | None, created_at: str, reason: str, src: ScanSource) -> None:
        with self.database.connection() as c:
            c.execute("BEGIN IMMEDIATE")
            c.execute("INSERT INTO quarantine_items (quarantine_id, incident_id, original_path, stored_path, sha256, original_size, created_at, reason, original_source, state, integrity_status, original_removed) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'PENDING', 'PENDING', 0)", (qid, iid, orig_p, store_p, sha, orig_sz, created_at, reason, src.value))

    def _mark_success(self, qid: str, integrity: IntegrityResult, quarantined_at: str) -> None:
        with self.database.connection() as c:
            c.execute("BEGIN IMMEDIATE")
            c.execute("UPDATE quarantine_items SET state = 'QUARANTINED', integrity_status = 'VERIFIED', verified_sha256 = ?, verified_size = ?, verified_at = ?, quarantined_at = ?, original_removed = 1, failure_reason = NULL WHERE quarantine_id = ?", (integrity.actual_sha256, integrity.actual_size, integrity.checked_at.isoformat(timespec="microseconds"), quarantined_at, qid))

    def _fail(self, qid: str, iid: str, orig_p: Path, src: ScanSource, failure_reason: str, *, integrity: IntegrityResult | None = None) -> QuarantineItem:
        st = QuarantineIntegrityStatus.VERIFIED if integrity is not None and integrity.verified else QuarantineIntegrityStatus.FAILED
        with self.database.connection() as c:
            c.execute("BEGIN IMMEDIATE")
            c.execute("UPDATE quarantine_items SET state = 'FAILED', integrity_status = ?, verified_sha256 = ?, verified_size = ?, verified_at = ?, original_removed = 0, failure_reason = ? WHERE quarantine_id = ?", (st.value, integrity.actual_sha256 if integrity else None, integrity.actual_size if integrity else None, integrity.checked_at.isoformat(timespec="microseconds") if integrity else _utc_now(), failure_reason, qid))
        self.incidents.append_event(iid, IncidentEventType.QUARANTINE_FAILED, path=orig_p, source=src, detection_reason=f"Quarantine {qid} failed: {failure_reason}")
        item = self.get_item(qid)
        if item is None: raise RuntimeError("Quarantine failure state was not persisted.")
        return item

    def _known_incident_location_still_exists(self, incident_id: str) -> bool:
        dt = self.incidents.get_incident(incident_id)
        return False if dt is None else any(Path(i.path).exists() for i in dt.files)