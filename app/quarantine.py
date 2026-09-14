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


class QuarantineService:
    """Move verified threat content into non-executable internal storage."""

    def __init__(self, database: Database, quarantine_dir: str | Path, incidents: IncidentService | None = None) -> None:
        self.database, self.quarantine_dir = database, normalize_path(quarantine_dir)
        self.quarantine_dir.mkdir(parents=True, exist_ok=True)
        self.incidents = incidents if incidents is not None else IncidentService(database)

    def quarantine_detection(self, detection: DetectionResult, incident_id: str, source: ScanSource, *, original_size: int | None = None) -> QuarantineItem:
        """Quarantine only signature-backed HIGH_CONFIDENCE detections."""
        if detection.status is not DetectionStatus.HIGH_CONFIDENCE: raise ValueError("Automatic quarantine requires a HIGH_CONFIDENCE detection.")
        if detection.matched_signature is None: raise ValueError("Automatic quarantine requires known-signature evidence.")
        return self.quarantine_file(incident_id=incident_id, path=detection.path, expected_sha256=detection.sha256, reason=detection.reason, source=source, expected_size=original_size)

    def quarantine_file(self, incident_id: str, path: str | Path, expected_sha256: str, reason: str, source: ScanSource, *, expected_size: int | None = None) -> QuarantineItem:
        """Quarantine one file and persist all success/failure evidence."""
        original_path, original_path_text = normalize_path(path), str(normalize_path(path))
        expected_sha256, source = _sha256(expected_sha256), ScanSource(source)
        if not reason: raise ValueError("reason must not be empty.")
        if expected_size is not None and (type(expected_size) is not int or expected_size < 0): raise ValueError("expected_size must be a nonnegative integer or None.")

        if (existing := self._existing_success(incident_id, original_path_text, expected_sha256)) is not None: return existing

        self._validate_incident(incident_id, expected_sha256)
        if expected_size is None:
            try: expected_size = original_path.stat().st_size
            except OSError: expected_size = None

        quarantine_id = str(uuid4())
        stored_path, temp_path = normalize_path(self.quarantine_dir / f"{quarantine_id}.agq"), normalize_path(self.quarantine_dir / f".{quarantine_id}.part")
        now = _utc_now()
        self._insert_pending(quarantine_id, incident_id, original_path_text, str(stored_path), expected_sha256, expected_size, now, reason, source)
        self.incidents.append_event(incident_id, IncidentEventType.QUARANTINE_STARTED, path=original_path, source=source, detection_reason=f"Quarantine {quarantine_id} started: {reason}")

        if not original_path.exists(): return self._fail(quarantine_id, incident_id, original_path, source, "Source file no longer exists; quarantine was not performed.")

        copied_integrity: IntegrityResult | None = None
        final_integrity: IntegrityResult | None = None
        try:
            shutil.copyfile(original_path, temp_path)
            _restrict_permissions(temp_path)

            copied_integrity = verify_quarantine_file(temp_path, expected_sha256, expected_size)
            if not copied_integrity.verified:
                _safe_unlink(temp_path)
                return self._fail(quarantine_id, incident_id, original_path, source, copied_integrity.error or "Copied quarantine content failed verification.", integrity=copied_integrity)

            os.replace(temp_path, stored_path)
            _restrict_permissions(stored_path)
            final_integrity = verify_quarantine_file(stored_path, expected_sha256, expected_size)
            if not final_integrity.verified:
                _safe_unlink(stored_path)
                return self._fail(quarantine_id, incident_id, original_path, source, final_integrity.error or "Final quarantine content failed verification.", integrity=final_integrity)

            if original_path.exists():
                source_integrity = verify_quarantine_file(original_path, expected_sha256, expected_size)
                if not source_integrity.verified:
                    return self._fail(quarantine_id, incident_id, original_path, source, "Original file changed after detection; it was left in place. " + (source_integrity.error or ""), integrity=final_integrity)
                try: original_path.unlink()
                except OSError as error:
                    return self._fail(quarantine_id, incident_id, original_path, source, f"Verified quarantine copy exists, but original could not be removed: {type(error).__name__}: {error}", integrity=final_integrity)

            quarantined_at = _utc_now()
            self._mark_success(quarantine_id, final_integrity, quarantined_at)
            self.incidents.append_event(incident_id, IncidentEventType.QUARANTINE_SUCCEEDED, path=original_path, source=source, detection_reason=f"Quarantine {quarantine_id} verified and original location removed.")
            if not self._known_incident_location_still_exists(incident_id):
                self.incidents.change_status(incident_id, IncidentStatus.CONTAINED, reason=f"Verified quarantine {quarantine_id} removed all currently present known incident locations.")
            return self.get_item(quarantine_id)  # type: ignore[return-value]
        except Exception as error:
            _safe_unlink(temp_path)
            return self._fail(quarantine_id, incident_id, original_path, source, f"Quarantine operation failed: {type(error).__name__}: {error}", integrity=final_integrity or copied_integrity)

    def list_quarantined_items(self) -> list[QuarantineItem]:
        """Return all quarantine attempts, including durable failure records."""
        with self.database.connection() as connection:
            rows = connection.execute("SELECT * FROM quarantine_items ORDER BY created_at DESC, rowid DESC").fetchall()
        return [_item(row) for row in rows]

    def get_item(self, quarantine_id: str) -> QuarantineItem | None:
        with self.database.connection() as connection:
            row = connection.execute("SELECT * FROM quarantine_items WHERE quarantine_id = ?", (quarantine_id,)).fetchone()
        return _item(row) if row is not None else None

    def get_metadata(self, quarantine_id: str) -> QuarantineItem | None:
        """Alias for callers that treat QuarantineItem as persisted metadata."""
        return self.get_item(quarantine_id)

    def verify_integrity(self, quarantine_id: str) -> IntegrityResult:
        """Recheck stored content and persist the newest integrity evidence."""
        if (item := self.get_item(quarantine_id)) is None: raise KeyError(f"Unknown quarantine item: {quarantine_id}")
        result = verify_quarantine_file(item.stored_path, item.sha256, item.original_size)
        with self.database.connection() as connection:
            connection.execute("BEGIN IMMEDIATE")
            connection.execute(
                """UPDATE quarantine_items
                   SET integrity_status = ?, verified_sha256 = ?, verified_size = ?,
                       verified_at = ?, state = CASE WHEN ? THEN state ELSE 'FAILED' END,
                       failure_reason = CASE WHEN ? THEN failure_reason ELSE ? END
                   WHERE quarantine_id = ?""",
                (
                    QuarantineIntegrityStatus.VERIFIED.value if result.verified else QuarantineIntegrityStatus.FAILED.value,
                    result.actual_sha256, result.actual_size, result.checked_at.isoformat(timespec="microseconds"),
                    1 if result.verified else 0, 1 if result.verified else 0,
                    result.error or "Quarantine integrity verification failed.", quarantine_id,
                ),
            )
        if not result.verified:
            self.incidents.append_event(item.incident_id, IncidentEventType.QUARANTINE_INTEGRITY_FAILED, path=item.original_path, source=item.original_source, detection_reason=f"Quarantine {quarantine_id} integrity check failed: {result.error or 'unknown integrity error'}")
            details = self.incidents.get_incident(item.incident_id)
            if details is not None and details.incident.status is IncidentStatus.CONTAINED:
                self.incidents.change_status(item.incident_id, IncidentStatus.INVESTIGATING, reason=f"Quarantine {quarantine_id} failed a later integrity check.")
        return result

    def original_location_exists(self, quarantine_id: str) -> bool:
        if (item := self.get_item(quarantine_id)) is None: raise KeyError(f"Unknown quarantine item: {quarantine_id}")
        return Path(item.original_path).exists()

    def _existing_success(self, incident_id: str, original_path: str, sha256: str) -> QuarantineItem | None:
        with self.database.connection() as connection:
            row = connection.execute(
                """SELECT * FROM quarantine_items
                   WHERE incident_id = ? AND original_path = ? AND sha256 = ?
                     AND state = 'QUARANTINED'
                   ORDER BY quarantined_at DESC, rowid DESC LIMIT 1""",
                (incident_id, original_path, sha256),
            ).fetchone()
        return _item(row) if row is not None else None

    def _validate_incident(self, incident_id: str, sha256: str) -> None:
        if (details := self.incidents.get_incident(incident_id)) is None: raise KeyError(f"Unknown threat incident: {incident_id}")
        if details.incident.status is IncidentStatus.RESOLVED: raise ValueError("Cannot quarantine content for a RESOLVED incident.")
        if details.incident.sha256 != sha256: raise ValueError("Quarantine SHA-256 does not match the incident SHA-256.")

    def _insert_pending(self, quarantine_id: str, incident_id: str, original_path: str, stored_path: str, sha256: str, original_size: int | None, created_at: str, reason: str, source: ScanSource) -> None:
        with self.database.connection() as connection:
            connection.execute("BEGIN IMMEDIATE")
            connection.execute(
                """INSERT INTO quarantine_items (
                       quarantine_id, incident_id, original_path, stored_path,
                       sha256, original_size, created_at, reason, original_source,
                       state, integrity_status, original_removed
                   ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'PENDING', 'PENDING', 0)""",
                (quarantine_id, incident_id, original_path, stored_path, sha256, original_size, created_at, reason, source.value),
            )

    def _mark_success(self, quarantine_id: str, integrity: IntegrityResult, quarantined_at: str) -> None:
        with self.database.connection() as connection:
            connection.execute("BEGIN IMMEDIATE")
            connection.execute(
                """UPDATE quarantine_items
                   SET state = 'QUARANTINED', integrity_status = 'VERIFIED',
                       verified_sha256 = ?, verified_size = ?, verified_at = ?,
                       quarantined_at = ?, original_removed = 1, failure_reason = NULL
                   WHERE quarantine_id = ?""",
                (integrity.actual_sha256, integrity.actual_size, integrity.checked_at.isoformat(timespec="microseconds"), quarantined_at, quarantine_id),
            )

    def _fail(self, quarantine_id: str, incident_id: str, original_path: Path, source: ScanSource, failure_reason: str, *, integrity: IntegrityResult | None = None) -> QuarantineItem:
        integrity_status = QuarantineIntegrityStatus.VERIFIED if integrity is not None and integrity.verified else QuarantineIntegrityStatus.FAILED
        with self.database.connection() as connection:
            connection.execute("BEGIN IMMEDIATE")
            connection.execute(
                """UPDATE quarantine_items
                   SET state = 'FAILED', integrity_status = ?, verified_sha256 = ?,
                       verified_size = ?, verified_at = ?, original_removed = 0,
                       failure_reason = ?
                   WHERE quarantine_id = ?""",
                (
                    integrity_status.value,
                    integrity.actual_sha256 if integrity else None,
                    integrity.actual_size if integrity else None,
                    integrity.checked_at.isoformat(timespec="microseconds") if integrity else _utc_now(),
                    failure_reason,
                    quarantine_id,
                ),
            )
        self.incidents.append_event(incident_id, IncidentEventType.QUARANTINE_FAILED, path=original_path, source=source, detection_reason=f"Quarantine {quarantine_id} failed: {failure_reason}")
        if (item := self.get_item(quarantine_id)) is None: raise RuntimeError("Quarantine failure state was not persisted.")
        return item

    def _known_incident_location_still_exists(self, incident_id: str) -> bool:
        if (details := self.incidents.get_incident(incident_id)) is None: return False
        return any(Path(item.path).exists() for item in details.files)


def _item(row: sqlite3.Row) -> QuarantineItem:
    return QuarantineItem(
        quarantine_id=row["quarantine_id"], incident_id=row["incident_id"], original_path=row["original_path"], stored_path=row["stored_path"],
        sha256=row["sha256"], original_size=row["original_size"], created_at=datetime.fromisoformat(row["created_at"]),
        quarantined_at=datetime.fromisoformat(row["quarantined_at"]) if row["quarantined_at"] else None, reason=row["reason"],
        original_source=ScanSource(row["original_source"]), state=QuarantineState(row["state"]), integrity_status=QuarantineIntegrityStatus(row["integrity_status"]),
        verified_sha256=row["verified_sha256"], verified_size=row["verified_size"],
        verified_at=datetime.fromisoformat(row["verified_at"]) if row["verified_at"] else None, original_removed=bool(row["original_removed"]), failure_reason=row["failure_reason"],
    )


def _sha256(value: str) -> str:
    normalized = value.strip().lower()
    if len(normalized) != 64 or any(ch not in "0123456789abcdef" for ch in normalized): raise ValueError("expected_sha256 must be exactly 64 hexadecimal characters.")
    return normalized


def _utc_now() -> str: return datetime.now(timezone.utc).isoformat(timespec="microseconds")


def _safe_unlink(path: Path) -> None:
    try: path.unlink(missing_ok=True)
    except OSError: pass


def _restrict_permissions(path: Path) -> None:
    try: path.chmod(0o600)
    except OSError: pass