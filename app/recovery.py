from __future__ import annotations
import os, sqlite3
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from uuid import uuid4
from app.database import Database
from app.detection_rules import SCRIPT_EXTENSIONS
from app.detector import SCRIPT_PREVIEW_BYTES, Detector
from app.hashing import inspect_file, normalize_path
from app.incidents import IncidentEventType, IncidentService, IncidentStatus
from app.models import DetectionResult, DetectionStatus, FileFingerprint, FileInspection, ScanSource
from app.quarantine import QuarantineService, QuarantineState

class RecoveryStatus(str, Enum):
    RESTORED = "RESTORED"; RESTORED_WITH_WARNING = "RESTORED_WITH_WARNING"; INTEGRITY_FAILED = "INTEGRITY_FAILED"; MISSING_QUARANTINE_OBJECT = "MISSING_QUARANTINE_OBJECT"; DESTINATION_CONFLICT = "DESTINATION_CONFLICT"; DANGEROUS_BLOCKED = "DANGEROUS_BLOCKED"; FAILED = "FAILED"

class RecoveryConflictOption(str, Enum):
    RESTORE_TO_ANOTHER_FILENAME = "RESTORE_TO_ANOTHER_FILENAME"; CHOOSE_ANOTHER_DESTINATION = "CHOOSE_ANOTHER_DESTINATION"; CANCEL = "CANCEL"

@dataclass(frozen=True)
class RecoveryAttempt:
    id: str; quarantine_id: str; incident_id: str; attempted_at: datetime; finished_at: datetime; requested_path: str; status: RecoveryStatus; detection_status: DetectionStatus | None; detection_reason: str | None; restored_path: str | None; error: str | None

@dataclass(frozen=True)
class RecoveryResult:
    status: RecoveryStatus; quarantine_id: str; incident_id: str; requested_path: str; restored_path: str | None; detection: DetectionResult | None; warning: str | None; error: str | None; conflict_options: tuple[RecoveryConflictOption, ...]; attempt: RecoveryAttempt
    @property
    def restored(self) -> bool: return self.status in (RecoveryStatus.RESTORED, RecoveryStatus.RESTORED_WITH_WARNING)

class RecoveryService:
    """Verify, re-evaluate, and safely copy a quarantine object to a destination."""
    def __init__(self, database: Database, quarantine: QuarantineService, detector: Detector, incidents: IncidentService | None = None) -> None:
        self.database, self.quarantine, self.detector, self.incidents = database, quarantine, detector, incidents if incidents is not None else IncidentService(database)

    def restore(self, quarantine_id: str, destination: str | Path | None = None) -> RecoveryResult:
        item = self.quarantine.get_item(quarantine_id)
        if item is None: raise KeyError(f"Unknown quarantine item: {quarantine_id}")
        requested, started = normalize_path(destination if destination is not None else item.original_path), _utc_now()
        requested_text = str(requested)
        self.incidents.append_event(item.incident_id, IncidentEventType.RECOVERY_ATTEMPTED, path=requested, source=ScanSource.RECOVERY, detection_reason=f"Recovery attempt for quarantine {quarantine_id} to {requested_text}. The file will not be executed or opened by AutoGuard.")

        if item.state is not QuarantineState.QUARANTINED or not Path(item.stored_path).is_file():
            msg = "Quarantine object is missing or is not in a restorable quarantined state."
            self._mark_investigating(item.incident_id, msg)
            return self._finish(item, requested_text, RecoveryStatus.MISSING_QUARANTINE_OBJECT, started=started, detection=None, restored_path=None, error=msg, event_type=IncidentEventType.RECOVERY_FAILED)

        integrity = self.quarantine.verify_integrity(quarantine_id)
        if not integrity.verified:
            msg = integrity.error or "Quarantine integrity verification failed."
            self._mark_investigating(item.incident_id, msg)
            return self._finish(item, requested_text, RecoveryStatus.INTEGRITY_FAILED, started=started, detection=None, restored_path=None, error=msg, event_type=IncidentEventType.RECOVERY_FAILED)

        if requested.exists():
            return self._finish(item, requested_text, RecoveryStatus.DESTINATION_CONFLICT, started=started, detection=None, restored_path=None, error="Destination already contains a file. AutoGuard will not overwrite it.", event_type=IncidentEventType.RECOVERY_CONFLICT, conflict_options=(RecoveryConflictOption.RESTORE_TO_ANOTHER_FILENAME, RecoveryConflictOption.CHOOSE_ANOTHER_DESTINATION, RecoveryConflictOption.CANCEL))

        try: detection = self._detect_for_destination(Path(item.stored_path), requested)
        except Exception as error: return self._finish(item, requested_text, RecoveryStatus.FAILED, started=started, detection=None, restored_path=None, error=f"Current detection evaluation failed: {type(error).__name__}: {error}", event_type=IncidentEventType.RECOVERY_FAILED)

        if detection.status is DetectionStatus.HIGH_CONFIDENCE:
            return self._finish(item, requested_text, RecoveryStatus.DANGEROUS_BLOCKED, started=started, detection=detection, restored_path=None, error=None, warning=f"Restore blocked: the current detection engine still classifies this file as dangerous. {detection.reason}", event_type=IncidentEventType.RECOVERY_BLOCKED)

        try:
            requested.parent.mkdir(parents=True, exist_ok=True); self._copy_exclusive(Path(item.stored_path), requested)
            restored_integrity = inspect_file(requested, follow_symlinks=False).fingerprint
            if restored_integrity.sha256 != item.sha256 or (item.original_size is not None and restored_integrity.size_bytes != item.original_size):
                try: requested.unlink(missing_ok=True)
                except OSError: pass
                raise RuntimeError("Restored bytes failed post-write SHA-256/size verification.")
        except FileExistsError: return self._finish(item, requested_text, RecoveryStatus.DESTINATION_CONFLICT, started=started, detection=detection, restored_path=None, error="Destination appeared during recovery; no content was overwritten.", event_type=IncidentEventType.RECOVERY_CONFLICT, conflict_options=(RecoveryConflictOption.RESTORE_TO_ANOTHER_FILENAME, RecoveryConflictOption.CHOOSE_ANOTHER_DESTINATION, RecoveryConflictOption.CANCEL))
        except Exception as error: return self._finish(item, requested_text, RecoveryStatus.FAILED, started=started, detection=detection, restored_path=None, error=f"Restore write failed: {type(error).__name__}: {error}", event_type=IncidentEventType.RECOVERY_FAILED)

        status = RecoveryStatus.RESTORED_WITH_WARNING if detection.status is DetectionStatus.LOW_CONFIDENCE else RecoveryStatus.RESTORED
        warning = detection.reason if detection.status is DetectionStatus.LOW_CONFIDENCE else None
        result = self._finish(item, requested_text, status, started=started, detection=detection, restored_path=requested_text, error=None, warning=warning, event_type=IncidentEventType.RECOVERY_SUCCEEDED)
        self.incidents.change_status(item.incident_id, IncidentStatus.RESTORED, reason=f"Quarantine {quarantine_id} was safely restored to {requested_text}. AutoGuard did not execute or open the restored file.")
        return result

    def list_attempts(self, quarantine_id: str | None = None) -> list[RecoveryAttempt]:
        with self.database.connection() as conn:
            query, params = ("SELECT * FROM quarantine_recovery_attempts ORDER BY attempted_at, rowid", ()) if quarantine_id is None else ("SELECT * FROM quarantine_recovery_attempts WHERE quarantine_id = ? ORDER BY attempted_at, rowid", (quarantine_id,))
            rows = conn.execute(query, params).fetchall()
        return [_attempt(row) for row in rows]

    def _detect_for_destination(self, stored_path: Path, destination: Path) -> DetectionResult:
        preview_bytes = SCRIPT_PREVIEW_BYTES if destination.suffix.lower() in SCRIPT_EXTENSIONS else 0
        inspection = inspect_file(stored_path, preview_bytes=preview_bytes, follow_symlinks=False)
        return self.detector.detect_inspection(FileInspection(FileFingerprint(inspection.fingerprint.sha256, str(normalize_path(destination)), inspection.fingerprint.size_bytes), inspection.preview))

    @staticmethod
    def _copy_exclusive(source: Path, destination: Path) -> None:
        with source.open("rb") as reader, destination.open("xb") as writer:
            while chunk := reader.read(1024 * 1024): writer.write(chunk)
            writer.flush(); os.fsync(writer.fileno())

    def _mark_investigating(self, incident_id: str, reason: str) -> None:
        if (details := self.incidents.get_incident(incident_id)) and details.incident.status not in (IncidentStatus.INVESTIGATING, IncidentStatus.RESOLVED):
            self.incidents.change_status(incident_id, IncidentStatus.INVESTIGATING, reason=reason)

    def _finish(self, item, requested_path: str, status: RecoveryStatus, *, started: str, detection: DetectionResult | None, restored_path: str | None, error: str | None, event_type: IncidentEventType, warning: str | None = None, conflict_options: tuple[RecoveryConflictOption, ...] = ()) -> RecoveryResult:
        finished, attempt_id = _utc_now(), str(uuid4())
        with self.database.connection() as conn:
            conn.execute("BEGIN IMMEDIATE")
            conn.execute("INSERT INTO quarantine_recovery_attempts (id, quarantine_id, incident_id, attempted_at, finished_at, requested_path, status, detection_status, detection_reason, restored_path, error) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)", (attempt_id, item.quarantine_id, item.incident_id, started, finished, requested_path, status.value, detection.status.value if detection else None, detection.reason if detection else None, restored_path, error))
            row = conn.execute("SELECT * FROM quarantine_recovery_attempts WHERE id = ?", (attempt_id,)).fetchone()
        message = warning or error or (f"Quarantine {item.quarantine_id} restored to {restored_path}." if restored_path else f"Recovery attempt for quarantine {item.quarantine_id} ended with {status.value}.")
        self.incidents.append_event(item.incident_id, event_type, path=requested_path, source=ScanSource.RECOVERY, detection_reason=message)
        return RecoveryResult(status=status, quarantine_id=item.quarantine_id, incident_id=item.incident_id, requested_path=requested_path, restored_path=restored_path, detection=detection, warning=warning, error=error, conflict_options=conflict_options, attempt=_attempt(row))

def _attempt(row: sqlite3.Row) -> RecoveryAttempt:
    return RecoveryAttempt(id=row["id"], quarantine_id=row["quarantine_id"], incident_id=row["incident_id"], attempted_at=datetime.fromisoformat(row["attempted_at"]), finished_at=datetime.fromisoformat(row["finished_at"]), requested_path=row["requested_path"], status=RecoveryStatus(row["status"]), detection_status=DetectionStatus(row["detection_status"]) if row["detection_status"] else None, detection_reason=row["detection_reason"], restored_path=row["restored_path"], error=row["error"])

def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="microseconds")