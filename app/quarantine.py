from __future__ import annotations
import os, shutil, sqlite3, stat
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from uuid import UUID, uuid4
from app.database import Database
from app.hashing import normalize_path
from app.incidents import IncidentEventType, IncidentService, IncidentStatus
from app.models import DetectionResult, DetectionStatus, ScanSource
from app.quarantine_integrity import IntegrityResult, verify_quarantine_file

class QuarantineState(str, Enum): PENDING = "PENDING"; QUARANTINED = "QUARANTINED"; FAILED = "FAILED"
class QuarantineIntegrityStatus(str, Enum): PENDING = "PENDING"; VERIFIED = "VERIFIED"; FAILED = "FAILED"


class QuarantineDeletionNeedsReview(OSError):
    """Storage disposal was requested but its final outcome is uncertain."""

@dataclass(frozen=True)
class QuarantineItem:
    quarantine_id: str; incident_id: str; original_path: str; stored_path: str; sha256: str
    original_size: int | None; created_at: datetime; quarantined_at: datetime | None; reason: str
    original_source: ScanSource; state: QuarantineState; integrity_status: QuarantineIntegrityStatus
    verified_sha256: str | None; verified_size: int | None; verified_at: datetime | None
    original_removed: bool; failure_reason: str | None
    deleted_at: datetime | None = None

class QuarantineService:
    """Move verified threat content into non-executable internal storage."""
    def __init__(self, database: Database, quarantine_dir: str | Path, incidents: IncidentService | None = None) -> None:
        self.database = database; self.quarantine_dir = normalize_path(quarantine_dir)
        self.quarantine_dir.mkdir(parents=True, exist_ok=True)
        self.incidents = incidents if incidents is not None else IncidentService(database)

    def quarantine_detection(self, detection: DetectionResult, incident_id: str, source: ScanSource, *, original_size: int | None = None) -> QuarantineItem:
        if detection.status is not DetectionStatus.HIGH_CONFIDENCE: raise ValueError("Automatic quarantine requires a HIGH_CONFIDENCE detection.")
        if detection.matched_signature is None: raise ValueError("Automatic quarantine requires known-signature evidence.")
        return self.quarantine_file(incident_id=incident_id, path=detection.path, expected_sha256=detection.sha256, reason=detection.reason, source=source, expected_size=original_size)

    def quarantine_file(self, incident_id: str, path: str | Path, expected_sha256: str, reason: str, source: ScanSource, *, expected_size: int | None = None) -> QuarantineItem:
        original_path = normalize_path(path); original_path_text = str(original_path); expected_sha256 = _sha256(expected_sha256); source = ScanSource(source)
        if not reason: raise ValueError("reason must not be empty.")
        if expected_size is not None and (type(expected_size) is not int or expected_size < 0): raise ValueError("expected_size must be a nonnegative integer or None.")
        existing = self._existing_success(incident_id, original_path_text, expected_sha256)
        if existing is not None: return existing
        self._validate_incident(incident_id, expected_sha256)
        if expected_size is None:
            try: expected_size = original_path.stat().st_size
            except OSError: expected_size = None
        quarantine_id = str(uuid4()); stored_path = normalize_path(self.quarantine_dir / f"{quarantine_id}.agq"); temp_path = normalize_path(self.quarantine_dir / f".{quarantine_id}.part"); now = _utc_now()
        self._insert_pending(quarantine_id, incident_id, original_path_text, str(stored_path), expected_sha256, expected_size, now, reason, source)
        self.incidents.append_event(incident_id, IncidentEventType.QUARANTINE_STARTED, path=original_path, source=source, detection_reason=f"Quarantine {quarantine_id} started: {reason}")
        if not original_path.exists(): return self._fail(quarantine_id, incident_id, original_path, source, "Source file no longer exists; quarantine was not performed.")
        copied_integrity: IntegrityResult | None = None; final_integrity: IntegrityResult | None = None
        try:
            shutil.copyfile(original_path, temp_path); _restrict_permissions(temp_path)
            copied_integrity = verify_quarantine_file(temp_path, expected_sha256, expected_size)
            if not copied_integrity.verified:
                _safe_unlink(temp_path)
                return self._fail(quarantine_id, incident_id, original_path, source, copied_integrity.error or "Copied quarantine content failed verification.", integrity=copied_integrity)
            os.replace(temp_path, stored_path); _restrict_permissions(stored_path)
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
            quarantined_at = _utc_now(); self._mark_success(quarantine_id, final_integrity, quarantined_at)
            self.incidents.append_event(incident_id, IncidentEventType.QUARANTINE_SUCCEEDED, path=original_path, source=source, detection_reason=f"Quarantine {quarantine_id} verified and original location removed.")
            return self.get_item(quarantine_id)  # type: ignore[return-value]
        except Exception as error:
            _safe_unlink(temp_path)
            return self._fail(quarantine_id, incident_id, original_path, source, f"Quarantine operation failed: {type(error).__name__}: {error}", integrity=final_integrity or copied_integrity)

    def list_quarantined_items(self) -> list[QuarantineItem]:
        with self.database.connection() as connection: rows = connection.execute("SELECT * FROM quarantine_items ORDER BY created_at DESC, rowid DESC").fetchall()
        return [_item(row) for row in rows]

    def get_item(self, quarantine_id: str) -> QuarantineItem | None:
        with self.database.connection() as connection: row = connection.execute("SELECT * FROM quarantine_items WHERE quarantine_id = ?", (quarantine_id,)).fetchone()
        return _item(row) if row is not None else None

    def get_metadata(self, quarantine_id: str) -> QuarantineItem | None: return self.get_item(quarantine_id)

    def verify_integrity(self, quarantine_id: str) -> IntegrityResult:
        item = self.get_item(quarantine_id)
        if item is None: raise KeyError(f"Unknown quarantine item: {quarantine_id}")
        result = verify_quarantine_file(item.stored_path, item.sha256, item.original_size)
        with self.database.connection() as connection:
            connection.execute("BEGIN IMMEDIATE")
            connection.execute("""UPDATE quarantine_items SET integrity_status = ?, verified_sha256 = ?, verified_size = ?, verified_at = ?, state = CASE WHEN ? THEN state ELSE 'FAILED' END, failure_reason = CASE WHEN ? THEN failure_reason ELSE ? END WHERE quarantine_id = ?""", (QuarantineIntegrityStatus.VERIFIED.value if result.verified else QuarantineIntegrityStatus.FAILED.value, result.actual_sha256, result.actual_size, result.checked_at.isoformat(timespec="microseconds"), 1 if result.verified else 0, 1 if result.verified else 0, result.error or "Quarantine integrity verification failed.", quarantine_id))
        if not result.verified:
            self.incidents.append_event(item.incident_id, IncidentEventType.QUARANTINE_INTEGRITY_FAILED, path=item.original_path, source=item.original_source, detection_reason=f"Quarantine {quarantine_id} integrity check failed: {result.error or 'unknown integrity error'}")
            details = self.incidents.get_incident(item.incident_id)
            if details is not None and details.incident.status not in (IncidentStatus.INVESTIGATING, IncidentStatus.RESOLVED):
                self.incidents.change_status(item.incident_id, IncidentStatus.INVESTIGATING, reason=f"Quarantine {quarantine_id} failed a later integrity check.")
        return result

    def original_location_exists(self, quarantine_id: str) -> bool:
        item = self.get_item(quarantine_id)
        if item is None: raise KeyError(f"Unknown quarantine item: {quarantine_id}")
        return Path(item.original_path).exists()

    def delete_quarantine_object(self, quarantine_id: str) -> bool:
        """Compatibility entry point; all deletion uses the same guarded service."""
        result = self.delete_quarantine_objects((quarantine_id,))[0]
        if not result["deleted"]:
            raise OSError(result["message"])
        return True

    def delete_quarantine_objects(self, quarantine_ids, *, batch_id: str | None = None) -> list[dict]:
        """Independently commit each selected outcome; never delete evidence rows.

        A durable RUNNING attempt claims each object before touching storage.
        Crashed/incomplete claims block retries rather than guessing an outcome.
        """
        if isinstance(quarantine_ids, (str, bytes)):
            raise ValueError("Provide a collection of quarantine IDs.")
        ids, seen = [], set()
        for value in quarantine_ids:
            if isinstance(value, str):
                if value in seen:
                    continue
                seen.add(value)
            ids.append(value)
        if not ids:
            return []
        batch_id = batch_id or str(uuid4())
        return [self._delete_selected_object(value, batch_id) for value in ids]

    def _delete_selected_object(self, requested_id, batch_id):
        attempt_id = str(uuid4())
        requested_text = str(requested_id)
        item = None
        claimed = False
        storage_deleted = False
        outcome = {"item_ref": requested_text, "name": requested_text, "deleted": False,
                   "status": "FAILED", "message": "Deletion did not complete."}
        try:
            if not isinstance(requested_id, str) or str(UUID(requested_id)) != requested_id:
                raise ValueError("Invalid quarantine ID.")
            with self.database.connection() as connection:
                connection.execute("BEGIN IMMEDIATE")
                row = connection.execute("SELECT * FROM quarantine_items WHERE quarantine_id = ?", (requested_id,)).fetchone()
                if row is None:
                    raise ValueError("The selected quarantine item does not exist.")
                item = _item(row)
                outcome["name"] = Path(item.original_path).name
                if item.deleted_at or str(item.failure_reason or "").startswith("Quarantine object permanently deleted"):
                    outcome["status"] = "ALREADY_DELETED"
                    raise ValueError("This quarantine object was already permanently deleted.")
                if item.state is QuarantineState.PENDING:
                    raise ValueError("Quarantine is still in progress; this file cannot be deleted yet.")
                if item.state is not QuarantineState.QUARANTINED:
                    raise ValueError("This item is not in a completed quarantined state.")
                running = connection.execute("SELECT 1 FROM quarantine_deletion_attempts WHERE quarantine_id=? AND status='RUNNING'", (requested_id,)).fetchone()
                if running:
                    raise ValueError("A deletion is already running or requires reconciliation for this item.")
                connection.execute(
                    """INSERT INTO quarantine_deletion_attempts
                       (id, batch_id, requested_id, quarantine_id, incident_id, attempted_at, status, message)
                       VALUES (?, ?, ?, ?, ?, ?, 'RUNNING', 'Deletion requested by user.')""",
                    (attempt_id, batch_id, requested_id, requested_id, item.incident_id, _utc_now()),
                )
            claimed = True
            with self.database.connection() as connection:
                connection.execute("BEGIN IMMEDIATE")
                current = connection.execute("SELECT * FROM quarantine_items WHERE quarantine_id=?", (requested_id,)).fetchone()
                if current is None or current["state"] != "QUARANTINED" or current["deleted_at"]:
                    raise ValueError("The quarantine state changed; no file was deleted.")
                item = _item(current)
                target = self._deletion_target(item)
                _unlink_quarantine_object(target)
                storage_deleted = True
                now = _utc_now()
                # FAILED is the existing non-restorable terminal state. Keep
                # the original hash, last verification, incident and recovery
                # evidence; intentional disposal is not an integrity failure.
                connection.execute(
                    """UPDATE quarantine_items SET state='FAILED', deleted_at=?, failure_reason=?
                       WHERE quarantine_id=?""",
                    (now, "Quarantine object permanently deleted by user.", requested_id),
                )
                connection.execute("UPDATE quarantine_deletion_attempts SET status='DELETED', finished_at=?, message=? WHERE id=?",
                                   (now, "Quarantine object permanently deleted. Security history retained.", attempt_id))
            outcome.update(deleted=True, status="DELETED", message="Permanently deleted from quarantine storage.")
        except Exception as error:
            if isinstance(error, FileNotFoundError):
                outcome["status"] = "MISSING"
            elif isinstance(error, (ValueError, KeyError)) and outcome["status"] != "ALREADY_DELETED":
                outcome["status"] = "REJECTED"
            outcome["message"] = f"{type(error).__name__}: {error}"
            needs_review = storage_deleted or isinstance(error, QuarantineDeletionNeedsReview)
            if needs_review:
                outcome["status"] = "RECONCILIATION_REQUIRED"
                outcome["message"] = "Storage disposal occurred or is uncertain, but finalization failed. The item is blocked from repeated deletion pending reconciliation. " + outcome["message"]
            try:
                with self.database.connection() as connection:
                    if claimed and needs_review:
                        # Retain the durable exclusive claim when a crash or
                        # database failure makes the two-resource outcome unclear.
                        connection.execute("UPDATE quarantine_deletion_attempts SET message=? WHERE id=?", (outcome["message"], attempt_id))
                    elif claimed:
                        connection.execute("UPDATE quarantine_deletion_attempts SET status=?, finished_at=?, message=? WHERE id=?",
                                           (outcome["status"], _utc_now(), outcome["message"], attempt_id))
                    else:
                        connection.execute(
                            """INSERT INTO quarantine_deletion_attempts
                               (id, batch_id, requested_id, quarantine_id, incident_id, attempted_at, finished_at, status, message)
                               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                            (attempt_id, batch_id, requested_text, item.quarantine_id if item else None,
                             item.incident_id if item else None, _utc_now(), _utc_now(), outcome["status"], outcome["message"]),
                        )
            except Exception as audit_error:
                outcome["message"] += f" Audit update could not be saved: {audit_error}"
        return outcome

    def _deletion_target(self, item: QuarantineItem) -> Path:
        root = self.quarantine_dir
        if root.resolve() != root or root.is_symlink():
            raise ValueError("Quarantine storage was redirected; deletion was refused.")
        expected = root / f"{item.quarantine_id}.agq"
        if os.path.normcase(os.path.abspath(item.stored_path)) != os.path.normcase(str(expected)):
            raise ValueError("Stored path does not identify this quarantine object.")
        if os.path.normcase(os.path.abspath(item.original_path)) == os.path.normcase(str(expected)):
            raise ValueError("Quarantine object cannot be an original file path.")
        info = expected.lstat()
        if not stat.S_ISREG(info.st_mode) or getattr(info, "st_file_attributes", 0) & 0x400:
            raise ValueError("Quarantine object is not a regular file; links and redirected paths are refused.")
        return expected

    def _existing_success(self, incident_id: str, original_path: str, sha256: str) -> QuarantineItem | None:
        with self.database.connection() as connection: row = connection.execute("""SELECT * FROM quarantine_items WHERE incident_id = ? AND original_path = ? AND sha256 = ? AND state = 'QUARANTINED' ORDER BY quarantined_at DESC, rowid DESC LIMIT 1""", (incident_id, original_path, sha256)).fetchone()
        if row is None or Path(original_path).exists(): return None
        return _item(row)

    def _validate_incident(self, incident_id: str, sha256: str) -> None:
        details = self.incidents.get_incident(incident_id)
        if details is None: raise KeyError(f"Unknown threat incident: {incident_id}")
        if details.incident.status is IncidentStatus.RESOLVED: raise ValueError("Cannot quarantine content for a RESOLVED incident.")
        if details.incident.sha256 != sha256: raise ValueError("Quarantine SHA-256 does not match the incident SHA-256.")

    def _insert_pending(self, quarantine_id: str, incident_id: str, original_path: str, stored_path: str, sha256: str, original_size: int | None, created_at: str, reason: str, source: ScanSource) -> None:
        with self.database.connection() as connection:
            connection.execute("BEGIN IMMEDIATE")
            connection.execute("""INSERT INTO quarantine_items (quarantine_id, incident_id, original_path, stored_path, sha256, original_size, created_at, reason, original_source, state, integrity_status, original_removed) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'PENDING', 'PENDING', 0)""", (quarantine_id, incident_id, original_path, stored_path, sha256, original_size, created_at, reason, source.value))

    def _mark_success(self, quarantine_id: str, integrity: IntegrityResult, quarantined_at: str) -> None:
        with self.database.connection() as connection:
            connection.execute("BEGIN IMMEDIATE")
            connection.execute("""UPDATE quarantine_items SET state = 'QUARANTINED', integrity_status = 'VERIFIED', verified_sha256 = ?, verified_size = ?, verified_at = ?, quarantined_at = ?, original_removed = 1, failure_reason = NULL WHERE quarantine_id = ?""", (integrity.actual_sha256, integrity.actual_size, integrity.checked_at.isoformat(timespec="microseconds"), quarantined_at, quarantine_id))

    def _fail(self, quarantine_id: str, incident_id: str, original_path: Path, source: ScanSource, failure_reason: str, *, integrity: IntegrityResult | None = None) -> QuarantineItem:
        integrity_status = QuarantineIntegrityStatus.VERIFIED if integrity is not None and integrity.verified else QuarantineIntegrityStatus.FAILED
        with self.database.connection() as connection:
            connection.execute("BEGIN IMMEDIATE")
            connection.execute("""UPDATE quarantine_items SET state = 'FAILED', integrity_status = ?, verified_sha256 = ?, verified_size = ?, verified_at = ?, original_removed = 0, failure_reason = ? WHERE quarantine_id = ?""", (integrity_status.value, integrity.actual_sha256 if integrity else None, integrity.actual_size if integrity else None, integrity.checked_at.isoformat(timespec="microseconds") if integrity else _utc_now(), failure_reason, quarantine_id))
        self.incidents.append_event(incident_id, IncidentEventType.QUARANTINE_FAILED, path=original_path, source=source, detection_reason=f"Quarantine {quarantine_id} failed: {failure_reason}")
        item = self.get_item(quarantine_id)
        if item is None: raise RuntimeError("Quarantine failure state was not persisted.")
        return item

    def _known_incident_location_still_exists(self, incident_id: str) -> bool:
        details = self.incidents.get_incident(incident_id)
        if details is None: return False
        return any(Path(item.path).exists() for item in details.files)

def _item(row: sqlite3.Row) -> QuarantineItem:
    return QuarantineItem(quarantine_id=row["quarantine_id"], incident_id=row["incident_id"], original_path=row["original_path"], stored_path=row["stored_path"], sha256=row["sha256"], original_size=row["original_size"], created_at=datetime.fromisoformat(row["created_at"]), quarantined_at=datetime.fromisoformat(row["quarantined_at"]) if row["quarantined_at"] else None, reason=row["reason"], original_source=ScanSource(row["original_source"]), state=QuarantineState(row["state"]), integrity_status=QuarantineIntegrityStatus(row["integrity_status"]), verified_sha256=row["verified_sha256"], verified_size=row["verified_size"], verified_at=datetime.fromisoformat(row["verified_at"]) if row["verified_at"] else None, original_removed=bool(row["original_removed"]), failure_reason=row["failure_reason"], deleted_at=datetime.fromisoformat(row["deleted_at"]) if row["deleted_at"] else None)

def _sha256(value: str) -> str:
    normalized = value.strip().lower()
    if len(normalized) != 64 or any(ch not in "0123456789abcdef" for ch in normalized): raise ValueError("expected_sha256 must be exactly 64 hexadecimal characters.")
    return normalized

def _utc_now() -> str: return datetime.now(timezone.utc).isoformat(timespec="microseconds")


def _unlink_quarantine_object(target: Path) -> None:
    """Delete one verified storage name, never a resolved link target.

    Windows uses a non-shared DELETE handle and validates its final path and
    attributes before disposal. This closes the rename/reparse gap between
    inspecting a path and deleting it. No directories or original paths enter
    this helper. Other platforms unlink relative to an opened directory.
    """
    if os.name != "nt":
        directory = os.open(target.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            info = os.stat(target.name, dir_fd=directory, follow_symlinks=False)
            if not stat.S_ISREG(info.st_mode):
                raise ValueError("Storage object changed into a non-regular file.")
            os.unlink(target.name, dir_fd=directory)
        finally:
            os.close(directory)
        return
    import ctypes
    from ctypes import wintypes
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel.CreateFileW.argtypes = (wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD,
                                   wintypes.LPVOID, wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE)
    kernel.CreateFileW.restype = wintypes.HANDLE
    kernel.GetFinalPathNameByHandleW.argtypes = (wintypes.HANDLE, wintypes.LPWSTR, wintypes.DWORD, wintypes.DWORD)
    kernel.GetFinalPathNameByHandleW.restype = wintypes.DWORD
    kernel.GetFileInformationByHandleEx.argtypes = (wintypes.HANDLE, ctypes.c_int, wintypes.LPVOID, wintypes.DWORD)
    kernel.GetFileInformationByHandleEx.restype = wintypes.BOOL
    kernel.SetFileInformationByHandle.argtypes = (wintypes.HANDLE, ctypes.c_int, wintypes.LPVOID, wintypes.DWORD)
    kernel.SetFileInformationByHandle.restype = wintypes.BOOL
    kernel.CloseHandle.argtypes = (wintypes.HANDLE,)
    kernel.CloseHandle.restype = wintypes.BOOL
    handle = kernel.CreateFileW(str(target), 0x00010000 | 0x80, 0, None, 3, 0x00200000, None)
    if handle == ctypes.c_void_p(-1).value:
        raise ctypes.WinError(ctypes.get_last_error())
    disposal_requested = False
    try:
        class Attributes(ctypes.Structure):
            _fields_ = (("attributes", wintypes.DWORD), ("tag", wintypes.DWORD))
        attributes = Attributes()
        if not kernel.GetFileInformationByHandleEx(handle, 9, ctypes.byref(attributes), ctypes.sizeof(attributes)):
            raise ctypes.WinError(ctypes.get_last_error())
        if attributes.attributes & (0x400 | 0x10):
            raise ValueError("Storage object is a redirected path or directory.")
        buffer = ctypes.create_unicode_buffer(32768)
        length = kernel.GetFinalPathNameByHandleW(handle, buffer, len(buffer), 0)
        if not length or length >= len(buffer):
            raise OSError("Could not validate the final quarantine storage path.")
        final = buffer.value
        if final.startswith("\\\\?\\UNC\\"):
            final = "\\\\" + final[8:]
        elif final.startswith("\\\\?\\"):
            final = final[4:]
        if os.path.normcase(final) != os.path.normcase(str(target)):
            raise ValueError("The storage path changed; no file was deleted.")
        delete = ctypes.c_ubyte(1)  # FILE_DISPOSITION_INFO.DeleteFile (BOOLEAN)
        if not kernel.SetFileInformationByHandle(handle, 4, ctypes.byref(delete), ctypes.sizeof(delete)):
            raise ctypes.WinError(ctypes.get_last_error())
        disposal_requested = True
    finally:
        if not kernel.CloseHandle(handle):
            if disposal_requested:
                raise QuarantineDeletionNeedsReview("Windows accepted disposal but could not confirm closing the object handle.")
            raise ctypes.WinError(ctypes.get_last_error())

def _safe_unlink(path: Path) -> None:
    try: path.unlink(missing_ok=True)
    except OSError: pass

def _restrict_permissions(path: Path) -> None:
    try: path.chmod(0o600)
    except OSError: pass
