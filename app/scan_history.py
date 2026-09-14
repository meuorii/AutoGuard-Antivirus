import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from uuid import uuid4

from app.database import Database
from app.hashing import normalize_path
from app.models import (
    DetectionStatus, ScanDetails, ScanResult, ScanSession, ScanSessionStatus,
    ScanSource, ScanStatus, ScanSummary, ScanType, SignatureKind, StoredScanResult,
)

COUNTER_NAMES = tuple(ScanSummary(()).counts)

class ScanHistoryError(RuntimeError):
    """History could not be saved; session_id identifies any committed session."""
    def __init__(self, message: str, session_id: str | None = None) -> None:
        self.session_id = session_id
        super().__init__((f"Scan {session_id}: " if session_id else "") + message)

def _utc_now() -> str: return datetime.now(timezone.utc).isoformat(timespec="microseconds")

def _session(row: sqlite3.Row) -> ScanSession:
    return ScanSession(
        id=row["id"], scan_type=ScanType(row["scan_type"]), source_path=row["source_path"],
        source=ScanSource(row["source"]), started_at=datetime.fromisoformat(row["started_at"]),
        finished_at=datetime.fromisoformat(row["finished_at"]) if row["finished_at"] else None,
        status=ScanSessionStatus(row["status"]), counters={name: row[name] for name in COUNTER_NAMES}, error=row["error"],
    )

def _result(row: sqlite3.Row) -> StoredScanResult:
    return StoredScanResult(
        id=row["id"], session_id=row["session_id"], path=row["path"], sha256=row["sha256"],
        result_category=ScanStatus(row["result_category"]), entry_kind=row["entry_kind"],
        detection_status=DetectionStatus(row["detection_status"]) if row["detection_status"] else None,
        detection_confidence=row["detection_confidence"], rule_name=row["rule_name"],
        reason=row["reason"], detection_reason=row["detection_reason"], matched_signature_name=row["matched_signature_name"],
        matched_signature_kind=SignatureKind(row["matched_signature_kind"]) if row["matched_signature_kind"] else None,
        recorded_at=datetime.fromisoformat(row["recorded_at"]),
    )

def _running(connection: sqlite3.Connection, session_id: str) -> sqlite3.Row:
    row = connection.execute("SELECT * FROM scan_sessions WHERE id = ?", (session_id,)).fetchone()
    if row is None: raise KeyError(f"Unknown scan session: {session_id}")
    if row["status"] != ScanSessionStatus.RUNNING.value: raise ValueError(f"Scan session is already finalized: {session_id}")
    return row

class ScanHistory:
    def __init__(self, database: Database) -> None: self.database = database

    def start_session(self, scan_type: ScanType, source_path: str | Path, source: ScanSource | None = None) -> ScanSession:
        scan_type, session_id = ScanType(scan_type), str(uuid4())
        source, source_path = scan_type.default_source if source is None else ScanSource(source), str(normalize_path(source_path))
        with self.database.connection() as connection:
            connection.execute(
                "INSERT INTO scan_sessions (id, scan_type, source_path, source, started_at) VALUES (?, ?, ?, ?, ?)",
                (session_id, scan_type.value, source_path, source.value, _utc_now()),
            )
            row = connection.execute("SELECT * FROM scan_sessions WHERE id = ?", (session_id,)).fetchone()
        return _session(row)

    def record_result(self, session_id: str, result: ScanResult) -> StoredScanResult:
        if result.session_id is not None and result.session_id != session_id: raise ValueError("Result belongs to a different scan session.")
        detection = result.detection; signature = detection.matched_signature if detection else None
        hashes = {v for v in (result.sha256, detection.sha256 if detection else None, result.observation.sha256 if result.observation else None) if v is not None}
        if len(hashes) > 1: raise ValueError("Outcome contains inconsistent SHA-256 values.")
        sha256, delta = next(iter(hashes), None), ScanSummary((result,)).counts
        with self.database.connection() as connection:
            connection.execute("BEGIN IMMEDIATE"); _running(connection, session_id)
            cursor = connection.execute(
                """INSERT INTO scan_results (
                    session_id, path, sha256, result_category, entry_kind, detection_status,
                    detection_confidence, rule_name, reason, detection_reason,
                    matched_signature_name, matched_signature_kind, recorded_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    session_id, str(normalize_path(result.path)), sha256, result.status.value, result.kind,
                    detection.status.value if detection else None, detection.confidence if detection else None,
                    detection.rule_name if detection else None, result.reason, detection.reason if detection else None,
                    signature.name if signature else None, signature.kind.value if signature else None, _utc_now(),
                ),
            )
            increments = ", ".join(f"{name} = {name} + ?" for name in COUNTER_NAMES)
            connection.execute(f"UPDATE scan_sessions SET {increments} WHERE id = ?", (*[delta[name] for name in COUNTER_NAMES], session_id))
            row = connection.execute("SELECT * FROM scan_results WHERE id = ?", (cursor.lastrowid,)).fetchone()
        return _result(row)

    def finish_session(self, session_id: str, *, error: str | None = None, interrupted: bool = False) -> ScanSession:
        with self.database.connection() as connection:
            connection.execute("BEGIN IMMEDIATE"); row = _running(connection, session_id)
            issue = connection.execute("SELECT path, reason FROM scan_results WHERE session_id = ? AND result_category <> 'SCANNED' ORDER BY id LIMIT 1", (session_id,)).fetchone()
            if interrupted: status, error = ScanSessionStatus.INCOMPLETE, error or "Scan interrupted before completion."
            elif error is not None or (row["errors"] and not row["scanned_files"]): status = ScanSessionStatus.FAILED
            elif issue is not None: status = ScanSessionStatus.INCOMPLETE
            else: status = ScanSessionStatus.COMPLETED
            if error is None and issue is not None: error = f"Skipped entries or errors were recorded. First issue: {issue['path']}: {issue['reason']}"
            connection.execute("UPDATE scan_sessions SET status = ?, finished_at = ?, error = ? WHERE id = ?", (status.value, max(_utc_now(), row["started_at"]), error, session_id))
            row = connection.execute("SELECT * FROM scan_sessions WHERE id = ?", (session_id,)).fetchone()
        return _session(row)

    def recent_scans(self, limit: int = 20) -> list[ScanSession]:
        if type(limit) is not int or limit <= 0: raise ValueError("limit must be a positive integer.")
        with self.database.connection() as connection:
            rows = connection.execute("SELECT * FROM scan_sessions ORDER BY started_at DESC, rowid DESC LIMIT ?", (limit,)).fetchall()
        return [_session(row) for row in rows]

    def get_scan(self, session_id: str) -> ScanDetails | None:
        with self.database.connection() as connection:
            connection.execute("BEGIN")
            row = connection.execute("SELECT * FROM scan_sessions WHERE id = ?", (session_id,)).fetchone()
            if row is None: return None
            results = connection.execute("SELECT * FROM scan_results WHERE session_id = ? ORDER BY id", (session_id,)).fetchall()
        return ScanDetails(_session(row), tuple(_result(r) for r in results))