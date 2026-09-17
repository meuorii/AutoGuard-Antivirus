from __future__ import annotations
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from uuid import uuid4
from app.database import Database
from app.hashing import normalize_path
from app.models import DetectionStatus, ScanDetails, ScanResult, ScanSession, ScanSessionStatus, ScanSource, ScanStatus, ScanSummary, ScanType, SignatureKind, StoredScanResult

COUNTER_NAMES = tuple(ScanSummary(()).counts)

class ScanHistoryError(RuntimeError):
    def __init__(self, message: str, session_id: str | None = None) -> None:
        self.session_id = session_id; super().__init__(f"Scan {session_id}: {message}" if session_id else message)

def _utc_now() -> str: return datetime.now(timezone.utc).isoformat(timespec="microseconds")

def _session(row: sqlite3.Row) -> ScanSession:
    return ScanSession(id=row["id"], scan_type=ScanType(row["scan_type"]), source_path=row["source_path"], source=ScanSource(row["source"]), started_at=datetime.fromisoformat(row["started_at"]), finished_at=datetime.fromisoformat(row["finished_at"]) if row["finished_at"] else None, status=ScanSessionStatus(row["status"]), counters={name: row[name] for name in COUNTER_NAMES}, error=row["error"])

def _result(row: sqlite3.Row) -> StoredScanResult:
    return StoredScanResult(id=row["id"], session_id=row["session_id"], path=row["path"], sha256=row["sha256"], result_category=ScanStatus(row["result_category"]), entry_kind=row["entry_kind"], detection_status=DetectionStatus(row["detection_status"]) if row["detection_status"] else None, detection_confidence=row["detection_confidence"], rule_name=row["rule_name"], reason=row["reason"], detection_reason=row["detection_reason"], matched_signature_name=row["matched_signature_name"], matched_signature_kind=SignatureKind(row["matched_signature_kind"]) if row["matched_signature_kind"] else None, recorded_at=datetime.fromisoformat(row["recorded_at"]))

def _running(connection: sqlite3.Connection, session_id: str) -> sqlite3.Row:
    if (row := connection.execute("SELECT * FROM scan_sessions WHERE id = ?", (session_id,)).fetchone()) is None: raise KeyError(f"Unknown scan session: {session_id}")
    if row["status"] != ScanSessionStatus.RUNNING.value: raise ValueError(f"Scan session is already finalized: {session_id}")
    return row

class ScanHistory:
    def __init__(self, database: Database) -> None: self.database = database

    def start_session(self, scan_type: ScanType, source_path: str | Path, source: ScanSource | None = None) -> ScanSession:
        st, src, sid, spath = ScanType(scan_type), ScanSource(source) if source is not None else ScanType(scan_type).default_source, str(uuid4()), str(normalize_path(source_path))
        with self.database.connection() as conn:
            conn.execute("INSERT INTO scan_sessions (id, scan_type, source_path, source, started_at) VALUES (?, ?, ?, ?, ?)", (sid, st.value, spath, src.value, _utc_now()))
            return _session(conn.execute("SELECT * FROM scan_sessions WHERE id = ?", (sid,)).fetchone())

    def record_result(self, session_id: str, result: ScanResult) -> StoredScanResult:
        if result.session_id is not None and result.session_id != session_id: raise ValueError("Result belongs to a different scan session.")
        det = result.detection; sig = det.matched_signature if det else None
        hashes = {v for v in (result.sha256, det.sha256 if det else None, result.observation.sha256 if result.observation else None) if v is not None}
        if len(hashes) > 1: raise ValueError("Outcome contains inconsistent SHA-256 values.")
        sha256, delta = next(iter(hashes), None), ScanSummary((result,)).counts
        with self.database.connection() as conn:
            conn.execute("BEGIN IMMEDIATE"); _running(conn, session_id)
            cur = conn.execute("INSERT INTO scan_results (session_id, path, sha256, result_category, entry_kind, detection_status, detection_confidence, rule_name, reason, detection_reason, matched_signature_name, matched_signature_kind, recorded_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)", (session_id, str(normalize_path(result.path)), sha256, result.status.value, result.kind, det.status.value if det else None, det.confidence if det else None, det.rule_name if det else None, result.reason, det.reason if det else None, sig.name if sig else None, sig.kind.value if sig else None, _utc_now()))
            conn.execute(f"UPDATE scan_sessions SET {', '.join(f'{n} = {n} + ?' for n in COUNTER_NAMES)} WHERE id = ?", (*[delta[n] for n in COUNTER_NAMES], session_id))
            return _result(conn.execute("SELECT * FROM scan_results WHERE id = ?", (cur.lastrowid,)).fetchone())

    def finish_session(self, session_id: str, *, error: str | None = None, interrupted: bool = False) -> ScanSession:
        with self.database.connection() as conn:
            conn.execute("BEGIN IMMEDIATE"); row = _running(conn, session_id)
            issue = conn.execute("SELECT path, reason FROM scan_results WHERE session_id = ? AND result_category <> 'SCANNED' ORDER BY id LIMIT 1", (session_id,)).fetchone()
            if interrupted: status, error = ScanSessionStatus.INCOMPLETE, error or "Scan interrupted before completion."
            elif error is not None or (row["errors"] and not row["scanned_files"]): status = ScanSessionStatus.FAILED
            elif issue is not None: status = ScanSessionStatus.INCOMPLETE
            else: status = ScanSessionStatus.COMPLETED
            if error is None and issue is not None: error = f"Skipped entries or errors were recorded. First issue: {issue['path']}: {issue['reason']}"
            conn.execute("UPDATE scan_sessions SET status = ?, finished_at = ?, error = ? WHERE id = ?", (status.value, max(_utc_now(), row["started_at"]), error, session_id))
            return _session(conn.execute("SELECT * FROM scan_sessions WHERE id = ?", (session_id,)).fetchone())

    def mark_interrupted(self, session_id: str, *, reason: str) -> ScanSession:
        if not reason.strip(): raise ValueError("reason must not be empty.")
        with self.database.connection() as conn:
            conn.execute("BEGIN IMMEDIATE")
            if (row := conn.execute("SELECT * FROM scan_sessions WHERE id = ?", (session_id,)).fetchone()) is None: raise KeyError(f"Unknown scan session: {session_id}")
            if row["scan_type"] != ScanType.USB.value: raise ValueError("Only USB scan sessions may be externally marked interrupted.")
            err, fin = (reason if not row["error"] else f"{row['error']}; {reason}"), (row["finished_at"] or max(_utc_now(), row["started_at"]))
            conn.execute("UPDATE scan_sessions SET status = ?, finished_at = ?, error = ? WHERE id = ?", (ScanSessionStatus.INCOMPLETE.value, fin, err, session_id))
            return _session(conn.execute("SELECT * FROM scan_sessions WHERE id = ?", (session_id,)).fetchone())

    def recent_scans(self, limit: int = 20) -> list[ScanSession]:
        if type(limit) is not int or limit <= 0: raise ValueError("limit must be a positive integer.")
        with self.database.connection() as conn: return [_session(r) for r in conn.execute("SELECT * FROM scan_sessions ORDER BY started_at DESC, rowid DESC LIMIT ?", (limit,)).fetchall()]

    def get_scan(self, session_id: str) -> ScanDetails | None:
        with self.database.connection() as conn:
            conn.execute("BEGIN")
            if (row := conn.execute("SELECT * FROM scan_sessions WHERE id = ?", (session_id,)).fetchone()) is None: return None
            return ScanDetails(_session(row), tuple(_result(r) for r in conn.execute("SELECT * FROM scan_results WHERE session_id = ? ORDER BY id", (session_id,)).fetchall()))

    def latest_detection_for_sha256(self, sha256: str) -> StoredScanResult | None:
        norm = sha256.strip().lower()
        if len(norm) != 64 or any(c not in "0123456789abcdef" for c in norm): raise ValueError("sha256 must be exactly 64 hexadecimal characters.")
        with self.database.connection() as conn:
            row = conn.execute("SELECT * FROM scan_results WHERE sha256 = ? AND detection_status IS NOT NULL ORDER BY recorded_at DESC, id DESC LIMIT 1", (norm,)).fetchone()
            return _result(row) if row is not None else None