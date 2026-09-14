from __future__ import annotations
import json, os, sqlite3, stat
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Iterable, Iterator
from uuid import uuid4

from app.database import Database
from app.hashing import hash_file, is_link_or_reparse, normalize_path
from app.incidents import IncidentEventType, IncidentService, IncidentStatus
from app.matching_cleanup import default_monitored_locations
from app.models import ScanSource
from app.quarantine import QuarantineService, QuarantineState

class VerificationStatus(str, Enum): VERIFIED = "VERIFIED"; PARTIAL = "PARTIAL"; FAILED = "FAILED"

@dataclass(frozen=True)
class VerificationIssue: path: str; reason: str

@dataclass(frozen=True)
class CleanupVerificationResult:
    verification_id: str; incident_id: str; sha256: str; status: VerificationStatus
    started_at: datetime; finished_at: datetime; locations_searched: tuple[str, ...]
    quarantined_copies: int; verified_quarantine_objects: int; remaining_matching_copies: int
    inaccessible_locations: int; verification_errors: int; remaining_paths: tuple[str, ...]
    inaccessible: tuple[VerificationIssue, ...]; errors: tuple[VerificationIssue, ...]

class CleanupVerifier:
    def __init__(self, database: Database, incidents: IncidentService, quarantine: QuarantineService, monitored_locations: Iterable[str | Path] | None = None) -> None:
        self.database, self.incidents, self.quarantine = database, incidents, quarantine
        self._configured_locations = tuple(normalize_path(p) for p in monitored_locations) if monitored_locations is not None else None
        self._quarantine_dir = normalize_path(quarantine.quarantine_dir)
        self._database_files = {normalize_path(str(database.path) + s) for s in ("", "-wal", "-shm", "-journal")}

    def verify_incident(self, incident_id: str) -> CleanupVerificationResult:
        if (details := self.incidents.get_incident(incident_id)) is None: raise KeyError(f"Unknown threat incident: {incident_id}")
        if details.incident.status is IncidentStatus.RESOLVED: raise ValueError("Cannot verify cleanup for a RESOLVED incident.")
        expected_sha256, verification_id, started, roots = details.incident.sha256, str(uuid4()), datetime.now(timezone.utc), self._search_locations()
        locations_searched = tuple(str(p) for p in roots)
        self.incidents.append_event(incident_id, IncidentEventType.CLEANUP_VERIFICATION_STARTED, path=details.incident.first_observed_path, source=ScanSource.RECOVERY, detection_reason=f"Cleanup verification {verification_id} started for SHA-256 {expected_sha256}.")
        errors, inaccessible, remaining, checked_paths = [], [], set(), set()
        quarantine_items = [i for i in self.quarantine.list_quarantined_items() if i.incident_id == incident_id and i.sha256 == expected_sha256 and i.state is QuarantineState.QUARANTINED]
        quarantined_copies, verified_quarantine_objects, quarantine_integrity_failed = len(quarantine_items), 0, False

        for item in quarantine_items:
            try: integrity = self.quarantine.verify_integrity(item.quarantine_id)
            except Exception as e: quarantine_integrity_failed = True; errors.append(VerificationIssue(item.stored_path, f"Could not verify quarantine object {item.quarantine_id}: {type(e).__name__}: {e}")); continue
            if integrity.verified and integrity.actual_sha256 == expected_sha256: verified_quarantine_objects += 1
            else: quarantine_integrity_failed = True; errors.append(VerificationIssue(item.stored_path, integrity.error or f"Quarantine object {item.quarantine_id} failed hash verification."))

        known_paths = [Path(i.path) for i in details.files] + [Path(i.original_path) for i in quarantine_items]
        for p in known_paths: self._check_candidate(p, expected_sha256, checked_paths, remaining, inaccessible, errors)
        for r in roots:
            for p in self._walk_files(r, inaccessible, errors): self._check_candidate(p, expected_sha256, checked_paths, remaining, inaccessible, errors)

        status = VerificationStatus.FAILED if (quarantined_copies == 0 or quarantine_integrity_failed) else (VerificationStatus.PARTIAL if (remaining or inaccessible or errors) else VerificationStatus.VERIFIED)
        result = CleanupVerificationResult(verification_id, incident_id, expected_sha256, status, started, datetime.now(timezone.utc), locations_searched, quarantined_copies, verified_quarantine_objects, len(remaining), len(inaccessible), len(errors), tuple(sorted(remaining)), tuple(inaccessible), tuple(errors))
        self._persist_result(result); self._record_result_event(result, details.incident.first_observed_path); self._apply_incident_status(result)
        return result

    def get_verification(self, verification_id: str) -> CleanupVerificationResult | None:
        with self.database.connection() as conn: row = conn.execute("SELECT * FROM cleanup_verifications WHERE id = ?", (verification_id,)).fetchone()
        return _result(row) if row is not None else None

    def list_verifications(self, incident_id: str) -> list[CleanupVerificationResult]:
        with self.database.connection() as conn: rows = conn.execute("SELECT * FROM cleanup_verifications WHERE incident_id = ? ORDER BY started_at, rowid", (incident_id,)).fetchall()
        return [_result(r) for r in rows]

    def _check_candidate(self, path: str | Path, expected_sha256: str, checked_paths: set[str], remaining: set[str], inaccessible: list[VerificationIssue], errors: list[VerificationIssue]) -> None:
        normalized, key = normalize_path(path), str(normalize_path(path))
        if key in checked_paths or self._excluded(normalized): return
        checked_paths.add(key)
        try: info = normalized.lstat()
        except FileNotFoundError: return
        except PermissionError as e: inaccessible.append(VerificationIssue(key, f"Permission denied while checking location: {e}")); return
        except OSError as e: inaccessible.append(VerificationIssue(key, f"Could not inspect location: {type(e).__name__}: {e}")); return
        if is_link_or_reparse(info) or not stat.S_ISREG(info.st_mode): return
        try:
            if hash_file(normalized).sha256 == expected_sha256: remaining.add(key)
        except PermissionError as e: inaccessible.append(VerificationIssue(key, f"Permission denied while hashing: {e}"))
        except OSError as e: inaccessible.append(VerificationIssue(key, f"Could not read/hash location: {type(e).__name__}: {e}"))
        except Exception as e: errors.append(VerificationIssue(key, f"Verification hash failed: {type(e).__name__}: {e}"))

    def _walk_files(self, root: Path, inaccessible: list[VerificationIssue], errors: list[VerificationIssue]) -> Iterator[Path]:
        try: info = root.lstat()
        except FileNotFoundError: return
        except PermissionError as e: inaccessible.append(VerificationIssue(str(root), f"Monitored location permission denied: {e}")); return
        except OSError as e: inaccessible.append(VerificationIssue(str(root), f"Monitored location is inaccessible: {type(e).__name__}: {e}")); return
        if is_link_or_reparse(info): errors.append(VerificationIssue(str(root), "Links/reparse-point roots are not verified.")); return
        if stat.S_ISREG(info.st_mode): yield root; return
        if not stat.S_ISDIR(info.st_mode): errors.append(VerificationIssue(str(root), "Monitored location is not a file or directory.")); return
        pending, visited = [root], set()
        while pending:
            current = pending.pop()
            try: current_info = current.lstat()
            except PermissionError as e: inaccessible.append(VerificationIssue(str(current), f"Directory permission denied: {e}")); continue
            except OSError as e: inaccessible.append(VerificationIssue(str(current), f"Could not inspect directory: {type(e).__name__}: {e}")); continue
            identity = (current_info.st_dev, current_info.st_ino)
            if current_info.st_ino and identity in visited: continue
            if current_info.st_ino: visited.add(identity)
            try:
                with os.scandir(current) as entries:
                    for entry in entries:
                        p = normalize_path(entry.path)
                        if self._excluded(p): continue
                        try: entry_info = entry.stat(follow_symlinks=False)
                        except PermissionError as e: inaccessible.append(VerificationIssue(str(p), f"Entry permission denied: {e}")); continue
                        except OSError as e: inaccessible.append(VerificationIssue(str(p), f"Could not inspect entry: {type(e).__name__}: {e}")); continue
                        if is_link_or_reparse(entry_info): continue
                        if stat.S_ISDIR(entry_info.st_mode): pending.append(p)
                        elif stat.S_ISREG(entry_info.st_mode): yield p
            except PermissionError as e: inaccessible.append(VerificationIssue(str(current), f"Directory listing denied: {e}"))
            except OSError as e: inaccessible.append(VerificationIssue(str(current), f"Could not list directory: {type(e).__name__}: {e}"))

    def _search_locations(self) -> tuple[Path, ...]:
        raw = self._configured_locations if self._configured_locations is not None else default_monitored_locations()
        unique, seen = [], set()
        for p in raw:
            if (k := str(norm := normalize_path(p))) not in seen: seen.add(k); unique.append(norm)
        return tuple(unique)

    def _excluded(self, path: Path) -> bool:
        norm = normalize_path(path)
        return norm in self._database_files or norm == self._quarantine_dir or self._quarantine_dir in norm.parents

    def _persist_result(self, result: CleanupVerificationResult) -> None:
        details_json = json.dumps({"locations_searched": list(result.locations_searched), "remaining_paths": list(result.remaining_paths), "inaccessible": [i.__dict__ for i in result.inaccessible], "errors": [i.__dict__ for i in result.errors]}, sort_keys=True)
        with self.database.connection() as conn:
            conn.execute("BEGIN IMMEDIATE")
            conn.execute("""INSERT INTO cleanup_verifications (id, incident_id, sha256, status, started_at, finished_at, locations_searched, quarantined_copies, verified_quarantine_objects, remaining_matching_copies, inaccessible_locations, verification_errors, details_json) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""", (result.verification_id, result.incident_id, result.sha256, result.status.value, result.started_at.isoformat(timespec="microseconds"), result.finished_at.isoformat(timespec="microseconds"), len(result.locations_searched), result.quarantined_copies, result.verified_quarantine_objects, result.remaining_matching_copies, result.inaccessible_locations, result.verification_errors, details_json))

    def _record_result_event(self, result: CleanupVerificationResult, first_observed_path: str) -> None:
        event_type = {VerificationStatus.VERIFIED: IncidentEventType.CLEANUP_VERIFIED, VerificationStatus.PARTIAL: IncidentEventType.CLEANUP_VERIFICATION_PARTIAL, VerificationStatus.FAILED: IncidentEventType.CLEANUP_VERIFICATION_FAILED}[result.status]
        self.incidents.append_event(result.incident_id, event_type, path=first_observed_path, source=ScanSource.RECOVERY, detection_reason=f"Cleanup verification {result.verification_id} finished as {result.status.value}: quarantined={result.quarantined_copies}, verified_quarantine={result.verified_quarantine_objects}, remaining_matches={result.remaining_matching_copies}, inaccessible={result.inaccessible_locations}, errors={result.verification_errors}.")

    def _apply_incident_status(self, result: CleanupVerificationResult) -> None:
        if (details := self.incidents.get_incident(result.incident_id)) is None: return
        if result.status is VerificationStatus.VERIFIED:
            if details.incident.status is not IncidentStatus.CONTAINED:
                self.incidents.change_status(result.incident_id, IncidentStatus.CONTAINED, reason=f"Cleanup verification {result.verification_id} confirmed all quarantine objects and found no remaining exact SHA-256 copies.")
        elif details.incident.status is IncidentStatus.CONTAINED:
            self.incidents.change_status(result.incident_id, IncidentStatus.INVESTIGATING, reason=f"Cleanup verification {result.verification_id} was {result.status.value}; containment cannot be fully verified.")

def _result(row: sqlite3.Row) -> CleanupVerificationResult:
    d = json.loads(row["details_json"])
    return CleanupVerificationResult(verification_id=row["id"], incident_id=row["incident_id"], sha256=row["sha256"], status=VerificationStatus(row["status"]), started_at=datetime.fromisoformat(row["started_at"]), finished_at=datetime.fromisoformat(row["finished_at"]), locations_searched=tuple(d.get("locations_searched", ())), quarantined_copies=row["quarantined_copies"], verified_quarantine_objects=row["verified_quarantine_objects"], remaining_matching_copies=row["remaining_matching_copies"], inaccessible_locations=row["inaccessible_locations"], verification_errors=row["verification_errors"], remaining_paths=tuple(d.get("remaining_paths", ())), inaccessible=tuple(VerificationIssue(i["path"], i["reason"]) for i in d.get("inaccessible", ())), errors=tuple(VerificationIssue(i["path"], i["reason"]) for i in d.get("errors", ())))