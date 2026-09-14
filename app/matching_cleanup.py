from __future__ import annotations

import os
import stat
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Iterator

from app.database import Database
from app.hashing import hash_file, is_link_or_reparse, normalize_path
from app.incidents import IncidentEventType, IncidentService, IncidentStatus
from app.models import ScanSource
from app.quarantine import QuarantineService, QuarantineState
from app.threat_trail import ThreatTrail


@dataclass(frozen=True)
class CleanupIssue:
    path: str
    reason: str


@dataclass(frozen=True)
class MatchingCleanupResult:
    incident_id: str
    sha256: str
    locations_searched: tuple[str, ...]
    candidates_examined: int
    exact_matches_found: int
    matches_quarantined: int
    already_contained_matches: int
    failures: tuple[CleanupIssue, ...]
    inaccessible_files: tuple[CleanupIssue, ...]


class MatchingCopyCleanup:
    """Find and quarantine only current files whose SHA-256 exactly matches an incident."""

    def __init__(
        self,
        database: Database,
        incidents: IncidentService,
        quarantine: QuarantineService,
        threat_trail: ThreatTrail,
        monitored_locations: Iterable[str | Path] | None = None,
    ) -> None:
        self.database = database
        self.incidents = incidents
        self.quarantine = quarantine
        self.threat_trail = threat_trail
        self._configured_locations = tuple(normalize_path(path) for path in monitored_locations) if monitored_locations is not None else None
        self._database_files = {normalize_path(str(database.path) + suffix) for suffix in ("", "-wal", "-shm", "-journal")}
        self._quarantine_dir = normalize_path(quarantine.quarantine_dir)

    def cleanup_incident(self, incident_id: str) -> MatchingCleanupResult:
        """Search monitored scope, verify exact hashes, and quarantine exact matches."""
        details = self.incidents.get_incident(incident_id)
        if details is None: raise KeyError(f"Unknown threat incident: {incident_id}")
        if details.incident.status is IncidentStatus.RESOLVED: raise ValueError("Cannot clean matching copies for a RESOLVED incident.")

        expected_sha256 = details.incident.sha256
        roots = self._search_locations()
        locations_searched = tuple(str(path) for path in roots)
        failures, inaccessible = [], []

        self.incidents.append_event(
            incident_id,
            IncidentEventType.MATCHING_CLEANUP_STARTED,
            path=details.incident.first_observed_path,
            source=ScanSource.MATCHING_COPY,
            detection_reason=f"Matching-copy cleanup started for SHA-256 {expected_sha256}; {len(roots)} monitored location(s) will be searched.",
        )

        contained_paths = self._currently_contained_paths(incident_id, expected_sha256)
        already_contained = sum(1 for path in contained_paths if self._within_any_root(path, roots))
        for path in contained_paths:
            if self._within_any_root(path, roots):
                self.incidents.append_event(
                    incident_id,
                    IncidentEventType.MATCHING_COPY_ALREADY_CONTAINED,
                    path=path,
                    source=ScanSource.MATCHING_COPY,
                    detection_reason="A verified quarantine record already contains this matching location.",
                )

        candidates, queued = [], set()
        for known in [Path(item.path) for item in details.files] + [Path(item.path) for item in self.threat_trail.get_observations(expected_sha256)]:
            normalized = normalize_path(known)
            if not self._within_any_root(normalized, roots): continue
            key = str(normalized)
            if key in queued or key in contained_paths: continue
            if normalized.exists(): queued.add(key); candidates.append(normalized)

        for root in roots:
            for path in self._walk_files(root, inaccessible, failures):
                key = str(path)
                if key in queued or key in contained_paths: continue
                queued.add(key); candidates.append(path)

        candidates_examined, exact_matches_found, matches_quarantined = 0, 0, 0

        for path in candidates:
            if self._excluded(path): continue
            candidates_examined += 1
            try:
                fingerprint = hash_file(path)
            except PermissionError as error:
                issue = CleanupIssue(str(path), f"Permission denied while hashing: {error}")
                inaccessible.append(issue); self._record_failure_event(incident_id, issue); continue
            except OSError as error:
                issue = CleanupIssue(str(path), f"Could not read/hash candidate: {type(error).__name__}: {error}")
                inaccessible.append(issue); self._record_failure_event(incident_id, issue); continue
            except Exception as error:
                issue = CleanupIssue(str(path), f"Candidate verification failed: {type(error).__name__}: {error}")
                failures.append(issue); self._record_failure_event(incident_id, issue); continue

            if fingerprint.sha256 != expected_sha256: continue

            exact_matches_found += 1
            reason = "Exact SHA-256 match confirmed during Matching-Copy Cleanup. The current file was rehashed before quarantine."
            self.incidents.attach_matching_file(incident_id, path, ScanSource.MATCHING_COPY, reason)
            self.incidents.append_event(incident_id, IncidentEventType.MATCHING_COPY_FOUND, path=path, source=ScanSource.MATCHING_COPY, detection_reason=reason)

            try:
                item = self.quarantine.quarantine_file(
                    incident_id=incident_id,
                    path=path,
                    expected_sha256=expected_sha256,
                    reason=reason,
                    source=ScanSource.MATCHING_COPY,
                    expected_size=fingerprint.size_bytes,
                )
            except Exception as error:
                issue = CleanupIssue(str(path), f"Quarantine call failed: {type(error).__name__}: {error}")
                failures.append(issue); self._record_failure_event(incident_id, issue); continue

            if item.state is QuarantineState.QUARANTINED and item.original_removed:
                matches_quarantined += 1
                self.incidents.append_event(
                    incident_id,
                    IncidentEventType.MATCHING_COPY_QUARANTINED,
                    path=path,
                    source=ScanSource.MATCHING_COPY,
                    detection_reason=f"Exact matching copy quarantined as {item.quarantine_id}.",
                )
            else:
                issue = CleanupIssue(str(path), item.failure_reason or "Exact match could not be quarantined.")
                failures.append(issue); self._record_failure_event(incident_id, issue)

        result = MatchingCleanupResult(
            incident_id=incident_id,
            sha256=expected_sha256,
            locations_searched=locations_searched,
            candidates_examined=candidates_examined,
            exact_matches_found=exact_matches_found,
            matches_quarantined=matches_quarantined,
            already_contained_matches=already_contained,
            failures=tuple(failures),
            inaccessible_files=tuple(inaccessible),
        )
        self.incidents.append_event(
            incident_id,
            IncidentEventType.MATCHING_CLEANUP_FINISHED,
            path=details.incident.first_observed_path,
            source=ScanSource.MATCHING_COPY,
            detection_reason=(
                f"Matching-copy cleanup finished: examined={result.candidates_examined}, exact_matches={result.exact_matches_found}, "
                f"quarantined={result.matches_quarantined}, already_contained={result.already_contained_matches}, "
                f"failures={len(result.failures)}, inaccessible={len(result.inaccessible_files)}."
            ),
        )
        return result

    def _search_locations(self) -> tuple[Path, ...]:
        raw = self._configured_locations if self._configured_locations is not None else default_monitored_locations()
        unique, seen = [], set()
        for path in raw:
            normalized = normalize_path(path); key = str(normalized)
            if key not in seen: seen.add(key); unique.append(normalized)
        return tuple(unique)

    def _currently_contained_paths(self, incident_id: str, sha256: str) -> set[str]:
        return {
            str(normalize_path(item.original_path))
            for item in self.quarantine.list_quarantined_items()
            if item.incident_id == incident_id and item.sha256 == sha256 and item.state is QuarantineState.QUARANTINED and item.original_removed and not Path(item.original_path).exists()
        }

    def _walk_files(self, root: Path, inaccessible: list[CleanupIssue], failures: list[CleanupIssue]) -> Iterator[Path]:
        try:
            info = root.lstat()
        except OSError as error:
            inaccessible.append(CleanupIssue(str(root), f"Monitored location is inaccessible: {type(error).__name__}: {error}")); return

        if is_link_or_reparse(info): failures.append(CleanupIssue(str(root), "Links/reparse-point roots are not searched.")); return
        if stat.S_ISREG(info.st_mode): yield root; return
        if not stat.S_ISDIR(info.st_mode): failures.append(CleanupIssue(str(root), "Monitored location is not a regular file or directory.")); return

        pending, visited = [root], set()
        while pending:
            current = pending.pop()
            try:
                current_info = current.lstat()
            except OSError as error:
                inaccessible.append(CleanupIssue(str(current), f"Could not inspect directory: {type(error).__name__}: {error}")); continue
            identity = (current_info.st_dev, current_info.st_ino)
            if current_info.st_ino and identity in visited: continue
            if current_info.st_ino: visited.add(identity)
            try:
                with os.scandir(current) as entries:
                    for entry in entries:
                        path = normalize_path(entry.path)
                        if self._excluded(path): continue
                        try:
                            entry_info = entry.stat(follow_symlinks=False)
                        except OSError as error:
                            inaccessible.append(CleanupIssue(str(path), f"Could not inspect candidate: {type(error).__name__}: {error}")); continue
                        if is_link_or_reparse(entry_info): continue
                        if stat.S_ISDIR(entry_info.st_mode): pending.append(path)
                        elif stat.S_ISREG(entry_info.st_mode): yield path
            except OSError as error:
                inaccessible.append(CleanupIssue(str(current), f"Could not list directory: {type(error).__name__}: {error}"))

    def _excluded(self, path: Path) -> bool:
        normalized = normalize_path(path)
        return normalized in self._database_files or normalized == self._quarantine_dir or self._quarantine_dir in normalized.parents

    @staticmethod
    def _within_any_root(path: str | Path, roots: tuple[Path, ...]) -> bool:
        normalized = normalize_path(path)
        return any(normalized == root or root in normalized.parents for root in roots)

    def _record_failure_event(self, incident_id: str, issue: CleanupIssue) -> None:
        self.incidents.append_event(incident_id, IncidentEventType.MATCHING_CLEANUP_FAILED, path=issue.path, source=ScanSource.MATCHING_COPY, detection_reason=issue.reason)


def default_monitored_locations() -> tuple[Path, ...]:
    """Return default user folders plus removable locations known right now."""
    home = Path.home()
    locations = [home / "Downloads", home / "Desktop", home / "Documents"] + list(known_removable_locations())
    return tuple(normalize_path(path) for path in locations)


def known_removable_locations() -> tuple[Path, ...]:
    """Best-effort removable-drive discovery using only the Python standard library."""
    if os.name == "nt":
        try:
            import ctypes
            kernel32 = ctypes.windll.kernel32; mask = kernel32.GetLogicalDrives(); removable = []
            for index in range(26):
                if not (mask & (1 << index)): continue
                root = f"{chr(ord('A') + index)}:\\"
                if kernel32.GetDriveTypeW(root) == 2: removable.append(Path(root))
            return tuple(normalize_path(path) for path in removable)
        except Exception:
            return ()

    user = os.environ.get("USER") or os.environ.get("USERNAME")
    bases = [Path("/media")] + ([Path("/media") / user, Path("/run/media") / user] if user else [])
    result, seen = [], set()
    for base in bases:
        try:
            children = list(base.iterdir())
        except OSError:
            continue
        for child in children:
            try:
                if not child.is_dir(): continue
            except OSError:
                continue
            normalized = normalize_path(child); key = str(normalized)
            if key not in seen: seen.add(key); result.append(normalized)
    return tuple(result)