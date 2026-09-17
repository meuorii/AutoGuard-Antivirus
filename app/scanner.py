"""Synchronous file/directory scanning, independent of presentation and actions."""

import errno
import os
import stat
import threading
from dataclasses import replace
from pathlib import Path
from typing import Callable, Iterator, Literal

from app.config import DEFAULT_MAX_FILE_SIZE_BYTES
from app.cleanup_verifier import CleanupVerificationResult, CleanupVerifier
from app.detection_rules import SCRIPT_EXTENSIONS
from app.detector import SCRIPT_PREVIEW_BYTES, Detector
from app.hashing import (
    FileTooLargeError,
    UnsupportedFileError,
    inspect_file,
    is_link_or_reparse,
    normalize_path,
)
from app.incidents import IncidentService
from app.logging_config import scanner_logger
from app.matching_cleanup import MatchingCleanupResult, MatchingCopyCleanup
from app.quarantine import QuarantineService
from app.reappearance import ReappearanceResult, ReappearanceWatch
from app.models import (
    DetectionStatus, EntryKind, ScanResult, ScanSource, ScanStatus, ScanSummary, ScanType,
)
from app.scan_history import ScanHistory, ScanHistoryError
from app.threat_trail import ThreatTrail

# Keep Phase 3 imports such as `from app.scanner import ScanStatus` working.
ScanMode = Literal["auto", "file", "directory"]
DiscoveryCallback = Callable[[str, EntryKind], None]


class ScanInterruptedError(RuntimeError):
    """A scan stopped because an external condition made its scope unavailable."""

    def __init__(self, message: str, session_id: str | None = None) -> None:
        self.session_id = session_id
        super().__init__(message)


class Scanner:
    def __init__(
        self,
        detector: Detector,
        threat_trail: ThreatTrail,
        *,
        max_file_size_bytes: int = DEFAULT_MAX_FILE_SIZE_BYTES,
        history: ScanHistory | None = None,
        incidents: IncidentService | None = None,
        quarantine: QuarantineService | None = None,
        matching_cleanup: MatchingCopyCleanup | None = None,
        cleanup_verifier: CleanupVerifier | None = None,
        reappearance: ReappearanceWatch | None = None,
    ) -> None:
        if type(max_file_size_bytes) is not int or max_file_size_bytes < 0:
            raise ValueError("max_file_size_bytes must be a nonnegative integer.")
        self.detector = detector
        self.threat_trail = threat_trail
        self.max_file_size_bytes = max_file_size_bytes
        self.history = history if history is not None else ScanHistory(threat_trail.database)
        self.incidents = incidents if incidents is not None else IncidentService(threat_trail.database)
        self.quarantine = quarantine
        self.matching_cleanup = matching_cleanup
        self.cleanup_verifier = cleanup_verifier
        self.reappearance = (
            reappearance
            if reappearance is not None
            else ReappearanceWatch(threat_trail.database, self.incidents)
        )
        self.last_reappearance_results: tuple[ReappearanceResult, ...] = ()
        self.last_matching_cleanup_results: tuple[MatchingCleanupResult, ...] = ()
        self.last_cleanup_verification_results: tuple[CleanupVerificationResult, ...] = ()
        self._current_reappearance_results: list[ReappearanceResult] = []
        self._persistence_local = threading.local()
        self._quarantine_dir = (
            normalize_path(quarantine.quarantine_dir) if quarantine is not None else None
        )
        # Avoid feeding our own changing database back into its observation log.
        self._database_files = {
            normalize_path(str(database.path) + suffix)
            for database in (threat_trail.database, self.history.database)
            for suffix in ("", "-wal", "-shm", "-journal")
        }

    def scan_file(
        self, path: str | Path, source: ScanSource | None = None,
        *, scan_type: ScanType | None = None,
        on_result: Callable[[ScanResult], None] | None = None,
        on_discovered: DiscoveryCallback | None = None,
    ) -> ScanResult:
        return self._run(path, source, scan_type, "file", on_result=on_result, on_discovered=on_discovered).results[0]

    def scan(
        self, path: str | Path, source: ScanSource | None = None,
        *, scan_type: ScanType | None = None,
        interrupt_check: Callable[[], bool] | None = None,
        on_result: Callable[[ScanResult], None] | None = None,
        on_discovered: DiscoveryCallback | None = None,
    ) -> ScanSummary:
        """Dispatch a file or directory, with exactly one persistent session.

        ``on_result`` is invoked synchronously on the scan worker after each
        result has been persisted. Presentation layers must still dispatch the
        scan itself off their UI thread.
        """
        return self._run(path, source, scan_type, "auto", interrupt_check, on_result=on_result, on_discovered=on_discovered)

    def scan_directory(
        self, path: str | Path, source: ScanSource | None = None,
        *, scan_type: ScanType | None = None,
        interrupt_check: Callable[[], bool] | None = None,
        on_result: Callable[[ScanResult], None] | None = None,
        on_discovered: DiscoveryCallback | None = None,
    ) -> ScanSummary:
        return self._run(path, source, scan_type, "directory", interrupt_check, on_result=on_result, on_discovered=on_discovered)

    def _run(
        self, path: str | Path, source: ScanSource | None,
        scan_type: ScanType | None, mode: ScanMode,
        interrupt_check: Callable[[], bool] | None = None,
        *, on_result: Callable[[ScanResult], None] | None = None,
        on_discovered: DiscoveryCallback | None = None,
    ) -> ScanSummary:
        if scan_type is None:
            source = ScanSource.MANUAL if source is None else ScanSource(source)
            scan_type = ScanType.from_source(source)
        else:
            scan_type = ScanType(scan_type)
            source = scan_type.default_source if source is None else ScanSource(source)
        root = normalize_path(path)
        log = scanner_logger(); log.info("Scan starting type=%s source=%s root=%s", scan_type.value, source.value, root)
        self._current_reappearance_results = []
        try:
            session = self.history.start_session(scan_type, root, source)
        except Exception as error:
            raise ScanHistoryError(
                f"Could not start scan history: {type(error).__name__}: {error}"
            ) from error

        results: list[ScanResult] = []
        stage = "processing"
        try:
            # Reuse the two SQLite connections for the scan lifetime. Each
            # observation/result is still committed independently, preserving the
            # durable per-file history while avoiding thousands of connect/close
            # cycles on large scans.
            with self.threat_trail.database.connection() as trail_connection, \
                 self.history.database.connection() as history_connection:
                self._persistence_local.trail_connection = trail_connection
                try:
                    for result in self._iter_scan(
                        root, source, mode, interrupt_check, on_discovered
                    ):
                        result = replace(result, session_id=session.id)
                        stage = f"saving result for {result.path}"
                        self.history.record_result(
                            session.id, result, _connection=history_connection
                        )
                        results.append(result)
                        if on_result is not None:
                            try:
                                on_result(result)
                            except Exception:
                                # UI/progress observers are advisory and must never turn
                                # a successful security scan into a scan failure.
                                pass
                        stage = "processing"
                finally:
                    self._persistence_local.trail_connection = None
            stage = "finalizing history"
            self.history.finish_session(session.id)
        except BaseException as error:
            # Persist progress on ordinary failures and Ctrl+C, then propagate.
            detail = f"{stage}: {type(error).__name__}: {error}"
            try:
                self.history.finish_session(
                    session.id, error=detail,
                    interrupted=isinstance(
                        error, (KeyboardInterrupt, SystemExit, ScanInterruptedError)
                    ),
                )
            except Exception as finish_error:
                if not isinstance(error, Exception):
                    raise error from finish_error
                raise ScanHistoryError(
                    f"{detail}; could not finalize history: {finish_error}", session.id
                ) from finish_error
            if isinstance(error, ScanInterruptedError):
                log.warning("Scan interrupted session=%s root=%s: %s", session.id, root, error); error.session_id = session.id; raise
            if isinstance(error, Exception): log.error("Scan failed session=%s root=%s stage=%s: %s", session.id, root, stage, error)
            if stage != "processing" and isinstance(error, Exception): raise ScanHistoryError(detail, session.id) from error
            raise

        self.last_reappearance_results = tuple(self._current_reappearance_results)

        # Matching-Copy Cleanup is deliberately deferred until the scan session
        # is finalized. This prevents cleanup from deleting files that a directory
        # scan has already queued but has not processed yet.
        cleanup_results: list[MatchingCleanupResult] = []
        verification_results: list[CleanupVerificationResult] = []
        dangerous_hashes = {
            result.detection.sha256
            for result in results
            if result.detection is not None
            and result.detection.status is DetectionStatus.HIGH_CONFIDENCE
        }
        active_by_hash = {
            item.sha256: item.id for item in self.incidents.get_active_incidents()
        }
        incident_ids = [
            active_by_hash[sha256]
            for sha256 in dangerous_hashes
            if sha256 in active_by_hash
        ]

        if self.matching_cleanup is not None:
            for incident_id in incident_ids:
                cleanup_results.append(
                    self.matching_cleanup.cleanup_incident(incident_id)
                )
        self.last_matching_cleanup_results = tuple(cleanup_results)

        # Phase 8 verifies containment only after quarantine and any configured
        # matching-copy cleanup have finished. The verifier, not quarantine, is
        # the authority that may move an incident to CONTAINED.
        if self.cleanup_verifier is not None:
            for incident_id in incident_ids:
                verification_results.append(
                    self.cleanup_verifier.verify_incident(incident_id)
                )
        self.last_cleanup_verification_results = tuple(verification_results)
        summary = ScanSummary(tuple(results), session.id); log.info("Scan completed session=%s root=%s counts=%s", session.id, root, summary.counts); return summary

    def count_scan_entries(
        self, path: str | Path, *, mode: ScanMode = "auto",
        interrupt_check: Callable[[], bool] | None = None,
    ) -> int:
        """Count entries that would produce :class:`ScanResult` objects.

        This is intentionally a lightweight metadata-only traversal for UI
        progress. It does not hash, detect, quarantine, or write scan history.
        The actual scan remains authoritative because the filesystem can change
        between counting and processing.
        """
        root = normalize_path(path)
        self._raise_if_interrupted(interrupt_check, root)
        try:
            info = root.lstat()
        except OSError:
            return 1

        directory = stat.S_ISDIR(info.st_mode) and not is_link_or_reparse(info)
        if mode == "directory" and not directory:
            return 1
        if mode != "file" and directory:
            return self._count_directory_entries(root, interrupt_check)
        return 1

    def _count_directory_entries(
        self, root: Path,
        interrupt_check: Callable[[], bool] | None = None,
    ) -> int:
        pending: list[tuple[Path, EntryKind]] = [(root, "directory")]
        visited: set[tuple[int, int]] = set()
        count = 0
        while pending:
            self._raise_if_interrupted(interrupt_check, root)
            current, kind = pending.pop()
            try:
                info = current.lstat()
            except OSError:
                count += 1
                continue

            if not stat.S_ISDIR(info.st_mode) or is_link_or_reparse(info):
                count += 1
                continue

            identity = (info.st_dev, info.st_ino)
            if info.st_ino and identity in visited:
                count += 1
                continue
            if info.st_ino:
                visited.add(identity)

            try:
                with os.scandir(current) as entries:
                    for entry in entries:
                        try:
                            entry_kind = (
                                "directory"
                                if entry.is_dir(follow_symlinks=False)
                                else "file"
                            )
                        except OSError:
                            entry_kind = "unknown"
                        pending.append((normalize_path(entry.path), entry_kind))
            except OSError:
                # The real scanner emits one directory issue for this path.
                count += 1
        return count

    @staticmethod
    def _notify_discovered(callback: DiscoveryCallback | None, path: Path, kind: EntryKind) -> None:
        if callback is None:return
        try:callback(str(path),kind)
        except Exception:pass

    def _iter_scan(self,root:Path,source:ScanSource,mode:ScanMode,interrupt_check:Callable[[],bool]|None=None,on_discovered:DiscoveryCallback|None=None)->Iterator[ScanResult]:
        self._raise_if_interrupted(interrupt_check,root)
        try:info=root.lstat()
        except OSError as error:self._notify_discovered(on_discovered,root,"unknown");yield self._failure(root,error,"unknown");return
        directory=stat.S_ISDIR(info.st_mode) and not is_link_or_reparse(info)
        if mode=="directory" and not directory:
            kind="directory" if stat.S_ISDIR(info.st_mode) else "file";self._notify_discovered(on_discovered,root,kind);yield ScanResult(str(root),ScanStatus.SKIPPED_UNSUPPORTED,"Expected a regular directory, not a file or link/reparse point.",kind)
        elif mode!="file" and directory:yield from self._iter_directory(root,source,interrupt_check,on_discovered)
        else:self._notify_discovered(on_discovered,root,"directory" if stat.S_ISDIR(info.st_mode) else "file");yield self._process_file(root,info,source)

    def _iter_directory(self,root:Path,source:ScanSource,interrupt_check:Callable[[],bool]|None=None,on_discovered:DiscoveryCallback|None=None)->Iterator[ScanResult]:
        """Single-pass walk: announce result-producing entries as found, then scan them."""
        pending:list[tuple[Path,EntryKind]]=[(root,"directory")];visited:set[tuple[int,int]]=set();announced:set[Path]=set()
        def announce(path:Path,kind:EntryKind)->None:
            if path in announced:return
            announced.add(path);self._notify_discovered(on_discovered,path,kind)
        while pending:
            self._raise_if_interrupted(interrupt_check,root);current,kind=pending.pop()
            try:info=current.lstat()
            except OSError as error:announce(current,kind);yield self._failure(current,error,kind);continue
            if not stat.S_ISDIR(info.st_mode) or is_link_or_reparse(info):announce(current,kind);yield self._process_file(current,info,source);continue
            identity=(info.st_dev,info.st_ino)
            if info.st_ino and identity in visited:announce(current,"directory");yield ScanResult(str(current),ScanStatus.SKIPPED_UNSUPPORTED,"Directory identity already visited; possible alias or loop.","directory");continue
            if info.st_ino:visited.add(identity)
            try:
                with os.scandir(current) as entries:
                    for entry in entries:
                        try:entry_kind="directory" if entry.is_dir(follow_symlinks=False) else "file"
                        except OSError:entry_kind="unknown"
                        path=normalize_path(entry.path);pending.append((path,entry_kind))
                        if entry_kind!="directory":announce(path,entry_kind)
            except OSError as error:announce(current,"directory");yield self._failure(current,error,"directory")


    @staticmethod
    def _raise_if_interrupted(
        interrupt_check: Callable[[], bool] | None, root: Path,
    ) -> None:
        if interrupt_check is not None and interrupt_check():
            raise ScanInterruptedError(
                f"Scan interrupted before completion: {root}"
            )

    def _process_file(
        self, path: Path, info: os.stat_result, source: ScanSource
    ) -> ScanResult:
        kind = "directory" if stat.S_ISDIR(info.st_mode) else "file"
        if is_link_or_reparse(info) or not stat.S_ISREG(info.st_mode):
            return ScanResult(
                str(path), ScanStatus.SKIPPED_UNSUPPORTED,
                "Only regular files are supported; links, reparse points, and special entries are skipped.",
                kind,
            )
        if path in self._database_files:
            return ScanResult(
                str(path), ScanStatus.SKIPPED_UNSUPPORTED,
                "AutoGuard's active database files are excluded.",
            )
        if self._quarantine_dir is not None and (
            path == self._quarantine_dir or self._quarantine_dir in path.parents
        ):
            return ScanResult(
                str(path), ScanStatus.SKIPPED_UNSUPPORTED,
                "AutoGuard quarantine storage is excluded from scanning.",
            )
        if info.st_size > self.max_file_size_bytes:
            return ScanResult(
                str(path), ScanStatus.SKIPPED_SIZE,
                f"Size {info.st_size} exceeds limit {self.max_file_size_bytes} bytes.",
            )

        detection = None
        sha256 = None
        stage = "read"
        try:
            preview_bytes = SCRIPT_PREVIEW_BYTES if path.suffix.lower() in SCRIPT_EXTENSIONS else 0
            inspection = inspect_file(
                path, preview_bytes=preview_bytes,
                max_size_bytes=self.max_file_size_bytes, follow_symlinks=False,
            )
            sha256 = inspection.fingerprint.sha256
            stage = "detection"
            detection = self.detector.detect_inspection(inspection)
            stage = "recording"
            observation = self.threat_trail.record_fingerprint(
                inspection.fingerprint, source,
                _connection=getattr(self._persistence_local, "trail_connection", None),
            )
            result_reason = detection.reason
            if detection.status is DetectionStatus.HIGH_CONFIDENCE:
                scanner_logger().warning("High-confidence detection path=%s sha256=%s rule=%s", path, detection.sha256, detection.rule_name); stage = "checking reappearance"
                reappearance = self.reappearance.check_detection(detection, source)
                if reappearance.detected:
                    if reappearance.incident is None:
                        raise RuntimeError("Reappearance was detected without an incident.")
                    incident = reappearance.incident
                    self._current_reappearance_results.append(reappearance)
                    if reappearance.explanation:
                        result_reason = f"{detection.reason} {reappearance.explanation}"
                else:
                    stage = "recording incident"
                    incident = self.incidents.record_high_confidence_detection(detection, source)
                if self.quarantine is not None and detection.matched_signature is not None:
                    stage = "quarantine"
                    self.quarantine.quarantine_detection(
                        detection, incident.id, source,
                        original_size=inspection.fingerprint.size_bytes,
                    )
        except Exception as error:
            if stage == "read":
                return self._failure(path, error, "file")
            return ScanResult(
                str(path), ScanStatus.ERROR,
                f"{stage.capitalize()} failed: {type(error).__name__}: {error}",
                detection=detection, sha256=sha256,
            )
        return ScanResult(
            str(path), ScanStatus.SCANNED, result_reason,
            detection=detection, observation=observation, sha256=sha256,
        )

    @staticmethod
    def _failure(path: Path, error: Exception, kind: EntryKind) -> ScanResult:
        status = ScanStatus.ERROR
        if isinstance(error, FileTooLargeError):
            status = ScanStatus.SKIPPED_SIZE
        elif isinstance(error, UnsupportedFileError):
            status = ScanStatus.SKIPPED_UNSUPPORTED
        elif kind != "directory" and isinstance(error, OSError) and (
            isinstance(error, PermissionError)
            or error.errno in {errno.EACCES, errno.EPERM, errno.EBUSY, errno.EAGAIN}
            or getattr(error, "winerror", None) in {5, 32, 33}
        ):
            status = ScanStatus.SKIPPED_LOCKED
        return ScanResult(str(path), status, f"{type(error).__name__}: {error}", kind)