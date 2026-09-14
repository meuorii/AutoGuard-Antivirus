import errno, os, stat
from dataclasses import replace
from pathlib import Path
from typing import Iterator, Literal

from app.cleanup_verifier import CleanupVerificationResult, CleanupVerifier
from app.config import DEFAULT_MAX_FILE_SIZE_BYTES
from app.detection_rules import SCRIPT_EXTENSIONS
from app.detector import SCRIPT_PREVIEW_BYTES, Detector
from app.hashing import FileTooLargeError, UnsupportedFileError, inspect_file, is_link_or_reparse, normalize_path
from app.incidents import IncidentService
from app.matching_cleanup import MatchingCleanupResult, MatchingCopyCleanup
from app.models import DetectionStatus, EntryKind, ScanResult, ScanSource, ScanStatus, ScanSummary, ScanType
from app.quarantine import QuarantineService
from app.scan_history import ScanHistory, ScanHistoryError
from app.threat_trail import ThreatTrail

ScanMode = Literal["auto", "file", "directory"]


class Scanner:
    def __init__(self, detector: Detector, threat_trail: ThreatTrail, *, max_file_size_bytes: int = DEFAULT_MAX_FILE_SIZE_BYTES, history: ScanHistory | None = None, incidents: IncidentService | None = None, quarantine: QuarantineService | None = None, matching_cleanup: MatchingCopyCleanup | None = None, cleanup_verifier: CleanupVerifier | None = None) -> None:
        if type(max_file_size_bytes) is not int or max_file_size_bytes < 0: raise ValueError("max_file_size_bytes must be a nonnegative integer.")
        self.detector, self.threat_trail, self.max_file_size_bytes = detector, threat_trail, max_file_size_bytes
        self.history = history if history is not None else ScanHistory(threat_trail.database)
        self.incidents = incidents if incidents is not None else IncidentService(threat_trail.database)
        self.quarantine, self.matching_cleanup, self.cleanup_verifier = quarantine, matching_cleanup, cleanup_verifier
        self.last_matching_cleanup_results: tuple[MatchingCleanupResult, ...] = ()
        self.last_cleanup_verification_results: tuple[CleanupVerificationResult, ...] = ()
        self._quarantine_dir = normalize_path(quarantine.quarantine_dir) if quarantine is not None else None
        self._database_files = {normalize_path(str(database.path) + suffix) for database in (threat_trail.database, self.history.database) for suffix in ("", "-wal", "-shm", "-journal")}

    def scan_file(self, path: str | Path, source: ScanSource | None = None, *, scan_type: ScanType | None = None) -> ScanResult: return self._run(path, source, scan_type, "file").results[0]

    def scan(self, path: str | Path, source: ScanSource | None = None, *, scan_type: ScanType | None = None) -> ScanSummary: return self._run(path, source, scan_type, "auto")

    def scan_directory(self, path: str | Path, source: ScanSource | None = None, *, scan_type: ScanType | None = None) -> ScanSummary: return self._run(path, source, scan_type, "directory")

    def _run(self, path: str | Path, source: ScanSource | None, scan_type: ScanType | None, mode: ScanMode) -> ScanSummary:
        if scan_type is None: source, scan_type = ScanSource.MANUAL if source is None else ScanSource(source), ScanType.from_source(source if source is not None else ScanSource.MANUAL)
        else: scan_type, source = ScanType(scan_type), scan_type.default_source if source is None else ScanSource(source)
        root = normalize_path(path)
        try: session = self.history.start_session(scan_type, root, source)
        except Exception as error: raise ScanHistoryError(f"Could not start scan history: {type(error).__name__}: {error}") from error
        results, stage = [], "processing"
        try:
            for result in self._iter_scan(root, source, mode):
                result = replace(result, session_id=session.id)
                stage = f"saving result for {result.path}"
                self.history.record_result(session.id, result)
                results.append(result)
                stage = "processing"
            stage = "finalizing history"
            self.history.finish_session(session.id)
        except BaseException as error:
            detail = f"{stage}: {type(error).__name__}: {error}"
            try: self.history.finish_session(session.id, error=detail, interrupted=isinstance(error, (KeyboardInterrupt, SystemExit)))
            except Exception as finish_error:
                if not isinstance(error, Exception): raise error from finish_error
                raise ScanHistoryError(f"{detail}; could not finalize history: {finish_error}", session.id) from finish_error
            if stage != "processing" and isinstance(error, Exception): raise ScanHistoryError(detail, session.id) from error
            raise
        cleanup_results, verification_results = [], []
        dangerous_hashes = {result.detection.sha256 for result in results if result.detection is not None and result.detection.status is DetectionStatus.HIGH_CONFIDENCE}
        active_by_hash = {item.sha256: item.id for item in self.incidents.get_active_incidents()}
        incident_ids = [active_by_hash[sha256] for sha256 in dangerous_hashes if sha256 in active_by_hash]
        if self.matching_cleanup is not None:
            for incident_id in incident_ids: cleanup_results.append(self.matching_cleanup.cleanup_incident(incident_id))
        self.last_matching_cleanup_results = tuple(cleanup_results)
        if self.cleanup_verifier is not None:
            for incident_id in incident_ids: verification_results.append(self.cleanup_verifier.verify_incident(incident_id))
        self.last_cleanup_verification_results = tuple(verification_results)
        return ScanSummary(tuple(results), session.id)

    def _iter_scan(self, root: Path, source: ScanSource, mode: ScanMode) -> Iterator[ScanResult]:
        try: info = root.lstat()
        except OSError as error: yield self._failure(root, error, "unknown"); return
        directory = stat.S_ISDIR(info.st_mode) and not is_link_or_reparse(info)
        if mode == "directory" and not directory: yield ScanResult(str(root), ScanStatus.SKIPPED_UNSUPPORTED, "Expected a regular directory, not a file or link/reparse point.", "directory" if stat.S_ISDIR(info.st_mode) else "file")
        elif mode != "file" and directory: yield from self._iter_directory(root, source)
        else: yield self._process_file(root, info, source)

    def _iter_directory(self, root: Path, source: ScanSource) -> Iterator[ScanResult]:
        pending: list[tuple[Path, EntryKind]] = [(root, "directory")]
        visited: set[tuple[int, int]] = set()
        while pending:
            current, kind = pending.pop()
            try: info = current.lstat()
            except OSError as error: yield self._failure(current, error, kind); continue
            if not stat.S_ISDIR(info.st_mode) or is_link_or_reparse(info): yield self._process_file(current, info, source); continue
            identity = (info.st_dev, info.st_ino)
            if info.st_ino and identity in visited: yield ScanResult(str(current), ScanStatus.SKIPPED_UNSUPPORTED, "Directory identity already visited; possible alias or loop.", "directory"); continue
            if info.st_ino: visited.add(identity)
            try:
                with os.scandir(current) as entries:
                    for entry in entries:
                        try: kind = "directory" if entry.is_dir(follow_symlinks=False) else "file"
                        except OSError: kind = "unknown"
                        pending.append((normalize_path(entry.path), kind))
            except OSError as error: yield self._failure(current, error, "directory")

    def _process_file(self, path: Path, info: os.stat_result, source: ScanSource) -> ScanResult:
        kind = "directory" if stat.S_ISDIR(info.st_mode) else "file"
        if is_link_or_reparse(info) or not stat.S_ISREG(info.st_mode): return ScanResult(str(path), ScanStatus.SKIPPED_UNSUPPORTED, "Only regular files are supported; links, reparse points, and special entries are skipped.", kind)
        if path in self._database_files: return ScanResult(str(path), ScanStatus.SKIPPED_UNSUPPORTED, "AutoGuard's active database files are excluded.")
        if self._quarantine_dir is not None and (path == self._quarantine_dir or self._quarantine_dir in path.parents): return ScanResult(str(path), ScanStatus.SKIPPED_UNSUPPORTED, "AutoGuard quarantine storage is excluded from scanning.")
        if info.st_size > self.max_file_size_bytes: return ScanResult(str(path), ScanStatus.SKIPPED_SIZE, f"Size {info.st_size} exceeds limit {self.max_file_size_bytes} bytes.")
        detection, sha256, stage = None, None, "read"
        try:
            preview_bytes = SCRIPT_PREVIEW_BYTES if path.suffix.lower() in SCRIPT_EXTENSIONS else 0
            inspection = inspect_file(path, preview_bytes=preview_bytes, max_size_bytes=self.max_file_size_bytes, follow_symlinks=False)
            sha256 = inspection.fingerprint.sha256
            stage = "detection"
            detection = self.detector.detect_inspection(inspection)
            stage = "recording"
            observation = self.threat_trail.record_fingerprint(inspection.fingerprint, source)
            if detection.status is DetectionStatus.HIGH_CONFIDENCE:
                stage = "recording incident"
                incident = self.incidents.record_high_confidence_detection(detection, source)
                if self.quarantine is not None and detection.matched_signature is not None:
                    stage = "quarantine"
                    self.quarantine.quarantine_detection(detection, incident.id, source, original_size=inspection.fingerprint.size_bytes)
        except Exception as error:
            if stage == "read": return self._failure(path, error, "file")
            return ScanResult(str(path), ScanStatus.ERROR, f"{stage.capitalize()} failed: {type(error).__name__}: {error}", detection=detection, sha256=sha256)
        return ScanResult(str(path), ScanStatus.SCANNED, detection.reason, detection=detection, observation=observation, sha256=sha256)

    @staticmethod
    def _failure(path: Path, error: Exception, kind: EntryKind) -> ScanResult:
        status = ScanStatus.ERROR
        if isinstance(error, FileTooLargeError): status = ScanStatus.SKIPPED_SIZE
        elif isinstance(error, UnsupportedFileError): status = ScanStatus.SKIPPED_UNSUPPORTED
        elif kind != "directory" and isinstance(error, OSError) and (isinstance(error, PermissionError) or error.errno in {errno.EACCES, errno.EPERM, errno.EBUSY, errno.EAGAIN} or getattr(error, "winerror", None) in {5, 32, 33}): status = ScanStatus.SKIPPED_LOCKED
        return ScanResult(str(path), status, f"{type(error).__name__}: {error}", kind)