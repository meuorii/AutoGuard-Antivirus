import errno, os, stat
from collections import Counter
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Literal

from app.config import DEFAULT_MAX_FILE_SIZE_BYTES
from app.detection_rules import SCRIPT_EXTENSIONS
from app.detector import SCRIPT_PREVIEW_BYTES, Detector
from app.hashing import FileTooLargeError, UnsupportedFileError, inspect_file, is_link_or_reparse, normalize_path
from app.models import DetectionResult, DetectionStatus, FileObservation, ScanSource
from app.threat_trail import ThreatTrail

EntryKind = Literal["file", "directory", "unknown"]

class ScanStatus(str, Enum):
    SCANNED = "SCANNED"
    SKIPPED_SIZE = "SKIPPED_SIZE"
    SKIPPED_LOCKED = "SKIPPED_LOCKED"
    SKIPPED_UNSUPPORTED = "SKIPPED_UNSUPPORTED"
    ERROR = "ERROR"

@dataclass(frozen=True)
class ScanResult:
    path: str; status: ScanStatus; reason: str; kind: EntryKind = "file"; detection: DetectionResult | None = None; observation: FileObservation | None = None

@dataclass(frozen=True)
class ScanSummary:
    results: tuple[ScanResult, ...]

    @property
    def counts(self) -> dict[str, int]:
        """Derive counters from outcomes so they cannot drift out of sync."""
        files = [r for r in self.results if r.kind == "file"]
        statuses, detections = Counter(r.status for r in files), Counter(r.detection.status for r in self.results if r.detection is not None)
        return {"discovered_files": len(files), "scanned_files": statuses[ScanStatus.SCANNED], "dangerous_detections": detections[DetectionStatus.HIGH_CONFIDENCE], "suspicious_detections": detections[DetectionStatus.LOW_CONFIDENCE], "skipped_size": statuses[ScanStatus.SKIPPED_SIZE], "locked_files": statuses[ScanStatus.SKIPPED_LOCKED], "unsupported_files": statuses[ScanStatus.SKIPPED_UNSUPPORTED], "errors": sum(r.status is ScanStatus.ERROR for r in self.results), "file_errors": statuses[ScanStatus.ERROR], "directory_issues": sum(r.kind == "directory" for r in self.results), "unclassified_entries": sum(r.kind == "unknown" for r in self.results)}

    @property
    def message(self) -> str:
        counts = self.counts
        if counts["dangerous_detections"] or counts["suspicious_detections"]: message = f"Detections found: {counts['dangerous_detections']} dangerous, {counts['suspicious_detections']} suspicious"
        else:
            message = "No threats detected"
            if not self.results: message += ". No files were found"
            elif counts["scanned_files"] == 0: message += ". No files were successfully scanned"
        if any(r.status is not ScanStatus.SCANNED for r in self.results): message += ". Scan incomplete: review skipped entries and errors"
        return message

class Scanner:
    def __init__(self, detector: Detector, threat_trail: ThreatTrail, *, max_file_size_bytes: int = DEFAULT_MAX_FILE_SIZE_BYTES) -> None:
        if type(max_file_size_bytes) is not int or max_file_size_bytes < 0: raise ValueError("max_file_size_bytes must be a nonnegative integer.")
        self.detector, self.threat_trail, self.max_file_size_bytes = detector, threat_trail, max_file_size_bytes
        database_path = str(threat_trail.database.path)
        self._database_files = {normalize_path(database_path + suffix) for suffix in ("", "-wal", "-shm", "-journal")}

    def scan_file(self, path: str | Path, source: ScanSource = ScanSource.MANUAL) -> ScanResult:
        source, path = ScanSource(source), normalize_path(path)
        try: info = path.lstat()
        except OSError as error: return self._failure(path, error, "unknown")
        return self._process_file(path, info, source)

    def scan(self, path: str | Path, source: ScanSource = ScanSource.MANUAL) -> ScanSummary:
        """Dispatch a single file or directory and return a uniform summary."""
        source, path = ScanSource(source), normalize_path(path)
        try: info = path.lstat()
        except OSError as error: return ScanSummary((self._failure(path, error, "unknown"),))
        if stat.S_ISDIR(info.st_mode) and not is_link_or_reparse(info): return self.scan_directory(path, source)
        return ScanSummary((self._process_file(path, info, source),))

    def scan_directory(self, path: str | Path, source: ScanSource = ScanSource.MANUAL) -> ScanSummary:
        """Walk iteratively, including entries queued before a listing error."""
        source, root = ScanSource(source), normalize_path(path)
        try: root_info = root.lstat()
        except OSError as error: return ScanSummary((self._failure(root, error, "unknown"),))
        if not stat.S_ISDIR(root_info.st_mode) or is_link_or_reparse(root_info):
            return ScanSummary((ScanResult(str(root), ScanStatus.SKIPPED_UNSUPPORTED, "Expected a regular directory, not a file or link/reparse point.", "directory" if stat.S_ISDIR(root_info.st_mode) else "file"),))

        pending, visited, results = [(root, "directory")], set(), []
        while pending:
            current, kind = pending.pop()
            try: info = current.lstat()
            except OSError as error: results.append(self._failure(current, error, kind)); continue
            if not stat.S_ISDIR(info.st_mode) or is_link_or_reparse(info): results.append(self._process_file(current, info, source)); continue

            identity = (info.st_dev, info.st_ino)
            if info.st_ino and identity in visited: results.append(ScanResult(str(current), ScanStatus.SKIPPED_UNSUPPORTED, "Directory identity already visited; possible alias or loop.", "directory")); continue
            if info.st_ino: visited.add(identity)
            try:
                with os.scandir(current) as entries:
                    for entry in entries:
                        try: kind = "directory" if entry.is_dir(follow_symlinks=False) else "file"
                        except OSError: kind = "unknown"
                        pending.append((normalize_path(entry.path), kind))
            except OSError as error: results.append(self._failure(current, error, "directory"))
        return ScanSummary(tuple(results))

    def _process_file(self, path: Path, info: os.stat_result, source: ScanSource) -> ScanResult:
        kind = "directory" if stat.S_ISDIR(info.st_mode) else "file"
        if is_link_or_reparse(info) or not stat.S_ISREG(info.st_mode): return ScanResult(str(path), ScanStatus.SKIPPED_UNSUPPORTED, "Only regular files are supported; links, reparse points, and special entries are skipped.", kind)
        if path in self._database_files: return ScanResult(str(path), ScanStatus.SKIPPED_UNSUPPORTED, "AutoGuard's active database files are excluded.")
        if info.st_size > self.max_file_size_bytes: return ScanResult(str(path), ScanStatus.SKIPPED_SIZE, f"Size {info.st_size} exceeds limit {self.max_file_size_bytes} bytes.")

        detection, stage = None, "read"
        try:
            preview_bytes = SCRIPT_PREVIEW_BYTES if path.suffix.lower() in SCRIPT_EXTENSIONS else 0
            inspection = inspect_file(path, preview_bytes=preview_bytes, max_size_bytes=self.max_file_size_bytes, follow_symlinks=False)
            stage = "detection"; detection = self.detector.detect_inspection(inspection)
            stage = "recording"; observation = self.threat_trail.record_fingerprint(inspection.fingerprint, source)
        except Exception as error:
            if stage == "read": return self._failure(path, error, "file")
            return ScanResult(str(path), ScanStatus.ERROR, f"{stage.capitalize()} failed: {type(error).__name__}: {error}", detection=detection)
        return ScanResult(str(path), ScanStatus.SCANNED, detection.reason, detection=detection, observation=observation)

    @staticmethod
    def _failure(path: Path, error: Exception, kind: EntryKind) -> ScanResult:
        status = ScanStatus.ERROR
        if isinstance(error, FileTooLargeError): status = ScanStatus.SKIPPED_SIZE
        elif isinstance(error, UnsupportedFileError): status = ScanStatus.SKIPPED_UNSUPPORTED
        elif kind != "directory" and isinstance(error, OSError) and (isinstance(error, PermissionError) or error.errno in {errno.EACCES, errno.EPERM, errno.EBUSY, errno.EAGAIN} or getattr(error, "winerror", None) in {5, 32, 33}): status = ScanStatus.SKIPPED_LOCKED
        return ScanResult(str(path), status, f"{type(error).__name__}: {error}", kind)