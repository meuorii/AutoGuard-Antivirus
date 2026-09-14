from collections import Counter
from dataclasses import dataclass
from datetime import datetime
from enum import Enum
from typing import Literal

class ScanSource(str, Enum):
    """How a sighting was collected; this does not identify infection origin."""
    MANUAL = "manual"; STARTUP = "startup"; SCHEDULED = "scheduled"; FILE_MONITOR = "file_monitor"; USB = "usb"; MATCHING_COPY = "matching_copy"; RECOVERY = "recovery"

@dataclass(frozen=True)
class FileFingerprint:
    sha256: str; path: str; size_bytes: int

@dataclass(frozen=True)
class FileObservation:
    id: int; sha256: str; path: str; source: ScanSource; size_bytes: int; first_seen: datetime; last_seen: datetime; seen_count: int

@dataclass(frozen=True)
class ObservationEvent:
    id: int; observation_id: int; sha256: str; path: str; source: ScanSource; size_bytes: int; observed_at: datetime

@dataclass(frozen=True)
class FileInspection:
    fingerprint: FileFingerprint; preview: bytes

class DetectionStatus(str, Enum):
    NO_DETECTION = "NO_DETECTION"; LOW_CONFIDENCE = "LOW_CONFIDENCE"; HIGH_CONFIDENCE = "HIGH_CONFIDENCE"

class SignatureKind(str, Enum):
    KNOWN_MALICIOUS = "known_malicious"; AUTOGUARD_TEST = "autoguard_test"

@dataclass(frozen=True)
class Signature:
    name: str; sha256: str; kind: SignatureKind; description: str = ""

@dataclass(frozen=True)
class DetectionResult:
    """Confidence is an evidence score, not a probability of malware."""
    status: DetectionStatus; confidence: float; reason: str; rule_name: str; sha256: str; path: str; matched_signature: Signature | None = None

    def __post_init__(self) -> None:
        object.__setattr__(self, "status", DetectionStatus(self.status))
        if not 0.0 <= self.confidence <= 1.0: raise ValueError("confidence must be between 0 and 1.")
        if self.status is DetectionStatus.HIGH_CONFIDENCE:
            if self.matched_signature is None or self.matched_signature.sha256 != self.sha256 or self.matched_signature.kind not in tuple(SignatureKind):
                raise ValueError("High confidence requires a matching signature.")
        elif self.matched_signature is not None or self.confidence >= 1.0: raise ValueError("Heuristics cannot carry signature-level evidence.")
        if self.status is DetectionStatus.NO_DETECTION and self.confidence != 0.0: raise ValueError("No detection must have a zero evidence score.")

    @property
    def label(self) -> str:
        return {DetectionStatus.NO_DETECTION: "No Threat Detected", DetectionStatus.LOW_CONFIDENCE: "Suspicious", DetectionStatus.HIGH_CONFIDENCE: "Dangerous"}[self.status]

EntryKind = Literal["file", "directory", "unknown"]

class ScanStatus(str, Enum):
    SCANNED = "SCANNED"; SKIPPED_SIZE = "SKIPPED_SIZE"; SKIPPED_LOCKED = "SKIPPED_LOCKED"; SKIPPED_UNSUPPORTED = "SKIPPED_UNSUPPORTED"; ERROR = "ERROR"

@dataclass(frozen=True)
class ScanResult:
    path: str; status: ScanStatus; reason: str; kind: EntryKind = "file"; detection: DetectionResult | None = None; observation: FileObservation | None = None; sha256: str | None = None; session_id: str | None = None

@dataclass(frozen=True)
class ScanSummary:
    results: tuple[ScanResult, ...]; session_id: str | None = None

    @property
    def counts(self) -> dict[str, int]:
        """Count outcomes, keeping directory issues and unknown types separate. Detections survive a later failure to persist an observation."""
        files = [r for r in self.results if r.kind == "file"]; statuses = Counter(r.status for r in files); detections = Counter(r.detection.status for r in self.results if r.detection is not None)
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

class ScanType(str, Enum):
    """Session labels; these do not enable automatic triggers or select targets."""
    MANUAL = "manual"; QUICK = "quick"; FULL = "full"; STARTUP = "startup"; SCHEDULED = "scheduled"; USB = "usb"; REAL_TIME = "real_time"; MATCHING_COPY = "matching_copy"; RECOVERY = "recovery"

    @property
    def default_source(self) -> ScanSource:
        if self in (ScanType.QUICK, ScanType.FULL): return ScanSource.MANUAL
        if self is ScanType.REAL_TIME: return ScanSource.FILE_MONITOR
        return ScanSource(self.value)

    @classmethod
    def from_source(cls, source: ScanSource) -> "ScanType":
        s = ScanSource(source); return cls.REAL_TIME if s is ScanSource.FILE_MONITOR else cls(s.value)

class ScanSessionStatus(str, Enum):
    RUNNING = "RUNNING"; COMPLETED = "COMPLETED"; INCOMPLETE = "INCOMPLETE"; FAILED = "FAILED"

@dataclass(frozen=True)
class ScanSession:
    id: str; scan_type: ScanType; source_path: str; source: ScanSource; started_at: datetime; finished_at: datetime | None; status: ScanSessionStatus; counters: dict[str, int]; error: str | None = None

@dataclass(frozen=True)
class StoredScanResult:
    """Historical evidence snapshot; reading history never reruns detection."""
    id: int; session_id: str; path: str; sha256: str | None; result_category: ScanStatus; entry_kind: EntryKind; detection_status: DetectionStatus | None; detection_confidence: float | None; rule_name: str | None; reason: str; detection_reason: str | None; matched_signature_name: str | None; matched_signature_kind: SignatureKind | None; recorded_at: datetime

@dataclass(frozen=True)
class ScanDetails:
    session: ScanSession; results: tuple[StoredScanResult, ...]