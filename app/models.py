from dataclasses import dataclass
from datetime import datetime
from enum import Enum

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