from dataclasses import dataclass
from datetime import datetime
from enum import Enum

class ScanSource(str, Enum):
    MANUAL, STARTUP, SCHEDULED = "manual", "startup", "scheduled"
    FILE_MONITOR, USB, MATCHING_COPY, RECOVERY = "file_monitor", "usb", "matching_copy", "recovery"

@dataclass(frozen=True)
class FileFingerprint:
    sha256: str; path: str; size_bytes: int

@dataclass(frozen=True)
class FileObservation:
    id: int; sha256: str; path: str; source: ScanSource; size_bytes: int; first_seen: datetime; last_seen: datetime; seen_count: int

@dataclass(frozen=True)
class ObservationEvent:
    id: int; observation_id: int; sha256: str; path: str; source: ScanSource; size_bytes: int; observed_at: datetime