"""Real scan progress and throughput estimates shared by UI scan workers."""
from __future__ import annotations

from dataclasses import dataclass
import time


@dataclass
class ScanProgress:
    """Accumulate scanner events and derive a conservative file-count ETA."""

    started_at: float
    alpha: float = 0.25
    processed: int = 0
    total: int | None = None
    bytes_processed: int = 0
    phase: str = "discovering"
    _sample_processed: int = 0
    _sample_at: float | None = None
    _rates: int = 0
    _rate: float | None = None

    @classmethod
    def start(cls, now: float | None = None) -> "ScanProgress":
        return cls(time.monotonic() if now is None else now)

    def set_phase(self, phase: str, total: int | None = None) -> None:
        self.phase = phase
        if total is not None:
            self.total = max(0, int(total))

    def record_result(
        self, *, size_bytes: int = 0, now: float | None = None
    ) -> None:
        moment = time.monotonic() if now is None else now
        self.processed += 1
        self.bytes_processed += max(0, int(size_bytes))
        if self.total is not None:
            self.total = max(self.total, self.processed)
        if self._sample_at is None:
            self._sample_at = moment
            self._sample_processed = self.processed
            return
        elapsed = moment - self._sample_at
        count = self.processed - self._sample_processed
        if elapsed <= 0 or count <= 0:
            return
        measured = count / elapsed
        self._rate = measured if self._rate is None else (
            self.alpha * measured + (1 - self.alpha) * self._rate
        )
        self._rates += 1
        self._sample_at = moment
        self._sample_processed = self.processed

    def snapshot(self, now: float | None = None) -> dict:
        moment = time.monotonic() if now is None else now
        remaining = None
        if (
            self.phase == "scanning"
            and self.total is not None
            and self._rates >= 2
            and self._rate is not None
            and self._rate > 0
        ):
            remaining = max(0, self.total - self.processed) / self._rate
        return {
            "phase": self.phase,
            "total": self.total,
            "processed": self.processed,
            "elapsed": max(0.0, moment - self.started_at),
            "eta_seconds": remaining,
            "bytes_processed": self.bytes_processed,
        }
