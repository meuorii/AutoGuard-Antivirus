"""Native Windows toast notifications for real-time file verdicts.

This module is deliberately presentation-only. It does not hash files, run
rules, quarantine content, or decide security state. The File Monitor supplies
an already completed :class:`ScanResult`, and this service only translates that
stored scanner outcome into a concise Windows notification.
"""

from __future__ import annotations

import os
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Protocol

from app.hashing import normalize_path
from app.logging_config import monitor_logger
from app.models import DetectionStatus, ScanResult, ScanStatus


_BROWSER_TEMP_SUFFIXES = (".crdownload", ".part", ".partial", ".opdownload")


class NotificationBackend(Protocol):
    def show(self, title: str, message: str) -> None: ...


class _WinotifyBackend:
    """Small adapter so winotify is imported only on Windows at runtime."""

    def __init__(self) -> None:
        from winotify import Notification

        self._notification_cls = Notification

    def show(self, title: str, message: str) -> None:
        toast = self._notification_cls(
            app_id="AutoGuard",
            title=title,
            msg=message,
        )
        toast.show()


@dataclass(frozen=True)
class NotificationHealth:
    enabled: bool
    available: bool
    notifications_sent: int
    notifications_suppressed: int
    last_error: str | None


class FileVerdictNotifier:
    """Translate completed real-time scan results into restrained Windows toasts.

    Policy:
    * Clean/incomplete notifications are shown only for new/moved files in the
      configured Downloads root(s).
    * Suspicious and confirmed-threat verdicts notify for any monitored path.
    * Browser temporary download filenames do not produce clean/incomplete
      notifications; the final renamed file is expected to be scanned normally.
    * Identical path/verdict notifications are deduplicated for a short cooldown.
    """

    def __init__(
        self,
        download_roots: tuple[str | Path, ...] = (),
        *,
        enabled: bool = True,
        backend: NotificationBackend | None = None,
        cooldown_seconds: float = 60.0,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        if cooldown_seconds < 0:
            raise ValueError("cooldown_seconds must be nonnegative.")
        self.enabled = bool(enabled)
        self.download_roots = tuple(normalize_path(path) for path in download_roots)
        self.cooldown_seconds = float(cooldown_seconds)
        self._clock = clock
        self._lock = threading.Lock()
        self._last_sent: dict[tuple[str, str], float] = {}
        self._sent = 0
        self._suppressed = 0
        self._last_error: str | None = None

        if backend is not None:
            self._backend: NotificationBackend | None = backend
        elif self.enabled and os.name == "nt":
            try:
                self._backend = _WinotifyBackend()
            except Exception as error:
                self._backend = None
                self._last_error = (
                    f"Windows notification backend unavailable: "
                    f"{type(error).__name__}: {error}"
                )
                monitor_logger().warning(self._last_error)
        else:
            self._backend = None

    def health(self) -> NotificationHealth:
        with self._lock:
            return NotificationHealth(
                enabled=self.enabled,
                available=self.enabled and self._backend is not None,
                notifications_sent=self._sent,
                notifications_suppressed=self._suppressed,
                last_error=self._last_error,
            )

    def handle_scan_result(self, result: ScanResult, event_type: str) -> bool:
        """Show a toast for one completed File Monitor result when policy allows."""
        if not self.enabled or self._backend is None:
            return False

        event = str(event_type or "").strip().lower()
        path = normalize_path(result.path)
        name = path.name or str(path)
        detection_status = (
            result.detection.status if result.detection is not None else DetectionStatus.NO_DETECTION
        )

        if detection_status is DetectionStatus.HIGH_CONFIDENCE:
            verdict = "confirmed"
            title = "Confirmed threat detected"
            message = f"{name} needs attention. AutoGuard detected a confirmed threat."
        elif detection_status is DetectionStatus.LOW_CONFIDENCE:
            # Low-confidence heuristics can be noisy for normal source-code edits.
            # Notify when the suspicious file is newly created/moved, while
            # ordinary modifications remain visible in Activity.
            if event not in {"created", "moved"}:
                return False
            verdict = "suspicious"
            title = "Suspicious file found"
            message = f"{name} needs review. No confirmed threat was detected."
        else:
            # Normal file edits across Desktop/Documents should stay in Activity
            # rather than becoming notification spam. A user-facing verdict is
            # useful primarily when a new download has just appeared.
            if event not in {"created", "moved"} or not self._is_download(path):
                return False
            if self._looks_temporary_download(path):
                return False
            if result.status is ScanStatus.SCANNED:
                verdict = "clean"
                title = f"{name} checked"
                message = "No threats detected in the file AutoGuard successfully scanned."
            else:
                verdict = "incomplete"
                title = f"Could not fully check {name}"
                message = "AutoGuard could not complete the file check. Open Activity for details."

        key = (str(path).casefold(), verdict)
        now = self._clock()
        with self._lock:
            previous = self._last_sent.get(key)
            if previous is not None and now - previous < self.cooldown_seconds:
                self._suppressed += 1
                return False
            # Reserve before invoking the backend so simultaneous monitor workers
            # cannot emit duplicate toasts for the same path/verdict.
            self._last_sent[key] = now

        try:
            self._backend.show(title, message)
        except Exception as error:
            with self._lock:
                self._last_sent.pop(key, None)
                self._last_error = f"Notification failed: {type(error).__name__}: {error}"
            monitor_logger().warning(self._last_error)
            return False

        with self._lock:
            self._sent += 1
            self._last_error = None
        return True

    def _is_download(self, path: Path) -> bool:
        return any(path == root or root in path.parents for root in self.download_roots)

    @staticmethod
    def _looks_temporary_download(path: Path) -> bool:
        name = path.name.casefold()
        return any(name.endswith(suffix) for suffix in _BROWSER_TEMP_SUFFIXES)
