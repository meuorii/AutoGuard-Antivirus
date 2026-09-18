"""Real-time filesystem monitoring with debounced background scan dispatch.

Watchdog callbacks must stay cheap: they only filter, normalize, debounce, and
queue candidate paths. Stability checks and AutoGuard scans run on worker
threads (or through ``process_pending_once`` in deterministic tests).
"""

from __future__ import annotations

import os
import queue
import stat
import threading
import time
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Callable, Iterable, Protocol

from app.hashing import normalize_path
from app.logging_config import monitor_logger
from app.models import ScanResult, ScanSource, ScanType
from app.scanner import Scanner

try:  # Runtime dependency. Tests can inject a fake observer without watchdog installed.
    from watchdog.events import FileSystemEventHandler
    from watchdog.observers import Observer
except ImportError:  # pragma: no cover - exercised only when dependency is absent.
    class FileSystemEventHandler:  # type: ignore[no-redef]
        """Minimal fallback base so deterministic unit tests can import this module."""

    Observer = None  # type: ignore[assignment]


class ObserverProtocol(Protocol):
    def schedule(self, event_handler, path: str, recursive: bool = True): ...
    def start(self) -> None: ...
    def stop(self) -> None: ...
    def join(self, timeout: float | None = None) -> None: ...
    def is_alive(self) -> bool: ...


class MonitorStatus(str, Enum):
    STOPPED = "STOPPED"
    RUNNING = "RUNNING"
    DEGRADED = "DEGRADED"


@dataclass(frozen=True)
class StabilityResult:
    stable: bool
    reason: str
    size_bytes: int | None = None
    mtime_ns: int | None = None


@dataclass(frozen=True)
class MonitorHealth:
    status: MonitorStatus
    running: bool
    observer_alive: bool
    workers_alive: int
    monitored_paths: tuple[str, ...]
    scheduled_paths: tuple[str, ...]
    queue_depth: int
    events_received: int
    events_queued: int
    events_debounced: int
    scans_dispatched: int
    stability_failures: int
    scan_failures: int
    last_error: str | None


@dataclass(frozen=True)
class _ScanRequest:
    path: Path
    event_type: str
    queued_at: float


_STOP = object()


def _windows_known_user_folders() -> tuple[Path, Path, Path] | None:
    """Resolve Downloads/Desktop/Documents from Windows User Shell Folders.

    This respects OneDrive and other shell-folder redirection.  Any registry
    failure falls back to the conventional profile-relative paths.
    """
    if os.name != "nt":
        return None
    try:
        import winreg
        key_path = r"Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders"
        downloads_guid = "{374DE290-123F-4565-9164-39C4925E467B}"
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, key_path) as key:
            values = []
            for name in (downloads_guid, "Desktop", "Personal"):
                raw, _ = winreg.QueryValueEx(key, name)
                values.append(normalize_path(os.path.expandvars(str(raw))))
        return tuple(values)  # type: ignore[return-value]
    except (OSError, ImportError, TypeError, ValueError):
        return None


def default_monitored_paths(home: str | Path | None = None) -> tuple[Path, ...]:
    """Return Downloads, Desktop, and Documents without creating them.

    On Windows the shell-folder registry is preferred so redirected locations
    such as OneDrive Desktop/Documents are monitored correctly. Passing an
    explicit ``home`` keeps the deterministic profile-relative behavior used by
    tests and custom configurations.
    """
    if home is None:
        known = _windows_known_user_folders()
        if known is not None:
            return known
    root = Path.home() if home is None else Path(home).expanduser()
    return tuple(normalize_path(root / name) for name in ("Downloads", "Desktop", "Documents"))


class _WatchdogHandler(FileSystemEventHandler):
    def __init__(self, monitor: "FileMonitor") -> None:
        super().__init__()
        self.monitor = monitor

    def on_created(self, event) -> None:
        self.monitor.handle_event("created", event.src_path, is_directory=event.is_directory)

    def on_modified(self, event) -> None:
        self.monitor.handle_event("modified", event.src_path, is_directory=event.is_directory)

    def on_moved(self, event) -> None:
        self.monitor.handle_event(
            "moved", event.src_path, dest_path=event.dest_path,
            is_directory=event.is_directory,
        )


class FileMonitor:
    """Queue stable file changes and dispatch them through the existing Scanner.

    The monitor never performs hashing, detection, quarantine, cleanup, or
    verification in watchdog callbacks. Those callbacks only enqueue work.
    """

    def __init__(
        self,
        scanner: Scanner,
        monitored_paths: Iterable[str | Path] | None = None,
        *,
        ignored_paths: Iterable[str | Path] = (),
        debounce_seconds: float = 1.0,
        stability_period_seconds: float = 1.0,
        stability_poll_seconds: float = 0.25,
        stability_timeout_seconds: float = 30.0,
        worker_count: int = 1,
        on_scan_result: Callable[[ScanResult, str], None] | None = None,
        observer_factory: Callable[[], ObserverProtocol] | None = None,
        clock: Callable[[], float] = time.monotonic,
        sleep: Callable[[float], None] = time.sleep,
        stat_func: Callable[[Path], os.stat_result] | None = None,
    ) -> None:
        if debounce_seconds < 0:
            raise ValueError("debounce_seconds must be nonnegative.")
        if stability_period_seconds < 0:
            raise ValueError("stability_period_seconds must be nonnegative.")
        if stability_poll_seconds <= 0:
            raise ValueError("stability_poll_seconds must be greater than zero.")
        if stability_timeout_seconds < stability_period_seconds:
            raise ValueError(
                "stability_timeout_seconds must be at least stability_period_seconds."
            )
        if type(worker_count) is not int or worker_count <= 0:
            raise ValueError("worker_count must be a positive integer.")

        self.scanner = scanner
        roots = default_monitored_paths() if monitored_paths is None else tuple(monitored_paths)
        self._monitored_paths = self._deduplicate_roots(roots)
        self._ignored_paths = self._deduplicate_roots(ignored_paths)
        self.debounce_seconds = float(debounce_seconds)
        self.stability_period_seconds = float(stability_period_seconds)
        self.stability_poll_seconds = float(stability_poll_seconds)
        self.stability_timeout_seconds = float(stability_timeout_seconds)
        self.worker_count = worker_count
        self._on_scan_result = on_scan_result
        self._observer_factory = observer_factory
        self._clock = clock
        self._sleep = sleep
        self._stat = stat_func if stat_func is not None else lambda path: path.stat()

        self._queue: queue.Queue[_ScanRequest | object] = queue.Queue()
        self._lock = threading.Lock()
        self._scheduled: set[Path] = set()
        self._last_completed: dict[Path, float] = {}
        self._observer: ObserverProtocol | None = None
        self._handler = _WatchdogHandler(self)
        self._workers: list[threading.Thread] = []
        self._running = False
        self._scheduled_roots: tuple[Path, ...] = ()
        self._last_error: str | None = None
        self._events_received = 0
        self._events_queued = 0
        self._events_debounced = 0
        self._scans_dispatched = 0
        self._stability_failures = 0
        self._scan_failures = 0

    @staticmethod
    def _deduplicate_roots(paths: Iterable[str | Path]) -> tuple[Path, ...]:
        unique: list[Path] = []
        for raw in paths:
            path = normalize_path(raw)
            if path not in unique:
                unique.append(path)
        return tuple(unique)

    def monitored_paths(self) -> tuple[Path, ...]:
        return self._monitored_paths

    def ignored_paths(self) -> tuple[Path, ...]:
        return self._ignored_paths

    def status(self) -> MonitorStatus:
        return self.health().status

    def health(self) -> MonitorHealth:
        observer_alive = bool(self._observer and self._safe_observer_alive(self._observer))
        workers_alive = sum(worker.is_alive() for worker in self._workers)
        with self._lock:
            running = self._running
            last_error = self._last_error
            counters = (
                self._events_received,
                self._events_queued,
                self._events_debounced,
                self._scans_dispatched,
                self._stability_failures,
                self._scan_failures,
            )
        if not running:
            status = MonitorStatus.STOPPED
        elif last_error is not None or not observer_alive or workers_alive < self.worker_count:
            status = MonitorStatus.DEGRADED
        else:
            status = MonitorStatus.RUNNING
        return MonitorHealth(
            status=status,
            running=running,
            observer_alive=observer_alive,
            workers_alive=workers_alive,
            monitored_paths=tuple(str(path) for path in self._monitored_paths),
            scheduled_paths=tuple(str(path) for path in self._scheduled_roots),
            queue_depth=self._queue.qsize(),
            events_received=counters[0],
            events_queued=counters[1],
            events_debounced=counters[2],
            scans_dispatched=counters[3],
            stability_failures=counters[4],
            scan_failures=counters[5],
            last_error=last_error,
        )

    @staticmethod
    def _safe_observer_alive(observer: ObserverProtocol) -> bool:
        try:
            return observer.is_alive()
        except Exception:
            return False

    def start(self) -> MonitorHealth:
        """Start watchdog observation and scan workers. Safe to call twice."""
        with self._lock:
            already_running = self._running
        if already_running:
            return self.health()

        if self._observer_factory is not None:
            observer = self._observer_factory()
        else:
            if Observer is None:
                raise RuntimeError(
                    "watchdog is required for real-time monitoring. "
                    "Install project dependencies with: python -m pip install -r requirements.txt"
                )
            observer = Observer()  # type: ignore[operator]

        scheduled: list[Path] = []
        for root in self._monitored_paths:
            if not root.exists() or not root.is_dir():
                continue
            observer.schedule(self._handler, str(root), recursive=True)
            scheduled.append(root)
        if not scheduled:
            raise ValueError("None of the configured monitored directories currently exist.")

        self._observer = observer
        self._scheduled_roots = tuple(scheduled)
        self._workers = [
            threading.Thread(
                target=self._worker_loop,
                name=f"AutoGuardFileMonitor-{index + 1}",
                daemon=True,
            )
            for index in range(self.worker_count)
        ]
        with self._lock:
            self._running = True
            self._last_error = None
        for worker in self._workers:
            worker.start()
        try:
            observer.start()
        except Exception:
            with self._lock:
                self._running = False
            for _ in self._workers:
                self._queue.put(_STOP)
            for worker in self._workers:
                worker.join(timeout=1.0)
            self._workers.clear()
            self._observer = None
            self._scheduled_roots = ()
            raise
        monitor_logger().info("File monitor started paths=%s", [str(p) for p in self._scheduled_roots]); return self.health()

    def stop(self, timeout: float = 5.0) -> MonitorHealth:
        """Stop observation and workers without abandoning an in-flight scan."""
        if timeout < 0:
            raise ValueError("timeout must be nonnegative.")
        with self._lock:
            was_running = self._running
            self._running = False
        if not was_running and self._observer is None and not self._workers:
            return self.health()

        observer = self._observer
        if observer is not None:
            try:
                observer.stop()
                observer.join(timeout=timeout)
            except Exception as error:
                self._record_error(f"Observer stop failed: {type(error).__name__}: {error}")

        for _ in self._workers:
            self._queue.put(_STOP)
        for worker in self._workers:
            worker.join(timeout=timeout)
        self._workers.clear()
        self._observer = None
        self._scheduled_roots = (); monitor_logger().info("File monitor stopped"); return self.health()

    def handle_event(
        self,
        event_type: str,
        src_path: str | Path,
        *,
        dest_path: str | Path | None = None,
        is_directory: bool = False,
    ) -> bool:
        """Handle a lightweight watchdog event and enqueue eligible file work."""
        with self._lock:
            self._events_received += 1
        if is_directory:
            return False
        event_type = event_type.lower()
        if event_type not in {"created", "modified", "moved"}:
            return False
        candidate = dest_path if event_type == "moved" else src_path
        if candidate is None:
            return False
        return self.queue_path(candidate, event_type=event_type)

    def queue_path(self, path: str | Path, *, event_type: str = "created") -> bool:
        """Filter and debounce a path before adding it to the worker queue."""
        candidate = normalize_path(path)
        if not self._is_monitored(candidate) or self._is_ignored(candidate):
            return False
        now = self._clock()
        with self._lock:
            last_completed = self._last_completed.get(candidate)
            if candidate in self._scheduled or (
                last_completed is not None and now - last_completed < self.debounce_seconds
            ):
                self._events_debounced += 1
                return False
            self._scheduled.add(candidate)
            self._events_queued += 1
        self._queue.put(_ScanRequest(candidate, event_type, now))
        return True

    def _is_monitored(self, path: Path) -> bool:
        return any(path == root or root in path.parents for root in self._monitored_paths)

    def _is_ignored(self, path: Path) -> bool:
        return any(path == root or root in path.parents for root in self._ignored_paths)

    def check_stability(self, path: str | Path) -> StabilityResult:
        """Wait until size and mtime stay unchanged for the configured period."""
        candidate = normalize_path(path)
        started = self._clock()
        stable_since: float | None = None
        previous: tuple[int, int] | None = None

        while True:
            now = self._clock()
            try:
                info = self._stat(candidate)
            except FileNotFoundError:
                return StabilityResult(False, "File no longer exists.")
            except (PermissionError, OSError) as error:
                return StabilityResult(
                    False, f"File cannot be checked: {type(error).__name__}: {error}"
                )

            mode = getattr(info, "st_mode", None)
            if mode is not None and not stat.S_ISREG(mode):
                return StabilityResult(False, "Path is not a regular file.")

            signature = (int(info.st_size), int(info.st_mtime_ns))
            if signature != previous:
                previous = signature
                stable_since = now
            elif stable_since is not None and now - stable_since >= self.stability_period_seconds:
                return StabilityResult(True, "File size and modification time are stable.", *signature)

            if self.stability_period_seconds == 0:
                return StabilityResult(True, "Stability delay is disabled.", *signature)
            if now - started >= self.stability_timeout_seconds:
                return StabilityResult(
                    False,
                    "File did not become stable before the stability timeout.",
                    *signature,
                )
            remaining = self.stability_timeout_seconds - (now - started)
            self._sleep(min(self.stability_poll_seconds, remaining))

    def process_pending_once(self, timeout: float = 0.0) -> bool:
        """Process one queued request; useful for deterministic service tests."""
        try:
            item = self._queue.get(timeout=timeout)
        except queue.Empty:
            return False
        if item is _STOP:
            self._queue.task_done()
            return False
        assert isinstance(item, _ScanRequest)
        try:
            self._process_request(item)
        finally:
            self._queue.task_done()
        return True

    def _worker_loop(self) -> None:
        while True:
            item = self._queue.get()
            try:
                if item is _STOP:
                    return
                assert isinstance(item, _ScanRequest)
                self._process_request(item)
            except Exception as error:  # Keep the worker alive after one bad file.
                self._record_error(
                    f"Monitor worker failed: {type(error).__name__}: {error}"
                )
            finally:
                self._queue.task_done()

    def _process_request(self, request: _ScanRequest) -> None:
        path = request.path
        try:
            if self._is_ignored(path) or not self._is_monitored(path):
                return
            stability = self.check_stability(path)
            if not stability.stable:
                with self._lock:
                    self._stability_failures += 1
                    self._last_error = f"{path}: {stability.reason}"
                return
            try:
                result = self.scanner.scan_file(
                    path,
                    ScanSource.FILE_MONITOR,
                    scan_type=ScanType.REAL_TIME,
                )
            except Exception as error:
                with self._lock:
                    self._scan_failures += 1
                    self._last_error = (
                        f"Scan dispatch failed for {path}: {type(error).__name__}: {error}"
                    )
                return
            with self._lock:
                self._scans_dispatched += 1
            if self._on_scan_result is not None:
                try:
                    self._on_scan_result(result, request.event_type)
                except Exception as error:
                    # Notification/presentation observers are advisory. A toast
                    # failure must never turn a successful security scan into a
                    # File Monitor failure.
                    monitor_logger().warning(
                        "File verdict observer failed path=%s: %s: %s",
                        path, type(error).__name__, error,
                    )
        finally:
            completed_at = self._clock()
            with self._lock:
                self._scheduled.discard(path)
                self._last_completed[path] = completed_at

    def _record_error(self, message: str) -> None:
        with self._lock: self._last_error = message
        monitor_logger().error("File monitor: %s", message)