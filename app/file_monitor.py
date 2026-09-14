from __future__ import annotations

import os, queue, stat, threading, time
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Callable, Iterable, Protocol

from app.hashing import normalize_path
from app.models import ScanSource, ScanType
from app.scanner import Scanner

try:
    from watchdog.events import FileSystemEventHandler
    from watchdog.observers import Observer
except ImportError:
    class FileSystemEventHandler: pass
    Observer = None

class ObserverProtocol(Protocol):
    def schedule(self, event_handler, path: str, recursive: bool = True): ...
    def start(self) -> None: ...
    def stop(self) -> None: ...
    def join(self, timeout: float | None = None) -> None: ...
    def is_alive(self) -> bool: ...

class MonitorStatus(str, Enum):
    STOPPED = "STOPPED"; RUNNING = "RUNNING"; DEGRADED = "DEGRADED"

@dataclass(frozen=True)
class StabilityResult:
    stable: bool; reason: str; size_bytes: int | None = None; mtime_ns: int | None = None

@dataclass(frozen=True)
class MonitorHealth:
    status: MonitorStatus; running: bool; observer_alive: bool; workers_alive: int
    monitored_paths: tuple[str, ...]; scheduled_paths: tuple[str, ...]; queue_depth: int
    events_received: int; events_queued: int; events_debounced: int; scans_dispatched: int
    stability_failures: int; scan_failures: int; last_error: str | None

@dataclass(frozen=True)
class _ScanRequest:
    path: Path; event_type: str; queued_at: float

_STOP = object()

def default_monitored_paths(home: str | Path | None = None) -> tuple[Path, ...]:
    root = Path.home() if home is None else Path(home).expanduser()
    return tuple(normalize_path(root / name) for name in ("Downloads", "Desktop", "Documents"))

class _WatchdogHandler(FileSystemEventHandler):
    def __init__(self, monitor: FileMonitor) -> None:
        super().__init__(); self.monitor = monitor
    def on_created(self, event) -> None: self.monitor.handle_event("created", event.src_path, is_directory=event.is_directory)
    def on_modified(self, event) -> None: self.monitor.handle_event("modified", event.src_path, is_directory=event.is_directory)
    def on_moved(self, event) -> None: self.monitor.handle_event("moved", event.src_path, dest_path=event.dest_path, is_directory=event.is_directory)

class FileMonitor:
    def __init__(self, scanner: Scanner, monitored_paths: Iterable[str | Path] | None = None, *, ignored_paths: Iterable[str | Path] = (), debounce_seconds: float = 1.0, stability_period_seconds: float = 1.0, stability_poll_seconds: float = 0.25, stability_timeout_seconds: float = 30.0, worker_count: int = 1, observer_factory: Callable[[], ObserverProtocol] | None = None, clock: Callable[[], float] = time.monotonic, sleep: Callable[[float], None] = time.sleep, stat_func: Callable[[Path], os.stat_result] | None = None) -> None:
        if debounce_seconds < 0: raise ValueError("debounce_seconds must be nonnegative.")
        if stability_period_seconds < 0: raise ValueError("stability_period_seconds must be nonnegative.")
        if stability_poll_seconds <= 0: raise ValueError("stability_poll_seconds must be greater than zero.")
        if stability_timeout_seconds < stability_period_seconds: raise ValueError("stability_timeout_seconds must be at least stability_period_seconds.")
        if type(worker_count) is not int or worker_count <= 0: raise ValueError("worker_count must be a positive integer.")
        self.scanner, roots = scanner, default_monitored_paths() if monitored_paths is None else tuple(monitored_paths)
        self._monitored_paths, self._ignored_paths = self._deduplicate_roots(roots), self._deduplicate_roots(ignored_paths)
        self.debounce_seconds, self.stability_period_seconds = float(debounce_seconds), float(stability_period_seconds)
        self.stability_poll_seconds, self.stability_timeout_seconds = float(stability_poll_seconds), float(stability_timeout_seconds)
        self.worker_count, self._observer_factory, self._clock, self._sleep = worker_count, observer_factory, clock, sleep
        self._stat = stat_func if stat_func is not None else lambda path: path.stat()
        self._queue: queue.Queue[_ScanRequest | object] = queue.Queue()
        self._lock, self._scheduled, self._last_completed = threading.Lock(), set(), {}
        self._observer, self._handler, self._workers, self._running = None, _WatchdogHandler(self), [], False
        self._scheduled_roots, self._last_error = (), None
        self._events_received = self._events_queued = self._events_debounced = self._scans_dispatched = self._stability_failures = self._scan_failures = 0

    @staticmethod
    def _deduplicate_roots(paths: Iterable[str | Path]) -> tuple[Path, ...]:
        unique: list[Path] = []
        for raw in paths:
            if (path := normalize_path(raw)) not in unique: unique.append(path)
        return tuple(unique)

    def monitored_paths(self) -> tuple[Path, ...]: return self._monitored_paths
    def ignored_paths(self) -> tuple[Path, ...]: return self._ignored_paths
    def status(self) -> MonitorStatus: return self.health().status

    def health(self) -> MonitorHealth:
        observer_alive, workers_alive = bool(self._observer and self._safe_observer_alive(self._observer)), sum(w.is_alive() for w in self._workers)
        with self._lock: running, last_error, counters = self._running, self._last_error, (self._events_received, self._events_queued, self._events_debounced, self._scans_dispatched, self._stability_failures, self._scan_failures)
        if not running: status = MonitorStatus.STOPPED
        elif last_error is not None or not observer_alive or workers_alive < self.worker_count: status = MonitorStatus.DEGRADED
        else: status = MonitorStatus.RUNNING
        return MonitorHealth(status=status, running=running, observer_alive=observer_alive, workers_alive=workers_alive, monitored_paths=tuple(str(p) for p in self._monitored_paths), scheduled_paths=tuple(str(p) for p in self._scheduled_roots), queue_depth=self._queue.qsize(), events_received=counters[0], events_queued=counters[1], events_debounced=counters[2], scans_dispatched=counters[3], stability_failures=counters[4], scan_failures=counters[5], last_error=last_error)

    @staticmethod
    def _safe_observer_alive(observer: ObserverProtocol) -> bool:
        try: return observer.is_alive()
        except Exception: return False

    def start(self) -> MonitorHealth:
        with self._lock:
            if self._running: return self.health()
        if self._observer_factory is not None: observer = self._observer_factory()
        else:
            if Observer is None: raise RuntimeError("watchdog is required for real-time monitoring. Install project dependencies with: python -m pip install -r requirements.txt")
            observer = Observer()
        scheduled = []
        for root in self._monitored_paths:
            if root.exists() and root.is_dir(): observer.schedule(self._handler, str(root), recursive=True); scheduled.append(root)
        if not scheduled: raise ValueError("None of the configured monitored directories currently exist.")
        self._observer, self._scheduled_roots = observer, tuple(scheduled)
        self._workers = [threading.Thread(target=self._worker_loop, name=f"AutoGuardFileMonitor-{i + 1}", daemon=True) for i in range(self.worker_count)]
        with self._lock: self._running, self._last_error = True, None
        for worker in self._workers: worker.start()
        try: observer.start()
        except Exception:
            with self._lock: self._running = False
            for _ in self._workers: self._queue.put(_STOP)
            for worker in self._workers: worker.join(timeout=1.0)
            self._workers.clear(); self._observer, self._scheduled_roots = None, (); raise
        return self.health()

    def stop(self, timeout: float = 5.0) -> MonitorHealth:
        if timeout < 0: raise ValueError("timeout must be nonnegative.")
        with self._lock:
            was_running, self._running = self._running, False
        if not was_running and self._observer is None and not self._workers: return self.health()
        if (observer := self._observer) is not None:
            try: observer.stop(); observer.join(timeout=timeout)
            except Exception as error: self._record_error(f"Observer stop failed: {type(error).__name__}: {error}")
        for _ in self._workers: self._queue.put(_STOP)
        for worker in self._workers: worker.join(timeout=timeout)
        self._workers.clear(); self._observer, self._scheduled_roots = None, (); return self.health()

    def handle_event(self, event_type: str, src_path: str | Path, *, dest_path: str | Path | None = None, is_directory: bool = False) -> bool:
        with self._lock: self._events_received += 1
        if is_directory or (event_type := event_type.lower()) not in {"created", "modified", "moved"}: return False
        return False if (candidate := dest_path if event_type == "moved" else src_path) is None else self.queue_path(candidate, event_type=event_type)

    def queue_path(self, path: str | Path, *, event_type: str = "created") -> bool:
        candidate = normalize_path(path)
        if not self._is_monitored(candidate) or self._is_ignored(candidate): return False
        now = self._clock()
        with self._lock:
            if candidate in self._scheduled or ((last := self._last_completed.get(candidate)) is not None and now - last < self.debounce_seconds):
                self._events_debounced += 1; return False
            self._scheduled.add(candidate); self._events_queued += 1
        self._queue.put(_ScanRequest(candidate, event_type, now)); return True

    def _is_monitored(self, path: Path) -> bool: return any(path == root or root in path.parents for root in self._monitored_paths)
    def _is_ignored(self, path: Path) -> bool: return any(path == root or root in path.parents for root in self._ignored_paths)

    def check_stability(self, path: str | Path) -> StabilityResult:
        candidate, started, stable_since, previous = normalize_path(path), self._clock(), None, None
        while True:
            now = self._clock()
            try: info = self._stat(candidate)
            except FileNotFoundError: return StabilityResult(False, "File no longer exists.")
            except (PermissionError, OSError) as error: return StabilityResult(False, f"File cannot be checked: {type(error).__name__}: {error}")
            if (mode := getattr(info, "st_mode", None)) is not None and not stat.S_ISREG(mode): return StabilityResult(False, "Path is not a regular file.")
            signature = (int(info.st_size), int(info.st_mtime_ns))
            if signature != previous: previous, stable_since = signature, now
            elif stable_since is not None and now - stable_since >= self.stability_period_seconds: return StabilityResult(True, "File size and modification time are stable.", *signature)
            if self.stability_period_seconds == 0: return StabilityResult(True, "Stability delay is disabled.", *signature)
            if now - started >= self.stability_timeout_seconds: return StabilityResult(False, "File did not become stable before the stability timeout.", *signature)
            self._sleep(min(self.stability_poll_seconds, self.stability_timeout_seconds - (now - started)))

    def process_pending_once(self, timeout: float = 0.0) -> bool:
        try: item = self._queue.get(timeout=timeout)
        except queue.Empty: return False
        if item is _STOP: self._queue.task_done(); return False
        assert isinstance(item, _ScanRequest)
        try: self._process_request(item)
        finally: self._queue.task_done()
        return True

    def _worker_loop(self) -> None:
        while True:
            item = self._queue.get()
            try:
                if item is _STOP: return
                assert isinstance(item, _ScanRequest); self._process_request(item)
            except Exception as error: self._record_error(f"Monitor worker failed: {type(error).__name__}: {error}")
            finally: self._queue.task_done()

    def _process_request(self, request: _ScanRequest) -> None:
        path = request.path
        try:
            if self._is_ignored(path) or not self._is_monitored(path): return
            if not (stability := self.check_stability(path)).stable:
                with self._lock: self._stability_failures += 1; self._last_error = f"{path}: {stability.reason}"
                return
            try: self.scanner.scan_file(path, ScanSource.FILE_MONITOR, scan_type=ScanType.REAL_TIME)
            except Exception as error:
                with self._lock: self._scan_failures += 1; self._last_error = f"Scan dispatch failed for {path}: {type(error).__name__}: {error}"
                return
            with self._lock: self._scans_dispatched += 1
        finally:
            completed_at = self._clock()
            with self._lock: self._scheduled.discard(path); self._last_completed[path] = completed_at

    def _record_error(self, message: str) -> None:
        with self._lock: self._last_error = message