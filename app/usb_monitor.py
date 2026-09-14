from __future__ import annotations
import os, queue, threading, time
from collections import deque
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Callable, Iterable, Protocol
from app.hashing import normalize_path
from app.models import ScanSessionStatus, ScanSource, ScanType
from app.scanner import ScanInterruptedError, Scanner

@dataclass(frozen=True)
class RemovableDrive:
    root: Path; device_id: str; label: str | None = None
    def __post_init__(self) -> None:
        object.__setattr__(self, "root", normalize_path(self.root))
        if not self.device_id.strip(): raise ValueError("device_id must not be empty.")
    @property
    def key(self) -> str: return self.device_id.casefold()

class DriveDiscovery(Protocol):
    def list_drives(self) -> tuple[RemovableDrive, ...]: ...

class WindowsRemovableDriveDiscovery:
    DRIVE_REMOVABLE = 2
    def list_drives(self) -> tuple[RemovableDrive, ...]:
        if os.name != "nt": return ()
        try: import ctypes
        except ImportError: return ()
        try: kernel32 = ctypes.windll.kernel32; mask = int(kernel32.GetLogicalDrives())
        except Exception: return ()
        drives: list[RemovableDrive] = []
        for index in range(26):
            if not (mask & (1 << index)): continue
            root_text = f"{chr(ord('A') + index)}:\\"
            try:
                if int(kernel32.GetDriveTypeW(root_text)) != self.DRIVE_REMOVABLE: continue
            except Exception: continue
            label, serial = self._volume_info(kernel32, root_text)
            identity = f"windows-volume:{serial:08x}" if serial is not None else f"windows-root:{root_text.casefold()}"
            drives.append(RemovableDrive(Path(root_text), identity, label))
        return tuple(drives)
    @staticmethod
    def _volume_info(kernel32, root_text: str) -> tuple[str | None, int | None]:
        try:
            import ctypes
            label_buf, fs_buf = ctypes.create_unicode_buffer(261), ctypes.create_unicode_buffer(261)
            serial, max_len, flags = ctypes.c_uint32(), ctypes.c_uint32(), ctypes.c_uint32()
            if not kernel32.GetVolumeInformationW(root_text, label_buf, len(label_buf), ctypes.byref(serial), ctypes.byref(max_len), ctypes.byref(flags), fs_buf, len(fs_buf)): return None, None
            return label_buf.value or None, int(serial.value)
        except Exception: return None, None

class USBEventType(str, Enum):
    USB_DETECTED = "USB_DETECTED"; SCAN_STARTED = "SCAN_STARTED"; SCAN_COMPLETED = "SCAN_COMPLETED"
    DEVICE_REMOVED = "DEVICE_REMOVED"; SCAN_INTERRUPTED = "SCAN_INTERRUPTED"; SCAN_FAILED = "SCAN_FAILED"

@dataclass(frozen=True)
class USBMonitorEvent:
    sequence: int; event_type: USBEventType; occurred_at: datetime; drive_id: str; drive_root: str; insertion_number: int; session_id: str | None; message: str

@dataclass(frozen=True)
class USBScanOutcome:
    drive_id: str; drive_root: str; insertion_number: int; session_id: str | None; status: ScanSessionStatus; message: str

class USBMonitorStatus(str, Enum):
    STOPPED = "STOPPED"; RUNNING = "RUNNING"; DEGRADED = "DEGRADED"

@dataclass(frozen=True)
class USBMonitorHealth:
    status: USBMonitorStatus; running: bool; poller_alive: bool; workers_alive: int; drives_present: tuple[str, ...]; queue_depth: int; drives_detected: int; devices_removed: int; scans_queued: int; scans_started: int; scans_completed: int; scans_interrupted: int; scan_failures: int; last_error: str | None

@dataclass(frozen=True)
class _DriveScanRequest:
    drive: RemovableDrive; insertion_number: int; removal_event: threading.Event

_STOP = object()

class USBMonitor:
    def __init__(self, scanner: Scanner, discovery: DriveDiscovery | None = None, *, poll_interval_seconds: float = 1.0, worker_count: int = 1, scan_once_per_insertion: bool = True, event_callback: Callable[[USBMonitorEvent], None] | None = None, event_history_limit: int = 500, clock: Callable[[], float] = time.monotonic, sleep: Callable[[float], None] = time.sleep) -> None:
        if poll_interval_seconds <= 0: raise ValueError("poll_interval_seconds must be greater than zero.")
        if type(worker_count) is not int or worker_count <= 0: raise ValueError("worker_count must be a positive integer.")
        if type(event_history_limit) is not int or event_history_limit <= 0: raise ValueError("event_history_limit must be a positive integer.")
        self.scanner, self.discovery = scanner, discovery if discovery is not None else WindowsRemovableDriveDiscovery()
        self.poll_interval_seconds, self.worker_count, self.scan_once_per_insertion = float(poll_interval_seconds), worker_count, bool(scan_once_per_insertion)
        self._event_callback, self._clock, self._sleep = event_callback, clock, sleep
        self._queue: queue.Queue[_DriveScanRequest | object] = queue.Queue()
        self._lock, self._stop_event = threading.RLock(), threading.Event()
        self._poller, self._workers, self._running = None, [], False
        self._present, self._insertion_counters = {}, {}
        self._queued_or_active, self._completed_insertions = set(), set()
        self._events, self._outcomes = deque(maxlen=event_history_limit), deque(maxlen=event_history_limit)
        self._event_sequence = self._drives_detected = self._devices_removed = self._scans_queued = self._scans_started = self._scans_completed = self._scans_interrupted = self._scan_failures = 0
        self._last_error = None

    def start(self) -> USBMonitorHealth:
        with self._lock:
            if self._running: return self.health()
            self._running, self._last_error = True, None
            self._stop_event.clear()
        self._workers = [threading.Thread(target=self._worker_loop, name=f"AutoGuardUSBScan-{i+1}", daemon=True) for i in range(self.worker_count)]
        for w in self._workers: w.start()
        self._poller = threading.Thread(target=self._poll_loop, name="AutoGuardUSBDiscovery", daemon=True)
        self._poller.start()
        return self.health()

    def stop(self, timeout: float = 5.0) -> USBMonitorHealth:
        if timeout < 0: raise ValueError("timeout must be nonnegative.")
        with self._lock: self._running = False
        self._stop_event.set()
        if self._poller is not None: self._poller.join(timeout=timeout); self._poller = None
        for _ in self._workers: self._queue.put(_STOP)
        for w in self._workers: w.join(timeout=timeout)
        self._workers.clear()
        return self.health()

    def status(self) -> USBMonitorStatus: return self.health().status

    def health(self) -> USBMonitorHealth:
        with self._lock:
            running, last_error = self._running, self._last_error
            roots = tuple(str(item[0].root) for item in self._present.values())
            counters = (self._drives_detected, self._devices_removed, self._scans_queued, self._scans_started, self._scans_completed, self._scans_interrupted, self._scan_failures)
        poller_alive = bool(self._poller and self._poller.is_alive())
        workers_alive = sum(w.is_alive() for w in self._workers)
        if not running: status = USBMonitorStatus.STOPPED
        elif last_error is not None or not poller_alive or workers_alive < self.worker_count: status = USBMonitorStatus.DEGRADED
        else: status = USBMonitorStatus.RUNNING
        return USBMonitorHealth(status=status, running=running, poller_alive=poller_alive, workers_alive=workers_alive, drives_present=roots, queue_depth=self._queue.qsize(), drives_detected=counters[0], devices_removed=counters[1], scans_queued=counters[2], scans_started=counters[3], scans_completed=counters[4], scans_interrupted=counters[5], scan_failures=counters[6], last_error=last_error)

    def present_drives(self) -> tuple[RemovableDrive, ...]:
        with self._lock: return tuple(item[0] for item in self._present.values())

    def recent_events(self) -> tuple[USBMonitorEvent, ...]:
        with self._lock: return tuple(self._events)

    def recent_scan_outcomes(self) -> tuple[USBScanOutcome, ...]:
        with self._lock: return tuple(self._outcomes)

    def poll_once(self) -> tuple[RemovableDrive, ...]:
        try: discovered = tuple(self.discovery.list_drives())
        except Exception as error:
            self._record_error(f"Removable-drive discovery failed: {type(error).__name__}: {error}")
            return self.present_drives()
        current_by_key = {drive.key: drive for drive in discovered}
        with self._lock: previous_keys, current_keys = set(self._present), set(current_by_key)
        for key in previous_keys - current_keys:
            with self._lock: drive, insertion, removal_event = self._present.pop(key); self._devices_removed += 1
            removal_event.set()
            self._emit(USBEventType.DEVICE_REMOVED, drive, insertion, message="Removable drive is no longer mounted. Any active scan will be reported as interrupted/incomplete rather than treated as a crash.")
        for key, drive in current_by_key.items():
            with self._lock: existing = self._present.get(key)
            if existing is None:
                with self._lock:
                    insertion = self._insertion_counters.get(key, 0) + 1; self._insertion_counters[key] = insertion
                    removal_event = threading.Event(); self._present[key] = (drive, insertion, removal_event); self._drives_detected += 1
                self._emit(USBEventType.USB_DETECTED, drive, insertion, message="Removable drive detected. USB identifies the collection source only; it does not establish an infection origin.")
                self._queue_scan(drive, insertion, removal_event)
            else:
                _, insertion, removal_event = existing
                with self._lock: self._present[key] = (drive, insertion, removal_event)
                if not self.scan_once_per_insertion: self._queue_scan(drive, insertion, removal_event)
        return self.present_drives()

    def process_pending_once(self, timeout: float = 0.0) -> bool:
        try: item = self._queue.get(timeout=timeout)
        except queue.Empty: return False
        if item is _STOP: self._queue.task_done(); return False
        assert isinstance(item, _DriveScanRequest)
        try: self._process_request(item)
        finally: self._queue.task_done()
        return True

    def _queue_scan(self, drive: RemovableDrive, insertion_number: int, removal_event: threading.Event) -> bool:
        token = (drive.key, insertion_number)
        with self._lock:
            if token in self._queued_or_active or (self.scan_once_per_insertion and token in self._completed_insertions): return False
            self._queued_or_active.add(token); self._scans_queued += 1
        self._queue.put(_DriveScanRequest(drive, insertion_number, removal_event))
        return True

    def _poll_loop(self) -> None:
        while not self._stop_event.is_set():
            try: self.poll_once()
            except Exception as error: self._record_error(f"USB discovery loop failed: {type(error).__name__}: {error}")
            self._stop_event.wait(self.poll_interval_seconds)

    def _worker_loop(self) -> None:
        while True:
            item = self._queue.get()
            try:
                if item is _STOP: return
                assert isinstance(item, _DriveScanRequest); self._process_request(item)
            except Exception as error: self._record_error(f"USB scan worker failed: {type(error).__name__}: {error}")
            finally: self._queue.task_done()

    def _process_request(self, request: _DriveScanRequest) -> None:
        drive, insertion, token, session_id = request.drive, request.insertion_number, (request.drive.key, request.insertion_number), None
        try:
            if request.removal_event.is_set():
                self._record_interrupted(drive, insertion, None, "USB scan did not start because the drive was removed first.")
                return
            with self._lock: self._scans_started += 1
            self._emit(USBEventType.SCAN_STARTED, drive, insertion, message="Automatic USB scan started using the existing AutoGuard scanner pipeline.")
            try:
                summary = self.scanner.scan_directory(drive.root, ScanSource.USB, scan_type=ScanType.USB, interrupt_check=request.removal_event.is_set)
                session_id = summary.session_id
            except ScanInterruptedError as error:
                session_id = error.session_id; self._record_interrupted(drive, insertion, session_id, "USB scan was interrupted because the removable drive became unavailable.")
                return
            except Exception as error:
                session_id = getattr(error, "session_id", None)
                if request.removal_event.is_set():
                    self._ensure_session_incomplete(session_id, str(error))
                    self._record_interrupted(drive, insertion, session_id, f"USB scan was interrupted after device removal: {type(error).__name__}: {error}")
                    return
                with self._lock: self._scan_failures += 1; self._last_error = f"USB scan failed for {drive.root}: {type(error).__name__}: {error}"
                self._emit(USBEventType.SCAN_FAILED, drive, insertion, session_id=session_id, message=self._last_error)
                self._append_outcome(USBScanOutcome(drive.device_id, str(drive.root), insertion, session_id, ScanSessionStatus.FAILED, self._last_error))
                return
            status = self._session_status(session_id)
            if status is ScanSessionStatus.INCOMPLETE and request.removal_event.is_set():
                self._record_interrupted(drive, insertion, session_id, "USB scan session is incomplete because the drive was removed during scanning.")
                return
            if status is ScanSessionStatus.FAILED and request.removal_event.is_set():
                self._ensure_session_incomplete(session_id, "Drive removed while USB scan was active.")
                self._record_interrupted(drive, insertion, session_id, "USB scan failed after device removal and was reclassified as incomplete.")
                return
            effective_status = status or ScanSessionStatus.COMPLETED
            with self._lock: self._scans_completed += 1
            message = f"USB scan completed with session status {effective_status.value}. USB is recorded as the observation source only, not infection origin."
            self._emit(USBEventType.SCAN_COMPLETED, drive, insertion, session_id=session_id, message=message)
            self._append_outcome(USBScanOutcome(drive.device_id, str(drive.root), insertion, session_id, effective_status, message))
        finally:
            with self._lock: self._queued_or_active.discard(token); self._completed_insertions.add(token)

    def _record_interrupted(self, drive: RemovableDrive, insertion: int, session_id: str | None, message: str) -> None:
        self._ensure_session_incomplete(session_id, message)
        with self._lock: self._scans_interrupted += 1
        self._emit(USBEventType.SCAN_INTERRUPTED, drive, insertion, session_id=session_id, message=message)
        self._append_outcome(USBScanOutcome(drive.device_id, str(drive.root), insertion, session_id, ScanSessionStatus.INCOMPLETE, message))

    def _ensure_session_incomplete(self, session_id: str | None, reason: str) -> None:
        if not session_id: return
        history = getattr(self.scanner, "history", None); marker = getattr(history, "mark_interrupted", None)
        if marker is None: return
        try: marker(session_id, reason=reason)
        except Exception as error: self._record_error(f"Could not mark USB scan {session_id} incomplete: {type(error).__name__}: {error}")

    def _session_status(self, session_id: str | None) -> ScanSessionStatus | None:
        if not session_id: return None
        history = getattr(self.scanner, "history", None); getter = getattr(history, "get_scan", None)
        if getter is None: return None
        try: details = getter(session_id)
        except Exception: return None
        return details.session.status if details is not None else None

    def _emit(self, event_type: USBEventType, drive: RemovableDrive, insertion_number: int, *, session_id: str | None = None, message: str) -> USBMonitorEvent:
        with self._lock:
            self._event_sequence += 1
            event = USBMonitorEvent(sequence=self._event_sequence, event_type=USBEventType(event_type), occurred_at=datetime.now(timezone.utc), drive_id=drive.device_id, drive_root=str(drive.root), insertion_number=insertion_number, session_id=session_id, message=message)
            self._events.append(event)
        if self._event_callback is not None:
            try: self._event_callback(event)
            except Exception as error: self._record_error(f"USB event callback failed: {type(error).__name__}: {error}")
        return event

    def _append_outcome(self, outcome: USBScanOutcome) -> None:
        with self._lock: self._outcomes.append(outcome)

    def _record_error(self, message: str) -> None:
        with self._lock: self._last_error = message