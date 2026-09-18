"""Background startup and scheduled scan dispatch for AutoGuard.

APScheduler owns recurring timers. AutoGuard still keeps its own scan gate so a
quick/full scan cannot overlap another scan of the same logical type even when
one was launched outside APScheduler (for example the startup quick scan).
"""

from __future__ import annotations

import threading
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Callable, Iterable, Protocol

from app.hashing import normalize_path
from app.models import ScanSource, ScanSummary, ScanType
from app.scanner import ScanInterruptedError, Scanner

try:  # Runtime dependency. Tests inject a deterministic APScheduler-compatible fake.
    from apscheduler.schedulers.background import BackgroundScheduler
except ImportError:  # pragma: no cover - depends on the runtime environment.
    BackgroundScheduler = None  # type: ignore[assignment]


class SchedulerBackend(Protocol):
    def add_job(self, func, trigger: str, **kwargs): ...
    def start(self) -> None: ...
    def shutdown(self, wait: bool = True) -> None: ...


class ScanKind(str, Enum):
    QUICK = "quick"
    FULL = "full"


class DispatchStatus(str, Enum):
    DISPATCHED = "DISPATCHED"
    SKIPPED_ALREADY_RUNNING = "SKIPPED_ALREADY_RUNNING"


@dataclass(frozen=True)
class ScheduleSettings:
    quick_interval_hours: float = 24.0
    full_interval_days: float = 7.0

    def __post_init__(self) -> None:
        if self.quick_interval_hours <= 0:
            raise ValueError("quick_interval_hours must be greater than zero.")
        if self.full_interval_days <= 0:
            raise ValueError("full_interval_days must be greater than zero.")


@dataclass(frozen=True)
class ScanBatchResult:
    kind: ScanKind
    source: ScanSource
    scan_type: ScanType
    started_at: datetime
    finished_at: datetime
    summaries: tuple[ScanSummary, ...]
    skipped_paths: tuple[str, ...]
    errors: tuple[str, ...]
    interrupted: bool = False


@dataclass(frozen=True)
class ScanDispatch:
    status: DispatchStatus
    kind: ScanKind
    thread_name: str | None = None

    @property
    def accepted(self) -> bool:
        return self.status is DispatchStatus.DISPATCHED


@dataclass(frozen=True)
class SchedulerHealth:
    running: bool
    quick_scan_running: bool
    full_scan_running: bool
    background_workers: int
    completed_batches: int
    last_error: str | None


class ScanExecutionGate:
    """Thread-safe same-kind overlap prevention shared by startup and schedules."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._active: set[ScanKind] = set()

    def try_acquire(self, kind: ScanKind) -> bool:
        kind = ScanKind(kind)
        with self._lock:
            if kind in self._active:
                return False
            self._active.add(kind)
            return True

    def release(self, kind: ScanKind) -> None:
        with self._lock:
            self._active.discard(ScanKind(kind))

    def is_running(self, kind: ScanKind) -> bool:
        with self._lock:
            return ScanKind(kind) in self._active


class ScanScheduler:
    """Run startup, quick, and full scans outside the caller/UI thread."""

    QUICK_JOB_ID = "autoguard_quick_scan"
    FULL_JOB_ID = "autoguard_full_scan"

    def __init__(
        self,
        scanner: Scanner,
        *,
        quick_paths: Iterable[str | Path],
        full_paths: Iterable[str | Path],
        settings: ScheduleSettings = ScheduleSettings(),
        gate: ScanExecutionGate | None = None,
        scheduler_factory: Callable[[], SchedulerBackend] | None = None,
        thread_factory: Callable[..., threading.Thread] = threading.Thread,
    ) -> None:
        self.scanner = scanner
        self.quick_paths = self._normalize_targets(quick_paths)
        self.full_paths = self._normalize_targets(full_paths)
        self.settings = settings
        self.gate = gate if gate is not None else ScanExecutionGate()
        self._scheduler_factory = scheduler_factory
        self._thread_factory = thread_factory
        self._backend: SchedulerBackend | None = None
        self._lock = threading.RLock()
        self._workers: set[threading.Thread] = set()
        self._shutdown_event = threading.Event()
        self._running = False
        self._completed: list[ScanBatchResult] = []
        self._last_error: str | None = None

    @staticmethod
    def _normalize_targets(paths: Iterable[str | Path]) -> tuple[Path, ...]:
        unique: list[Path] = []
        for raw in paths:
            path = normalize_path(raw)
            if path not in unique:
                unique.append(path)
        return tuple(unique)

    def start(self) -> SchedulerHealth:
        """Start APScheduler. Jobs first run after their configured interval."""
        with self._lock:
            if self._running:
                return self.health()
            factory = self._scheduler_factory
            if factory is None:
                if BackgroundScheduler is None:
                    raise RuntimeError(
                        "APScheduler is required for Phase 12 scheduling. "
                        "Install dependencies with: pip install -r requirements.txt"
                    )
                factory = BackgroundScheduler
            backend = factory()
            backend.add_job(
                self.dispatch_quick_scan,
                "interval",
                hours=self.settings.quick_interval_hours,
                id=self.QUICK_JOB_ID,
                replace_existing=True,
                max_instances=1,
                coalesce=True,
            )
            backend.add_job(
                self.dispatch_full_scan,
                "interval",
                days=self.settings.full_interval_days,
                id=self.FULL_JOB_ID,
                replace_existing=True,
                max_instances=1,
                coalesce=True,
            )
            backend.start()
            self._backend = backend
            self._running = True
            self._shutdown_event.clear()
            self._last_error = None
        return self.health()

    def stop(self, *, wait: bool = True, timeout: float = 5.0) -> SchedulerHealth:
        """Stop future jobs and request interruption of AutoGuard-owned scan workers."""
        if timeout < 0:
            raise ValueError("timeout must be nonnegative.")
        with self._lock:
            self._running = False
            backend = self._backend
            self._backend = None
        self._shutdown_event.set()
        if backend is not None:
            try:
                backend.shutdown(wait=wait)
            except Exception as error:  # Scheduler shutdown must not strand other services.
                with self._lock:
                    self._last_error = f"{type(error).__name__}: {error}"
        if wait:
            current = threading.current_thread()
            with self._lock:
                workers = tuple(self._workers)
            for worker in workers:
                if worker is not current:
                    worker.join(timeout=timeout)
        return self.health()

    def dispatch_startup_scan(self) -> ScanDispatch:
        """Launch the startup quick scan using STARTUP history metadata."""
        return self._dispatch(
            ScanKind.QUICK,
            self.quick_paths,
            source=ScanSource.STARTUP,
            scan_type=ScanType.STARTUP,
            thread_name="AutoGuardStartupQuickScan",
        )

    def dispatch_quick_scan(self) -> ScanDispatch:
        """Launch a scheduled quick scan without overlapping another quick scan."""
        return self._dispatch(
            ScanKind.QUICK,
            self.quick_paths,
            source=ScanSource.SCHEDULED,
            scan_type=ScanType.QUICK,
            thread_name="AutoGuardScheduledQuickScan",
        )

    def dispatch_full_scan(self) -> ScanDispatch:
        """Launch a scheduled full scan without overlapping another full scan."""
        return self._dispatch(
            ScanKind.FULL,
            self.full_paths,
            source=ScanSource.SCHEDULED,
            scan_type=ScanType.FULL,
            thread_name="AutoGuardScheduledFullScan",
        )

    def _dispatch(
        self,
        kind: ScanKind,
        targets: tuple[Path, ...],
        *,
        source: ScanSource,
        scan_type: ScanType,
        thread_name: str,
    ) -> ScanDispatch:
        if not self.gate.try_acquire(kind):
            return ScanDispatch(DispatchStatus.SKIPPED_ALREADY_RUNNING, kind)

        def runner() -> None:
            try:
                self._run_batch(kind, targets, source=source, scan_type=scan_type)
            finally:
                self.gate.release(kind)
                with self._lock:
                    self._workers.discard(threading.current_thread())

        thread = self._thread_factory(target=runner, name=thread_name, daemon=True)
        with self._lock:
            self._workers.add(thread)
        try:
            thread.start()
        except Exception:
            with self._lock:
                self._workers.discard(thread)
            self.gate.release(kind)
            raise
        return ScanDispatch(DispatchStatus.DISPATCHED, kind, thread.name)

    def _run_batch(
        self,
        kind: ScanKind,
        targets: tuple[Path, ...],
        *,
        source: ScanSource,
        scan_type: ScanType,
    ) -> ScanBatchResult:
        started = datetime.now(timezone.utc)
        summaries: list[ScanSummary] = []
        skipped: list[str] = []
        errors: list[str] = []
        interrupted = False
        for target in targets:
            if self._shutdown_event.is_set():
                interrupted = True
                break
            if not target.exists():
                skipped.append(str(target))
                continue
            try:
                summaries.append(
                    self.scanner.scan(
                        target,
                        source,
                        scan_type=scan_type,
                        interrupt_check=self._shutdown_event.is_set,
                    )
                )
            except ScanInterruptedError as error:
                interrupted = True
                errors.append(f"{target}: {error}")
                break
            except Exception as error:
                errors.append(f"{target}: {type(error).__name__}: {error}")

        result = ScanBatchResult(
            kind=kind,
            source=source,
            scan_type=scan_type,
            started_at=started,
            finished_at=datetime.now(timezone.utc),
            summaries=tuple(summaries),
            skipped_paths=tuple(skipped),
            errors=tuple(errors),
            interrupted=interrupted,
        )
        with self._lock:
            self._completed.append(result)
            if errors:
                self._last_error = errors[-1]
        return result

    def health(self) -> SchedulerHealth:
        with self._lock:
            running = self._running
            workers = sum(worker.is_alive() for worker in self._workers)
            completed = len(self._completed)
            last_error = self._last_error
        return SchedulerHealth(
            running=running,
            quick_scan_running=self.gate.is_running(ScanKind.QUICK),
            full_scan_running=self.gate.is_running(ScanKind.FULL),
            background_workers=workers,
            completed_batches=completed,
            last_error=last_error,
        )

    def next_run_times(self) -> dict[str, datetime | None]:
        """Return APScheduler's next quick/full run times without changing jobs.

        The tray and other presentation layers use this read-only snapshot. Test
        backends from older phases may not implement ``get_job``; in that case
        the schedule remains valid but the exact next timestamp is unavailable.
        """
        with self._lock:
            backend = self._backend
            running = self._running
        result: dict[str, datetime | None] = {"quick": None, "full": None}
        if not running or backend is None:
            return result
        get_job = getattr(backend, "get_job", None)
        if not callable(get_job):
            return result
        for key, job_id in (("quick", self.QUICK_JOB_ID), ("full", self.FULL_JOB_ID)):
            try:
                job = get_job(job_id)
                value = getattr(job, "next_run_time", None) if job is not None else None
                if isinstance(value, datetime):
                    result[key] = value
            except Exception:
                # Exact display time is optional presentation data; scheduling
                # continues to be owned by APScheduler even if introspection fails.
                continue
        return result

    def completed_batches(self) -> tuple[ScanBatchResult, ...]:
        with self._lock:
            return tuple(self._completed)