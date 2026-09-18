"""Phase 12 application startup orchestration.

The future UI/main thread only coordinates services and opens the interface.
Startup scanning is dispatched to a background worker and is never executed
synchronously on that thread.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable

from app.cleanup_verifier import CleanupVerifier
from app.config import AppConfig
from app.database import Database
from app.detector import Detector
from app.file_monitor import FileMonitor, default_monitored_paths
from app.incidents import IncidentService
from app.logging_config import application_logger, configure_production_logging, shutdown_production_logging
from app.matching_cleanup import MatchingCopyCleanup
from app.quarantine import QuarantineService
from app.reappearance import ReappearanceWatch
from app.recovery import RecoveryService
from app.reports import ReportService
from app.scanner import Scanner
from app.scan_history import ScanHistory
from app.scheduler import ScanDispatch, ScanScheduler, ScheduleSettings, SchedulerBackend
from app.signatures import SignatureStore, load_signatures
from app.threat_trail import ThreatTrail
from app.usb_monitor import USBMonitor
from app.windows_notifications import FileVerdictNotifier


@dataclass(frozen=True)
class StartupSettings:
    schedule: ScheduleSettings = field(default_factory=ScheduleSettings)
    startup_quick_scan_enabled: bool = True
    scheduler_enabled: bool = True
    file_monitor_enabled: bool = True
    usb_monitor_enabled: bool | None = None  # None = Windows only.
    monitor_paths: tuple[Path, ...] | None = None
    quick_scan_paths: tuple[Path, ...] | None = None
    full_scan_paths: tuple[Path, ...] | None = None
    debounce_seconds: float = 1.0
    stability_seconds: float = 1.0
    usb_poll_seconds: float = 1.0
    windows_notifications_enabled: bool = True

    def __post_init__(self) -> None:
        if self.debounce_seconds < 0 or self.stability_seconds < 0:
            raise ValueError("monitor timing values must not be negative.")
        if self.usb_poll_seconds <= 0:
            raise ValueError("usb_poll_seconds must be greater than zero.")


@dataclass
class AutoGuardServices:
    config: AppConfig
    database: Database
    signatures: SignatureStore
    incidents: IncidentService
    threat_trail: ThreatTrail
    quarantine: QuarantineService
    matching_cleanup: MatchingCopyCleanup
    cleanup_verifier: CleanupVerifier
    reappearance: ReappearanceWatch
    recovery: RecoveryService
    reports: ReportService
    scanner: Scanner
    file_monitor: FileMonitor | object | None
    usb_monitor: USBMonitor | object | None
    scheduler: ScanScheduler
    notifications: FileVerdictNotifier
    startup_dispatch: ScanDispatch | None = None


@dataclass(frozen=True)
class ShutdownReport:
    scheduler_stopped: bool
    usb_monitor_stopped: bool
    file_monitor_stopped: bool
    errors: tuple[str, ...] = ()


class AutoGuardStartup:
    """Initialize, start, and gracefully stop AutoGuard runtime services."""

    def __init__(
        self,
        config: AppConfig | None = None,
        settings: StartupSettings = StartupSettings(),
        *,
        signature_loader: Callable[[], SignatureStore] = load_signatures,
        file_monitor_factory: Callable[..., object] = FileMonitor,
        usb_monitor_factory: Callable[..., object] = USBMonitor,
        scheduler_factory: Callable[..., ScanScheduler] = ScanScheduler,
        notification_factory: Callable[..., FileVerdictNotifier] = FileVerdictNotifier,
        apscheduler_factory: Callable[[], SchedulerBackend] | None = None,
    ) -> None:
        self.config = config if config is not None else AppConfig()
        self.settings = settings
        self.signature_loader = signature_loader
        self.file_monitor_factory = file_monitor_factory
        self.usb_monitor_factory = usb_monitor_factory
        self.scheduler_factory = scheduler_factory
        self.notification_factory = notification_factory
        self.apscheduler_factory = apscheduler_factory
        self.services: AutoGuardServices | None = None
        self._started = False

    def initialize(self) -> AutoGuardServices:
        """Create directories/database and construct every Phase 12 service once."""
        if self.services is not None:
            return self.services

        config = self.config
        config.create_directories()
        configure_production_logging(config.logs_dir)
        log = application_logger(); log.info("Initializing AutoGuard runtime at %s", config.data_dir)

        database = Database(config.database_path)
        database.initialize()
        signatures = self.signature_loader()
        incidents = IncidentService(database)
        trail = ThreatTrail(database)
        quarantine = QuarantineService(database, config.quarantine_dir, incidents)

        monitor_paths = self._configured_monitor_paths()
        quick_paths = self._configured_quick_paths(monitor_paths)
        full_paths = self._configured_full_paths(monitor_paths)
        download_paths = self._configured_download_paths(monitor_paths)
        notifications = self.notification_factory(
            download_paths, enabled=self.settings.windows_notifications_enabled
        )

        matching_cleanup = MatchingCopyCleanup(
            database, incidents, quarantine, trail,
            monitored_locations=monitor_paths,
        )
        cleanup_verifier = CleanupVerifier(
            database, incidents, quarantine,
            monitored_locations=monitor_paths,
        )
        reappearance = ReappearanceWatch(database, incidents)
        detector = Detector(signatures)
        recovery = RecoveryService(database, quarantine, detector, incidents)
        history = ScanHistory(database)
        reports = ReportService(history, incidents, quarantine, cleanup_verifier, recovery)
        scanner = Scanner(
            detector, trail,
            max_file_size_bytes=config.max_file_size_bytes,
            history=history,
            incidents=incidents,
            quarantine=quarantine,
            matching_cleanup=matching_cleanup,
            cleanup_verifier=cleanup_verifier,
            reappearance=reappearance,
        )

        file_monitor: object | None = None
        if self.settings.file_monitor_enabled:
            file_monitor = self.file_monitor_factory(
                scanner,
                monitor_paths,
                ignored_paths=(config.quarantine_dir, config.database_dir, config.logs_dir),
                debounce_seconds=self.settings.debounce_seconds,
                stability_period_seconds=self.settings.stability_seconds,
                on_scan_result=notifications.handle_scan_result,
            )

        usb_monitor: object | None = None
        if self._usb_enabled():
            usb_monitor = self.usb_monitor_factory(
                scanner,
                poll_interval_seconds=self.settings.usb_poll_seconds,
            )

        scheduler = self.scheduler_factory(
            scanner,
            quick_paths=quick_paths,
            full_paths=full_paths,
            settings=self.settings.schedule,
            scheduler_factory=self.apscheduler_factory,
        )

        application_logger().info("AutoGuard services initialized; signatures=%d monitor_paths=%s", len(signatures), [str(p) for p in monitor_paths])
        self.services = AutoGuardServices(
            config=config,
            database=database,
            signatures=signatures,
            incidents=incidents,
            threat_trail=trail,
            quarantine=quarantine,
            matching_cleanup=matching_cleanup,
            cleanup_verifier=cleanup_verifier,
            reappearance=reappearance,
            recovery=recovery,
            reports=reports,
            scanner=scanner,
            file_monitor=file_monitor,
            usb_monitor=usb_monitor,
            scheduler=scheduler,
            notifications=notifications,
        )
        return self.services

    def start(
        self,
        interface: Callable[[AutoGuardServices], None] | None = None,
    ) -> AutoGuardServices:
        """Start background services, dispatch startup scan, then open interface.

        ``interface`` executes on the calling/main thread only after the startup
        scan has been *dispatched*. AutoGuard never waits for that scan before
        invoking the interface.
        """
        services = self.initialize()
        if self._started:
            if interface is not None:
                interface(services)
            return services

        if services.file_monitor is not None:
            services.file_monitor.start(); application_logger().info("File monitor started")
        if services.usb_monitor is not None:
            services.usb_monitor.start(); application_logger().info("USB monitor started")
        if self.settings.scheduler_enabled:
            services.scheduler.start(); application_logger().info("Scheduler started")
        if self.settings.startup_quick_scan_enabled:
            services.startup_dispatch = services.scheduler.dispatch_startup_scan(); application_logger().info("Startup quick scan dispatched")

        self._started = True
        if interface is not None:
            interface(services)
        return services

    def shutdown(self, *, timeout: float = 5.0) -> ShutdownReport:
        """Stop recurring work and monitors without letting one failure block others."""
        services = self.services
        if services is None:
            return ShutdownReport(True, True, True)

        errors: list[str] = []
        scheduler_stopped = True
        usb_stopped = True
        file_stopped = True

        try:
            services.scheduler.stop(wait=True, timeout=timeout)
        except Exception as error:
            scheduler_stopped = False
            errors.append(f"scheduler: {type(error).__name__}: {error}")

        if services.usb_monitor is not None:
            try:
                services.usb_monitor.stop(timeout=timeout)
            except TypeError:  # Small test/mocked service may expose stop() only.
                try:
                    services.usb_monitor.stop()
                except Exception as error:
                    usb_stopped = False
                    errors.append(f"usb_monitor: {type(error).__name__}: {error}")
            except Exception as error:
                usb_stopped = False
                errors.append(f"usb_monitor: {type(error).__name__}: {error}")

        if services.file_monitor is not None:
            try:
                services.file_monitor.stop(timeout=timeout)
            except TypeError:
                try:
                    services.file_monitor.stop()
                except Exception as error:
                    file_stopped = False
                    errors.append(f"file_monitor: {type(error).__name__}: {error}")
            except Exception as error:
                file_stopped = False
                errors.append(f"file_monitor: {type(error).__name__}: {error}")

        self._started = False
        report = ShutdownReport(
            scheduler_stopped=scheduler_stopped,
            usb_monitor_stopped=usb_stopped,
            file_monitor_stopped=file_stopped,
            errors=tuple(errors),
        )
        if errors: application_logger().error("Shutdown completed with errors: %s", errors)
        else: application_logger().info("AutoGuard shutdown completed cleanly")
        shutdown_production_logging(); return report

    def _usb_enabled(self) -> bool:
        value = self.settings.usb_monitor_enabled
        return os.name == "nt" if value is None else bool(value)

    def _configured_monitor_paths(self) -> tuple[Path, ...]:
        return (
            tuple(self.settings.monitor_paths)
            if self.settings.monitor_paths is not None
            else default_monitored_paths()
        )


    def _configured_download_paths(self, monitor_paths: tuple[Path, ...]) -> tuple[Path, ...]:
        """Return roots eligible for clean-file download verdict notifications.

        The default monitor ordering is Downloads, Desktop, Documents. For a
        custom monitor configuration, only roots explicitly named Downloads are
        treated as download locations; suspicious/confirmed notifications still
        apply everywhere the File Monitor scans.
        """
        if self.settings.monitor_paths is None:
            return monitor_paths[:1]
        return tuple(path for path in monitor_paths if path.name.casefold() == "downloads")

    def _configured_quick_paths(self, monitor_paths: tuple[Path, ...]) -> tuple[Path, ...]:
        return (
            tuple(self.settings.quick_scan_paths)
            if self.settings.quick_scan_paths is not None
            else monitor_paths
        )

    def _configured_full_paths(self, monitor_paths: tuple[Path, ...]) -> tuple[Path, ...]:
        # Phase 12 treats "full" as the complete configured protected scope.
        # Broader whole-disk targets can be supplied later through configuration/UI.
        return (
            tuple(self.settings.full_scan_paths)
            if self.settings.full_scan_paths is not None
            else monitor_paths
        )