from __future__ import annotations

import argparse, json, threading, time
from pathlib import Path

from app.config import AppConfig
from app.scheduler import ScheduleSettings
from app.startup import AutoGuardServices, AutoGuardStartup, StartupSettings


def print_scan(summary, services: AutoGuardServices) -> None:
    print(f"Scan ID: {summary.session_id}")
    for result in summary.results: print(f"[{result.status.value}] {result.path}: {result.reason}")
    print(json.dumps(summary.counts, indent=2))
    print(summary.message)
    for reappearance_result in services.scanner.last_reappearance_results:
        print(f"Reappearance: incident={reappearance_result.incident.id if reappearance_result.incident else 'unknown'}, count={reappearance_result.reappearance_count}, {reappearance_result.explanation or ''}")


def minimal_interface(services: AutoGuardServices, initial_path: Path | None = None) -> None:
    """Temporary Phase 12 interface shell; replace with the real UI later."""
    print("AutoGuard Phase 12 is running.")
    print(f"Database: {services.config.database_path}\nQuarantine: {services.config.quarantine_dir}\nSignatures loaded: {len(services.signatures)}")
    if services.startup_dispatch is not None: print(f"Startup quick scan: {services.startup_dispatch.status.value}")
    print(f"Scheduled scans: quick every {services.scheduler.settings.quick_interval_hours:g}h, full every {services.scheduler.settings.full_interval_days:g}d")

    if initial_path is not None:
        def one_shot() -> None:
            try: print_scan(services.scanner.scan(initial_path), services)
            except Exception as error: print(f"One-shot scan failed: {type(error).__name__}: {error}")
        threading.Thread(target=one_shot, name="AutoGuardManualScan", daemon=True).start()

    print("Minimal interface active. Press Ctrl+C to shut down AutoGuard.")
    while True: time.sleep(1.0)


def main() -> None:
    config = AppConfig()
    parser = argparse.ArgumentParser(description="AutoGuard Phase 12 automatic startup and scheduled scanning")
    parser.add_argument("path", nargs="?", type=Path, help="Optional one-shot file/directory scan")
    parser.add_argument("--max-bytes", type=int, default=config.max_file_size_bytes)
    parser.add_argument("--quick-hours", type=float, default=24.0)
    parser.add_argument("--full-days", type=float, default=7.0)
    parser.add_argument("--debounce-seconds", type=float, default=1.0)
    parser.add_argument("--stability-seconds", type=float, default=1.0)
    parser.add_argument("--usb-poll-seconds", type=float, default=1.0)
    parser.add_argument("--no-file-monitor", action="store_true")
    parser.add_argument("--no-usb-monitor", action="store_true")
    parser.add_argument("--no-scheduler", action="store_true")
    parser.add_argument("--no-startup-scan", action="store_true")
    args = parser.parse_args()

    if args.max_bytes < 0: parser.error("--max-bytes must not be negative")
    if args.quick_hours <= 0 or args.full_days <= 0: parser.error("schedule intervals must be greater than zero")
    if args.debounce_seconds < 0 or args.stability_seconds < 0: parser.error("monitor timing values must not be negative")
    if args.usb_poll_seconds <= 0: parser.error("--usb-poll-seconds must be greater than zero")

    config = AppConfig(max_file_size_bytes=args.max_bytes)
    settings = StartupSettings(
        schedule=ScheduleSettings(quick_interval_hours=args.quick_hours, full_interval_days=args.full_days),
        startup_quick_scan_enabled=not args.no_startup_scan,
        scheduler_enabled=not args.no_scheduler,
        file_monitor_enabled=not args.no_file_monitor,
        usb_monitor_enabled=False if args.no_usb_monitor else None,
        debounce_seconds=args.debounce_seconds,
        stability_seconds=args.stability_seconds,
        usb_poll_seconds=args.usb_poll_seconds,
    )
    application = AutoGuardStartup(config, settings)

    try: application.start(lambda services: minimal_interface(services, args.path))
    except KeyboardInterrupt: print("Stopping AutoGuard...")
    finally:
        report = application.shutdown()
        if report.errors:
            for error in report.errors: print(f"Shutdown warning: {error}")
        print("AutoGuard stopped.")


if __name__ == "__main__":
    main()