"""AutoGuard desktop application entry point."""
from __future__ import annotations

import argparse
from pathlib import Path

from app.config import AppConfig
from app.scheduler import ScheduleSettings
from app.startup import AutoGuardStartup, StartupSettings


def main() -> None:
    config = AppConfig()
    parser = argparse.ArgumentParser(description="AutoGuard automatic protection")
    parser.add_argument("path", nargs="?", type=Path, help="Optional file/directory to scan after the UI opens")
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
    parser.add_argument("--no-windows-notifications", action="store_true")
    parser.add_argument("--no-system-tray", action="store_true")
    args = parser.parse_args()

    if args.max_bytes < 0:
        parser.error("--max-bytes must not be negative")
    if args.quick_hours <= 0 or args.full_days <= 0:
        parser.error("schedule intervals must be greater than zero")
    if args.debounce_seconds < 0 or args.stability_seconds < 0:
        parser.error("monitor timing values must not be negative")
    if args.usb_poll_seconds <= 0:
        parser.error("--usb-poll-seconds must be greater than zero")

    settings = StartupSettings(
        schedule=ScheduleSettings(args.quick_hours, args.full_days),
        startup_quick_scan_enabled=not args.no_startup_scan,
        scheduler_enabled=not args.no_scheduler,
        file_monitor_enabled=not args.no_file_monitor,
        usb_monitor_enabled=False if args.no_usb_monitor else None,
        debounce_seconds=args.debounce_seconds,
        stability_seconds=args.stability_seconds,
        usb_poll_seconds=args.usb_poll_seconds,
        windows_notifications_enabled=not args.no_windows_notifications,
    )
    application = AutoGuardStartup(AppConfig(max_file_size_bytes=args.max_bytes), settings)

    def open_interface(services):
        try:
            from app.ui.main_window import launch_desktop
        except ModuleNotFoundError as error:
            if error.name == "customtkinter":
                raise SystemExit("customtkinter is required for the desktop UI. Install dependencies with: .\\.venv\\Scripts\\python.exe -m pip install -r requirements.txt") from error
            raise
        launch_desktop(services, args.path, enable_system_tray=not args.no_system_tray)

    try:
        application.start(open_interface)
    except Exception:
        try:
            from app.logging_config import application_logger
            application_logger().exception("Fatal AutoGuard application error")
        finally:
            raise
    finally:
        application.shutdown()


if __name__ == "__main__":
    main()