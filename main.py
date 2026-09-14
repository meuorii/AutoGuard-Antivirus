import argparse, json, logging, os, time
from pathlib import Path

from app.cleanup_verifier import CleanupVerifier
from app.config import AppConfig
from app.database import Database
from app.detector import Detector
from app.file_monitor import FileMonitor, default_monitored_paths
from app.incidents import IncidentService
from app.matching_cleanup import MatchingCopyCleanup
from app.quarantine import QuarantineService
from app.reappearance import ReappearanceWatch
from app.scanner import Scanner
from app.signatures import load_signatures
from app.threat_trail import ThreatTrail
from app.usb_monitor import USBMonitor, USBMonitorEvent

def build_scanner(config: AppConfig, database: Database, max_bytes: int) -> Scanner:
    signatures, incidents, trail = load_signatures(), IncidentService(database), ThreatTrail(database)
    quarantine = QuarantineService(database, config.quarantine_dir, incidents)
    matching_cleanup = MatchingCopyCleanup(database, incidents, quarantine, trail)
    cleanup_verifier, reappearance = CleanupVerifier(database, incidents, quarantine), ReappearanceWatch(database, incidents)
    return Scanner(
        Detector(signatures), trail, max_file_size_bytes=max_bytes, incidents=incidents,
        quarantine=quarantine, matching_cleanup=matching_cleanup, cleanup_verifier=cleanup_verifier, reappearance=reappearance,
    )


def print_scan(summary, scanner: Scanner) -> None:
    print(f"Scan ID: {summary.session_id}")
    for result in summary.results: print(f"[{result.status.value}] {result.path}: {result.reason}")
    print(json.dumps(summary.counts, indent=2)); print(summary.message)
    for reappearance_result in scanner.last_reappearance_results:
        print(
            f"Reappearance: incident={reappearance_result.incident.id if reappearance_result.incident else 'unknown'}, "
            f"count={reappearance_result.reappearance_count}, {reappearance_result.explanation or ''}"
        )


def print_usb_event(event: USBMonitorEvent) -> None:
    message = f"[USB][{event.event_type.value}] {event.drive_root} insertion={event.insertion_number}"
    if event.session_id: message += f" session={event.session_id}"
    message += f": {event.message}"; print(message); logging.getLogger(__name__).info(message)


def main() -> None:
    config = AppConfig()
    parser = argparse.ArgumentParser(description="AutoGuard Phase 11 scanner with real-time file and removable-drive monitoring")
    parser.add_argument("path", nargs="?", type=Path, help="One file or directory to scan")
    parser.add_argument("--max-bytes", type=int, default=config.max_file_size_bytes)
    parser.add_argument("--monitor", action="store_true", help="Keep file/USB monitoring active after any one-shot scan.")
    parser.add_argument("--debounce-seconds", type=float, default=1.0)
    parser.add_argument("--stability-seconds", type=float, default=1.0)
    parser.add_argument("--usb-poll-seconds", type=float, default=1.0)
    parser.add_argument("--repeat-usb-scans", action="store_true", help="Allow a still-mounted removable drive to be rescanned on later discovery polls.")
    parser.add_argument("--no-usb-monitor", action="store_true", help="Disable automatic Windows removable-drive monitoring.")
    args = parser.parse_args()

    if args.max_bytes < 0: parser.error("--max-bytes must not be negative")
    if args.debounce_seconds < 0 or args.stability_seconds < 0: parser.error("monitor timing values must not be negative")
    if args.usb_poll_seconds <= 0: parser.error("--usb-poll-seconds must be greater than zero")

    config.create_directories()
    logging.basicConfig(filename=config.logs_dir / "autoguard.log", level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s", encoding="utf-8")
    database = Database(config.database_path); database.initialize()
    scanner = build_scanner(config, database, args.max_bytes); signatures = scanner.detector.signatures
    print("AutoGuard Phase 11 initialized."); print(f"Database: {config.database_path}"); print(f"Quarantine directory: {config.quarantine_dir}")
    print(f"Logs: {config.logs_dir}"); print(f"Signatures loaded: {len(signatures)}")

    if args.path is not None: print_scan(scanner.scan(args.path), scanner)

    if args.path is None or args.monitor:
        file_monitor, usb_monitor = None, None
        roots = tuple(path for path in default_monitored_paths() if path.is_dir())
        if roots:
            file_monitor = FileMonitor(scanner, roots, ignored_paths=(config.quarantine_dir, config.database_dir, config.logs_dir), debounce_seconds=args.debounce_seconds, stability_period_seconds=args.stability_seconds)
            health = file_monitor.start(); print("Real-time filesystem monitoring started:")
            for path in health.scheduled_paths: print(f"  - {path}")
        else: print("No default Downloads/Desktop/Documents directories currently exist.")

        if not args.no_usb_monitor and os.name == "nt":
            usb_monitor = USBMonitor(scanner, poll_interval_seconds=args.usb_poll_seconds, scan_once_per_insertion=not args.repeat_usb_scans, event_callback=print_usb_event)
            usb_monitor.start(); print("Windows removable-drive monitoring started. Newly mounted removable drives will be scanned automatically.")
        elif args.no_usb_monitor: print("USB monitoring disabled by command-line option.")
        else: print("Automatic removable-drive discovery is enabled only on Windows in Phase 11.")

        if file_monitor is None and usb_monitor is None: return

        print("Press Ctrl+C to stop AutoGuard monitoring.")
        try:
            while True: time.sleep(1.0)
        except KeyboardInterrupt:
            if usb_monitor is not None: usb_monitor.stop()
            if file_monitor is not None: file_monitor.stop()
            print("AutoGuard monitoring stopped.")


if __name__ == "__main__": main()