import argparse, json, logging, time
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

def build_scanner(config: AppConfig, database: Database, max_bytes: int) -> Scanner:
    signatures, incidents = load_signatures(), IncidentService(database)
    quarantine, trail = QuarantineService(database, config.quarantine_dir, incidents), ThreatTrail(database)
    matching_cleanup, cleanup_verifier = MatchingCopyCleanup(database, incidents, quarantine, trail), CleanupVerifier(database, incidents, quarantine)
    reappearance = ReappearanceWatch(database, incidents)
    return Scanner(Detector(signatures), trail, max_file_size_bytes=max_bytes, incidents=incidents, quarantine=quarantine, matching_cleanup=matching_cleanup, cleanup_verifier=cleanup_verifier, reappearance=reappearance)

def print_scan(summary, scanner: Scanner) -> None:
    print(f"Scan ID: {summary.session_id}")
    for result in summary.results: print(f"[{result.status.value}] {result.path}: {result.reason}")
    print(json.dumps(summary.counts, indent=2)); print(summary.message)
    for reappearance_result in scanner.last_reappearance_results: print(f"Reappearance: incident={reappearance_result.incident.id if reappearance_result.incident else 'unknown'}, count={reappearance_result.reappearance_count}, {reappearance_result.explanation or ''}")

def main() -> None:
    config = AppConfig()
    parser = argparse.ArgumentParser(description="AutoGuard Phase 10 scanner with real-time watchdog monitoring")
    parser.add_argument("path", nargs="?", type=Path, help="One file or directory to scan")
    parser.add_argument("--max-bytes", type=int, default=config.max_file_size_bytes)
    parser.add_argument("--monitor", action="store_true", help="Keep monitoring Downloads, Desktop, and Documents after any one-shot scan.")
    parser.add_argument("--debounce-seconds", type=float, default=1.0); parser.add_argument("--stability-seconds", type=float, default=1.0)
    args = parser.parse_args()
    if args.max_bytes < 0: parser.error("--max-bytes must not be negative")
    if args.debounce_seconds < 0 or args.stability_seconds < 0: parser.error("monitor timing values must not be negative")

    config.create_directories()
    logging.basicConfig(filename=config.logs_dir / "autoguard.log", level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s", encoding="utf-8")
    database = Database(config.database_path); database.initialize()
    scanner = build_scanner(config, database, args.max_bytes); signatures = scanner.detector.signatures
    print("AutoGuard Phase 10 initialized."); print(f"Database: {config.database_path}"); print(f"Quarantine directory: {config.quarantine_dir}"); print(f"Logs: {config.logs_dir}"); print(f"Signatures loaded: {len(signatures)}")

    if args.path is not None: print_scan(scanner.scan(args.path), scanner)

    if args.path is None or args.monitor:
        if not (roots := tuple(path for path in default_monitored_paths() if path.is_dir())): print("No default monitored directories currently exist; real-time monitor was not started."); return
        monitor = FileMonitor(scanner, roots, ignored_paths=(config.quarantine_dir, config.database_dir, config.logs_dir), debounce_seconds=args.debounce_seconds, stability_period_seconds=args.stability_seconds)
        health = monitor.start(); print("Real-time monitoring started:")
        for path in health.scheduled_paths: print(f"  - {path}")
        print("Press Ctrl+C to stop AutoGuard monitoring.")
        try:
            while True: time.sleep(1.0)
        except KeyboardInterrupt: monitor.stop(); print("Real-time monitoring stopped.")

if __name__ == "__main__": main()