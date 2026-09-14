import argparse, json, logging
from pathlib import Path

from app.cleanup_verifier import CleanupVerifier
from app.config import AppConfig
from app.database import Database
from app.detector import Detector
from app.incidents import IncidentService
from app.matching_cleanup import MatchingCopyCleanup
from app.quarantine import QuarantineService
from app.reappearance import ReappearanceWatch
from app.scanner import Scanner
from app.signatures import load_signatures
from app.threat_trail import ThreatTrail

def main() -> None:
    config = AppConfig()
    parser = argparse.ArgumentParser(description="AutoGuard Phase 9 scanner with reappearance watch")
    parser.add_argument("path", nargs="?", type=Path, help="One file or directory to scan")
    parser.add_argument("--max-bytes", type=int, default=config.max_file_size_bytes)
    args = parser.parse_args()
    if args.max_bytes < 0: parser.error("--max-bytes must not be negative")
    config.create_directories()
    logging.basicConfig(filename=config.logs_dir / "autoguard.log", level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s", encoding="utf-8")
    database = Database(config.database_path); database.initialize()
    signatures = load_signatures()
    logging.getLogger(__name__).info("Phase 9 initialized with %d signatures", len(signatures))
    print("AutoGuard Phase 9 initialized.")
    print(f"Database: {config.database_path}\nQuarantine directory: {config.quarantine_dir}\nLogs: {config.logs_dir}\nSignatures loaded: {len(signatures)}")
    if args.path is not None:
        incidents = IncidentService(database)
        quarantine = QuarantineService(database, config.quarantine_dir, incidents)
        trail = ThreatTrail(database)
        matching_cleanup = MatchingCopyCleanup(database, incidents, quarantine, trail)
        cleanup_verifier = CleanupVerifier(database, incidents, quarantine)
        reappearance = ReappearanceWatch(database, incidents)
        scanner = Scanner(Detector(signatures), trail, max_file_size_bytes=args.max_bytes, incidents=incidents, quarantine=quarantine, matching_cleanup=matching_cleanup, cleanup_verifier=cleanup_verifier, reappearance=reappearance)
        summary = scanner.scan(args.path)
        print(f"Scan ID: {summary.session_id}")
        for result in summary.results: print(f"[{result.status.value}] {result.path}: {result.reason}")
        print(json.dumps(summary.counts, indent=2))
        print(summary.message)
        for r in scanner.last_reappearance_results: print(f"Reappearance: incident={r.incident.id if r.incident else 'unknown'}, count={r.reappearance_count}, {r.explanation or ''}")
        for c in scanner.last_matching_cleanup_results: print(f"Matching cleanup: searched={len(c.locations_searched)}, examined={c.candidates_examined}, exact={c.exact_matches_found}, quarantined={c.matches_quarantined}, already_contained={c.already_contained_matches}, failures={len(c.failures)}, inaccessible={len(c.inaccessible_files)}")
        for v in scanner.last_cleanup_verification_results: print(f"Cleanup verification: status={v.status.value}, quarantined={v.quarantined_copies}, verified={v.verified_quarantine_objects}, remaining={v.remaining_matching_copies}, inaccessible={v.inaccessible_locations}, errors={v.verification_errors}")

if __name__ == "__main__": main()