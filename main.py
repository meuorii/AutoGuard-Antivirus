import argparse
import json
import logging
from pathlib import Path

from app.cleanup_verifier import CleanupVerifier
from app.config import AppConfig
from app.database import Database
from app.detector import Detector
from app.incidents import IncidentService
from app.matching_cleanup import MatchingCopyCleanup
from app.quarantine import QuarantineService
from app.scanner import Scanner
from app.signatures import load_signatures
from app.threat_trail import ThreatTrail


def main() -> None:
    config = AppConfig()
    parser = argparse.ArgumentParser(description="AutoGuard Phase 8 scanner with cleanup verification")
    parser.add_argument("path", nargs="?", type=Path, help="One file or directory to scan")
    parser.add_argument("--max-bytes", type=int, default=config.max_file_size_bytes)
    args = parser.parse_args()
    if args.max_bytes < 0: parser.error("--max-bytes must not be negative")
    config.create_directories()
    logging.basicConfig(filename=config.logs_dir / "autoguard.log", level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s", encoding="utf-8")
    database = Database(config.database_path); database.initialize()
    signatures = load_signatures()
    logging.getLogger(__name__).info("Phase 8 initialized with %d signatures", len(signatures))
    print("AutoGuard Phase 8 initialized."); print(f"Database: {config.database_path}"); print(f"Quarantine directory: {config.quarantine_dir}"); print(f"Logs: {config.logs_dir}"); print(f"Signatures loaded: {len(signatures)}")
    if args.path is not None:
        incidents = IncidentService(database)
        quarantine = QuarantineService(database, config.quarantine_dir, incidents)
        trail = ThreatTrail(database)
        matching_cleanup = MatchingCopyCleanup(database, incidents, quarantine, trail)
        cleanup_verifier = CleanupVerifier(database, incidents, quarantine)
        scanner = Scanner(Detector(signatures), trail, max_file_size_bytes=args.max_bytes, incidents=incidents, quarantine=quarantine, matching_cleanup=matching_cleanup, cleanup_verifier=cleanup_verifier)
        summary = scanner.scan(args.path)
        print(f"Scan ID: {summary.session_id}")
        for result in summary.results: print(f"[{result.status.value}] {result.path}: {result.reason}")
        print(json.dumps(summary.counts, indent=2)); print(summary.message)
        for cleanup in scanner.last_matching_cleanup_results: print("Matching cleanup: " f"searched={len(cleanup.locations_searched)}, " f"examined={cleanup.candidates_examined}, " f"exact={cleanup.exact_matches_found}, " f"quarantined={cleanup.matches_quarantined}, " f"already_contained={cleanup.already_contained_matches}, " f"failures={len(cleanup.failures)}, " f"inaccessible={len(cleanup.inaccessible_files)}")
        for verification in scanner.last_cleanup_verification_results: print("Cleanup verification: " f"status={verification.status.value}, " f"quarantined={verification.quarantined_copies}, " f"verified={verification.verified_quarantine_objects}, " f"remaining={verification.remaining_matching_copies}, " f"inaccessible={verification.inaccessible_locations}, " f"errors={verification.verification_errors}")


if __name__ == "__main__":
    main()