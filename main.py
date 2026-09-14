import argparse, json, logging
from pathlib import Path
from app.config import AppConfig
from app.database import Database
from app.detector import Detector
from app.scanner import Scanner
from app.signatures import load_signatures
from app.threat_trail import ThreatTrail

def main() -> None:
    config = AppConfig()
    parser = argparse.ArgumentParser(description="AutoGuard Phase 3 scanner")
    parser.add_argument("path", nargs="?", type=Path, help="One file or directory to scan")
    parser.add_argument("--max-bytes", type=int, default=config.max_file_size_bytes)
    args = parser.parse_args()
    if args.max_bytes < 0: parser.error("--max-bytes must not be negative")
    config.create_directories()
    logging.basicConfig(filename=config.logs_dir / "autoguard.log", level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s", encoding="utf-8")
    database = Database(config.database_path); database.initialize()
    signatures = load_signatures()
    logging.getLogger(__name__).info("Phase 3 initialized with %d signatures", len(signatures))
    print("AutoGuard Phase 3 initialized."); print(f"Database: {config.database_path}"); print(f"Quarantine directory: {config.quarantine_dir}"); print(f"Logs: {config.logs_dir}"); print(f"Signatures loaded: {len(signatures)}")
    if args.path is not None:
        scanner = Scanner(Detector(signatures), ThreatTrail(database), max_file_size_bytes=args.max_bytes)
        summary = scanner.scan(args.path)
        for result in summary.results: print(f"[{result.status.value}] {result.path}: {result.reason}")
        print(json.dumps(summary.counts, indent=2)); print(summary.message)

if __name__ == "__main__": main()