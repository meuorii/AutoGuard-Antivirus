import logging
from app.config import AppConfig
from app.database import Database
from app.signatures import load_signatures

def main() -> None:
    config = AppConfig(); config.create_directories()
    logging.basicConfig(filename=config.logs_dir / "autoguard.log", level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s", encoding="utf-8")
    Database(config.database_path).initialize()
    signatures = load_signatures()
    logging.getLogger(__name__).info("Phase 2 initialized with %d signatures", len(signatures))
    print("AutoGuard Phase 2 initialized."); print(f"Database: {config.database_path}"); print(f"Quarantine directory: {config.quarantine_dir}"); print(f"Logs: {config.logs_dir}"); print(f"Signatures loaded: {len(signatures)}")

if __name__ == "__main__": main()