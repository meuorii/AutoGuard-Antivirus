import logging
from app.config import AppConfig
from app.database import Database

def main() -> None:
    config = AppConfig(); config.create_directories()
    logging.basicConfig(filename=config.logs_dir / "autoguard.log", level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s", encoding="utf-8")
    Database(config.database_path).initialize()
    logging.getLogger(__name__).info("Phase 1 foundation initialized")
    print(f"AutoGuard Phase 1 initialized.\nDatabase: {config.database_path}\nQuarantine directory: {config.quarantine_dir}\nLogs: {config.logs_dir}")

if __name__ == "__main__": main()