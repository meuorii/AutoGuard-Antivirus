from dataclasses import dataclass, field
from pathlib import Path

HASH_CHUNK_SIZE, SQLITE_TIMEOUT_SECONDS = 1024 * 1024, 30.0

@dataclass(frozen=True)
class AppConfig:
    data_dir: Path = field(default_factory=lambda: Path.home() / "AutoGuardData")

    @property
    def database_dir(self) -> Path: return self.data_dir / "database"

    @property
    def database_path(self) -> Path: return self.database_dir / "autoguard.db"

    @property
    def quarantine_dir(self) -> Path: return self.data_dir / "quarantine"

    @property
    def logs_dir(self) -> Path: return self.data_dir / "logs"

    def create_directories(self) -> None:
        for d in (self.database_dir, self.quarantine_dir, self.logs_dir): d.mkdir(parents=True, exist_ok=True)