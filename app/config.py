from dataclasses import dataclass, field
from pathlib import Path

HASH_CHUNK_SIZE = 1024 * 1024
DEFAULT_MAX_FILE_SIZE_BYTES = 512 * 1024 * 1024
SQLITE_TIMEOUT_SECONDS = 30.0

@dataclass(frozen=True)
class AppConfig:
    data_dir: Path = field(default_factory=lambda: Path.home() / "AutoGuardData")
    max_file_size_bytes: int = DEFAULT_MAX_FILE_SIZE_BYTES

    def __post_init__(self) -> None:
        if type(self.max_file_size_bytes) is not int or self.max_file_size_bytes < 0: raise ValueError("max_file_size_bytes must be a nonnegative integer.")

    @property
    def database_dir(self) -> Path: return self.data_dir / "database"

    @property
    def database_path(self) -> Path: return self.database_dir / "autoguard.db"

    @property
    def quarantine_dir(self) -> Path: return self.data_dir / "quarantine"

    @property
    def logs_dir(self) -> Path: return self.data_dir / "logs"

    def create_directories(self) -> None:
        for directory in (self.database_dir, self.quarantine_dir, self.logs_dir): directory.mkdir(parents=True, exist_ok=True)