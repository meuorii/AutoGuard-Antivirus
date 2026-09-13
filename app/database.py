import sqlite3
from contextlib import closing, contextmanager
from pathlib import Path
from typing import Iterator
from app.config import SQLITE_TIMEOUT_SECONDS

SCHEMA = """
CREATE TABLE IF NOT EXISTS file_observations (
    id INTEGER PRIMARY KEY,
    sha256 TEXT NOT NULL CHECK (length(sha256) = 64 AND sha256 NOT GLOB '*[^0-9a-f]*'),
    path TEXT NOT NULL CHECK (length(path) > 0),
    source TEXT NOT NULL CHECK (source IN ('manual', 'startup', 'scheduled', 'file_monitor', 'usb', 'matching_copy', 'recovery')),
    size_bytes INTEGER NOT NULL CHECK (size_bytes >= 0),
    first_seen TEXT NOT NULL,
    last_seen TEXT NOT NULL CHECK (last_seen >= first_seen),
    seen_count INTEGER NOT NULL DEFAULT 1 CHECK (seen_count >= 1),
    UNIQUE (sha256, path)
);
CREATE TABLE IF NOT EXISTS observation_events (
    id INTEGER PRIMARY KEY,
    observation_id INTEGER NOT NULL REFERENCES file_observations(id) ON DELETE RESTRICT,
    source TEXT NOT NULL CHECK (source IN ('manual', 'startup', 'scheduled', 'file_monitor', 'usb', 'matching_copy', 'recovery')),
    observed_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_observations_path ON file_observations(path);
CREATE INDEX IF NOT EXISTS idx_events_observation_time ON observation_events(observation_id, observed_at, id);
"""

class Database:
    def __init__(self, path: str | Path) -> None:
        if str(path) == ":memory:": raise ValueError("Use a database file with fresh connections.")
        self.path = Path(path).expanduser().absolute()

    @contextmanager
    def connection(self) -> Iterator[sqlite3.Connection]:
        with closing(sqlite3.connect(self.path, timeout=SQLITE_TIMEOUT_SECONDS)) as connection:
            connection.row_factory = sqlite3.Row
            connection.execute("PRAGMA foreign_keys = ON")
            with connection: yield connection

    def initialize(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self.connection() as connection:
            connection.execute("PRAGMA journal_mode = WAL")
            connection.executescript("BEGIN IMMEDIATE;\n" + SCHEMA)