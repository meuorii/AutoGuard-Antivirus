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

CREATE TABLE IF NOT EXISTS scan_sessions (
    id TEXT PRIMARY KEY NOT NULL,
    scan_type TEXT NOT NULL CHECK (scan_type IN ('manual', 'quick', 'full', 'startup', 'scheduled', 'usb', 'real_time', 'matching_copy', 'recovery')),
    source_path TEXT NOT NULL CHECK (length(source_path) > 0),
    source TEXT NOT NULL CHECK (source IN ('manual', 'startup', 'scheduled', 'file_monitor', 'usb', 'matching_copy', 'recovery')),
    started_at TEXT NOT NULL,
    finished_at TEXT,
    status TEXT NOT NULL DEFAULT 'RUNNING' CHECK (status IN ('RUNNING', 'COMPLETED', 'INCOMPLETE', 'FAILED')),
    discovered_files INTEGER NOT NULL DEFAULT 0 CHECK (discovered_files >= 0),
    scanned_files INTEGER NOT NULL DEFAULT 0 CHECK (scanned_files >= 0),
    dangerous_detections INTEGER NOT NULL DEFAULT 0 CHECK (dangerous_detections >= 0),
    suspicious_detections INTEGER NOT NULL DEFAULT 0 CHECK (suspicious_detections >= 0),
    skipped_size INTEGER NOT NULL DEFAULT 0 CHECK (skipped_size >= 0),
    locked_files INTEGER NOT NULL DEFAULT 0 CHECK (locked_files >= 0),
    unsupported_files INTEGER NOT NULL DEFAULT 0 CHECK (unsupported_files >= 0),
    errors INTEGER NOT NULL DEFAULT 0 CHECK (errors >= 0),
    file_errors INTEGER NOT NULL DEFAULT 0 CHECK (file_errors >= 0),
    directory_issues INTEGER NOT NULL DEFAULT 0 CHECK (directory_issues >= 0),
    unclassified_entries INTEGER NOT NULL DEFAULT 0 CHECK (unclassified_entries >= 0),
    error TEXT,
    CHECK ((status = 'RUNNING' AND finished_at IS NULL) OR (status <> 'RUNNING' AND finished_at IS NOT NULL AND finished_at >= started_at)),
    CHECK (discovered_files = scanned_files + skipped_size + locked_files + unsupported_files + file_errors)
);

CREATE TABLE IF NOT EXISTS scan_results (
    id INTEGER PRIMARY KEY,
    session_id TEXT NOT NULL REFERENCES scan_sessions(id) ON DELETE RESTRICT,
    path TEXT NOT NULL CHECK (length(path) > 0),
    sha256 TEXT CHECK (sha256 IS NULL OR (length(sha256) = 64 AND sha256 NOT GLOB '*[^0-9a-f]*')),
    result_category TEXT NOT NULL CHECK (result_category IN ('SCANNED', 'SKIPPED_SIZE', 'SKIPPED_LOCKED', 'SKIPPED_UNSUPPORTED', 'ERROR')),
    entry_kind TEXT NOT NULL CHECK (entry_kind IN ('file', 'directory', 'unknown')),
    detection_status TEXT CHECK (detection_status IN ('NO_DETECTION', 'LOW_CONFIDENCE', 'HIGH_CONFIDENCE')),
    detection_confidence REAL CHECK (detection_confidence BETWEEN 0.0 AND 1.0),
    rule_name TEXT,
    reason TEXT NOT NULL,
    detection_reason TEXT,
    matched_signature_name TEXT,
    matched_signature_kind TEXT CHECK (matched_signature_kind IN ('known_malicious', 'autoguard_test')),
    recorded_at TEXT NOT NULL,
    CHECK ((detection_status IS NULL AND detection_confidence IS NULL AND rule_name IS NULL AND detection_reason IS NULL) OR (detection_status IS NOT NULL AND detection_confidence IS NOT NULL AND rule_name IS NOT NULL AND detection_reason IS NOT NULL AND sha256 IS NOT NULL)),
    CHECK ((detection_status IS 'HIGH_CONFIDENCE' AND matched_signature_name IS NOT NULL AND matched_signature_kind IS NOT NULL) OR (detection_status IS NOT 'HIGH_CONFIDENCE' AND matched_signature_name IS NULL AND matched_signature_kind IS NULL)),
    CHECK (result_category <> 'SCANNED' OR (entry_kind = 'file' AND sha256 IS NOT NULL AND detection_status IS NOT NULL))
);

CREATE INDEX IF NOT EXISTS idx_scan_sessions_started ON scan_sessions(started_at DESC);
CREATE INDEX IF NOT EXISTS idx_scan_results_session ON scan_results(session_id, id);
"""

class Database:
    """Keep only the database path; never retain a shared connection."""

    def __init__(self, path: str | Path) -> None:
        if str(path) == ":memory:": raise ValueError("Use a database file with fresh connections.")
        self.path = Path(path).expanduser().absolute()

    @contextmanager
    def connection(self) -> Iterator[sqlite3.Connection]:
        """Commit on success, roll back on error, and always close."""
        with closing(sqlite3.connect(self.path, timeout=SQLITE_TIMEOUT_SECONDS)) as connection:
            connection.row_factory = sqlite3.Row
            connection.execute("PRAGMA foreign_keys = ON")
            with connection: yield connection

    def initialize(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self.connection() as connection:
            connection.execute("PRAGMA journal_mode = WAL")
            connection.executescript("BEGIN IMMEDIATE;\n" + SCHEMA)