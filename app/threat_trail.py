import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from app.database import Database
from app.hashing import hash_file
from app.models import FileFingerprint, FileObservation, ObservationEvent, ScanSource

def _observation(row: sqlite3.Row) -> FileObservation:
    return FileObservation(id=row["id"], sha256=row["sha256"], path=row["path"], source=ScanSource(row["source"]), size_bytes=row["size_bytes"], first_seen=datetime.fromisoformat(row["first_seen"]), last_seen=datetime.fromisoformat(row["last_seen"]), seen_count=row["seen_count"])

class ThreatTrail:
    def __init__(self, database: Database) -> None: self.database = database

    def record_file(self, path: str | Path, source: ScanSource = ScanSource.MANUAL) -> FileObservation:
        """Hash one file, update its aggregate, and append one event atomically."""
        return self.record_fingerprint(hash_file(path), ScanSource(source))

    def record_fingerprint(self, fingerprint: FileFingerprint, source: ScanSource = ScanSource.MANUAL) -> FileObservation:
        """Persist a trusted completed inspection without rereading the file."""
        source, observed_at = ScanSource(source), datetime.now(timezone.utc).isoformat(timespec="microseconds")
        with self.database.connection() as connection:
            connection.execute("BEGIN IMMEDIATE")
            connection.execute("INSERT INTO file_observations (sha256, path, source, size_bytes, first_seen, last_seen, seen_count) VALUES (?, ?, ?, ?, ?, ?, 1) ON CONFLICT (sha256, path) DO UPDATE SET source = CASE WHEN excluded.last_seen >= file_observations.last_seen THEN excluded.source ELSE file_observations.source END, first_seen = MIN(file_observations.first_seen, excluded.first_seen), last_seen = MAX(file_observations.last_seen, excluded.last_seen), seen_count = file_observations.seen_count + 1", (fingerprint.sha256, fingerprint.path, source.value, fingerprint.size_bytes, observed_at, observed_at))
            if (row := connection.execute("SELECT * FROM file_observations WHERE sha256 = ? AND path = ?", (fingerprint.sha256, fingerprint.path)).fetchone()) is None: raise RuntimeError("Observation was not persisted.")
            connection.execute("INSERT INTO observation_events (observation_id, source, observed_at) VALUES (?, ?, ?)", (row["id"], source.value, observed_at))
            return _observation(row)

    def get_observations(self, sha256: str) -> list[FileObservation]:
        """Return recorded locations for this hash, including historical ones."""
        with self.database.connection() as connection:
            rows = connection.execute("SELECT * FROM file_observations WHERE sha256 = ? ORDER BY first_seen, id", (sha256.lower(),)).fetchall()
            return [_observation(row) for row in rows]

    def get_events(self, sha256: str) -> list[ObservationEvent]:
        """Return every sighting for a hash, ordered by UTC time then event ID."""
        with self.database.connection() as connection:
            rows = connection.execute("SELECT e.id, e.observation_id, o.sha256, o.path, e.source, o.size_bytes, e.observed_at FROM observation_events AS e JOIN file_observations AS o ON o.id = e.observation_id WHERE o.sha256 = ? ORDER BY e.observed_at, e.id", (sha256.lower(),)).fetchall()
            return [ObservationEvent(id=row["id"], observation_id=row["observation_id"], sha256=row["sha256"], path=row["path"], source=ScanSource(row["source"]), size_bytes=row["size_bytes"], observed_at=datetime.fromisoformat(row["observed_at"])) for row in rows]

    def describe_locations(self, sha256: str) -> str:
        count = len(self.get_observations(sha256))
        if count == 0: return "No observations recorded for this SHA-256."
        if count == 1: return "Content was observed at one recorded location."
        return f"Identical content was observed in multiple locations ({count}). These observations do not establish an infection source or direction of spread."