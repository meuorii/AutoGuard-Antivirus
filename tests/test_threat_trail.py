import hashlib, os, sqlite3
from concurrent.futures import ThreadPoolExecutor
from datetime import timedelta
from pathlib import Path
import pytest
from app.config import AppConfig
from app.database import Database
from app.hashing import FileChangedError, hash_file
from app.models import ScanSource
from app.threat_trail import ThreatTrail

@pytest.fixture
def trail(tmp_path: Path) -> ThreatTrail:
    config = AppConfig(data_dir=tmp_path / "AutoGuardData")
    config.create_directories()
    database = Database(config.database_path)
    database.initialize()
    return ThreatTrail(database)

def test_record_file(trail: ThreatTrail, tmp_path: Path) -> None:
    path = tmp_path / "example.txt"
    content = b"AutoGuard observation"
    path.write_bytes(content)
    recorded = trail.record_file(path)
    assert recorded.sha256 == hashlib.sha256(content).hexdigest()
    assert recorded.path == os.path.normcase(str(path.absolute()))
    assert recorded.source is ScanSource.MANUAL
    assert recorded.size_bytes == len(content)
    assert recorded.seen_count == 1
    assert recorded.first_seen == recorded.last_seen
    assert recorded.first_seen.utcoffset() == timedelta(0)
    assert trail.get_observations(recorded.sha256) == [recorded]
    assert len(trail.get_events(recorded.sha256)) == 1

def test_repeated_sightings(trail: ThreatTrail, tmp_path: Path) -> None:
    path = tmp_path / "repeated.txt"
    path.write_text("unchanged", encoding="utf-8")
    first = trail.record_file(path, ScanSource.MANUAL)
    second = trail.record_file(path, ScanSource.STARTUP)
    third = trail.record_file(path, ScanSource.SCHEDULED)
    assert first.id == second.id == third.id
    assert third.seen_count == 3
    assert third.first_seen == first.first_seen
    assert third.last_seen >= second.last_seen >= first.last_seen
    assert third.source is ScanSource.SCHEDULED
    assert len(trail.get_observations(first.sha256)) == 1
    assert len(trail.get_events(first.sha256)) == 3

def test_identical_content_in_different_paths(trail: ThreatTrail, tmp_path: Path) -> None:
    first_path, second_path = tmp_path / "usb-copy.txt", tmp_path / "desktop-copy.txt"
    first_path.write_bytes(b"same content"); second_path.write_bytes(b"same content")
    first = trail.record_file(first_path, ScanSource.USB)
    second = trail.record_file(second_path, ScanSource.MANUAL)
    assert first.sha256 == second.sha256 and first.id != second.id
    observations = trail.get_observations(first.sha256)
    assert {item.path for item in observations} == {first.path, second.path}
    assert [item.seen_count for item in observations] == [1, 1]
    assert trail.describe_locations(first.sha256) == ("Identical content was observed in multiple locations (2). These observations do not establish an infection source or direction of spread.")

def test_historical_trail_events(trail: ThreatTrail, tmp_path: Path) -> None:
    first_path, second_path = tmp_path / "first.txt", tmp_path / "second.txt"
    first_path.write_bytes(b"historical content"); second_path.write_bytes(b"historical content")
    first = trail.record_file(first_path, ScanSource.USB)
    trail.record_file(first_path, ScanSource.FILE_MONITOR)
    second = trail.record_file(second_path, ScanSource.MATCHING_COPY)
    first_path.unlink(); second_path.unlink()
    reopened_database = Database(trail.database.path)
    reopened_database.initialize()
    reopened = ThreatTrail(reopened_database)
    events = reopened.get_events(first.sha256)
    assert [event.source for event in events] == [ScanSource.USB, ScanSource.FILE_MONITOR, ScanSource.MATCHING_COPY]
    assert [event.observation_id for event in events] == [first.id, first.id, second.id]
    assert [event.path for event in events] == [first.path, first.path, second.path]
    assert all(event.sha256 == first.sha256 for event in events)
    assert all(event.size_bytes == len(b"historical content") for event in events)
    assert len({event.id for event in events}) == 3
    assert [event.observed_at for event in events] == sorted(event.observed_at for event in events)
    assert len(reopened.get_observations(first.sha256)) == 2

def test_changed_content_preserves_old_history(trail: ThreatTrail, tmp_path: Path) -> None:
    path = tmp_path / "replaced.txt"
    path.write_bytes(b"old content"); old = trail.record_file(path)
    path.write_bytes(b"new content"); new = trail.record_file(path, ScanSource.RECOVERY)
    assert old.sha256 != new.sha256 and old.id != new.id and old.path == new.path
    assert trail.get_observations(old.sha256) == [old]
    assert trail.get_observations(new.sha256) == [new]
    assert trail.get_events(old.sha256)[0].source is ScanSource.MANUAL
    assert trail.get_events(new.sha256)[0].source is ScanSource.RECOVERY

def test_hashing_multiple_chunks_and_empty_file(tmp_path: Path) -> None:
    path = tmp_path / "chunks.bin"
    content = bytes(range(256)) * 8193
    path.write_bytes(content)
    fingerprint = hash_file(path, chunk_size=4096)
    assert fingerprint.sha256 == hashlib.sha256(content).hexdigest()
    assert fingerprint.size_bytes == len(content)
    path.write_bytes(b"")
    empty = hash_file(path)
    assert empty.sha256 == hashlib.sha256(b"").hexdigest() and empty.size_bytes == 0

def test_invalid_inputs_leave_no_records(trail: ThreatTrail, tmp_path: Path) -> None:
    with pytest.raises(FileNotFoundError): trail.record_file(tmp_path / "missing.txt")
    with pytest.raises(ValueError, match="regular files"): trail.record_file(tmp_path)
    with pytest.raises(ValueError, match="chunk_size"): hash_file(tmp_path / "missing.txt", chunk_size=0)
    path = tmp_path / "valid.txt"
    path.write_bytes(b"valid")
    with pytest.raises(ValueError): trail.record_file(path, "unknown_source")
    with trail.database.connection() as connection:
        assert connection.execute("SELECT COUNT(*) FROM file_observations").fetchone()[0] == 0
        assert connection.execute("SELECT COUNT(*) FROM observation_events").fetchone()[0] == 0

def test_failed_event_rolls_back_sighting(trail: ThreatTrail, tmp_path: Path) -> None:
    path = tmp_path / "rollback.txt"; path.write_bytes(b"transactional content")
    first = trail.record_file(path)
    with trail.database.connection() as connection:
        connection.execute("CREATE TRIGGER reject_event BEFORE INSERT ON observation_events BEGIN SELECT RAISE(ABORT, 'event rejected'); END")
    with pytest.raises(sqlite3.IntegrityError, match="event rejected"): trail.record_file(path, ScanSource.STARTUP)
    assert trail.get_observations(first.sha256) == [first]
    assert len(trail.get_events(first.sha256)) == 1

def test_connections_are_fresh_closed_and_enforce_foreign_keys(trail: ThreatTrail) -> None:
    with trail.database.connection() as first:
        with trail.database.connection() as second:
            assert first is not second
            assert first.execute("PRAGMA foreign_keys").fetchone()[0] == 1
            assert second.execute("PRAGMA foreign_keys").fetchone()[0] == 1
            with pytest.raises(sqlite3.IntegrityError):
                second.execute("INSERT INTO observation_events (observation_id, source, observed_at) VALUES (9999, 'manual', '2026-01-01T00:00:00.000000+00:00')")
    for connection in (first, second):
        with pytest.raises(sqlite3.ProgrammingError): connection.execute("SELECT 1")

def test_concurrent_sightings_do_not_lose_counts(trail: ThreatTrail, tmp_path: Path) -> None:
    path = tmp_path / "concurrent.txt"; path.write_bytes(b"concurrent content")
    with ThreadPoolExecutor(max_workers=4) as executor:
        recorded = list(executor.map(lambda _: trail.record_file(path), range(12)))
    assert len({item.id for item in recorded}) == 1
    observations = trail.get_observations(recorded[0].sha256)
    assert len(observations) == 1 and observations[0].seen_count == 12
    assert len(trail.get_events(recorded[0].sha256)) == 12

def test_file_changed_during_hashing_is_not_recorded(trail: ThreatTrail, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    path = tmp_path / "changing.txt"; path.write_bytes(b"original")
    real_fstat, calls = os.fstat, 0
    def change_before_final_stat(file_descriptor: int) -> os.stat_result:
        nonlocal calls; calls += 1
        if calls == 2:
            with path.open("ab") as writer: writer.write(b" changed")
        return real_fstat(file_descriptor)
    monkeypatch.setattr("app.hashing.os.fstat", change_before_final_stat)
    with pytest.raises(FileChangedError): trail.record_file(path)
    assert trail.get_observations(hashlib.sha256(b"original").hexdigest()) == []
    with trail.database.connection() as connection:
        assert connection.execute("SELECT COUNT(*) FROM observation_events").fetchone()[0] == 0

def test_equivalent_paths_count_as_one_location(trail: ThreatTrail, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.chdir(tmp_path)
    path = tmp_path / "same-path.txt"; path.write_bytes(b"normalized path")
    first = trail.record_file(path); second = trail.record_file("./same-path.txt")
    assert first.id == second.id and second.seen_count == 2
    assert len(trail.get_observations(first.sha256)) == 1