import errno, hashlib, os, sqlite3
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from datetime import timedelta
from pathlib import Path
from types import SimpleNamespace
from uuid import UUID
import pytest
from app.config import AppConfig
from app.database import Database
from app.detector import Detector
from app.hashing import normalize_path
from app.models import DetectionStatus, ScanResult, ScanSessionStatus, ScanSource, ScanStatus, ScanType, SignatureKind
from app.scan_history import ScanHistory, ScanHistoryError
from app.scanner import Scanner
from app.signatures import AUTOGUARD_TEST_CONTENT, load_signatures
from app.threat_trail import ThreatTrail

@pytest.fixture
def setup(tmp_path):
    config = AppConfig(data_dir=tmp_path / "runtime"); config.create_directories()
    database = Database(config.database_path); database.initialize()
    history = ScanHistory(database); scanner = Scanner(Detector(load_signatures()), ThreatTrail(database), history=history)
    files = tmp_path / "files"; files.mkdir()
    return scanner, history, files, database

def write_file(root, name="normal.txt", content=b"ordinary content"):
    path = root / name; path.write_bytes(content); return path

def test_start_session_has_unique_id_utc_times_and_zero_counters(setup):
    _, history, files, _ = setup; first = history.start_session(ScanType.MANUAL, files); second = history.start_session(ScanType.MANUAL, files)
    assert UUID(first.id).version == 4 and first.id != second.id and first.source_path == str(normalize_path(files)) and first.source is ScanSource.MANUAL and first.status is ScanSessionStatus.RUNNING and first.started_at.utcoffset() == timedelta(0) and first.finished_at is None and first.error is None and all(v == 0 for v in first.counters.values()) and history.get_scan(first.id).session == first and history.get_scan(first.id).results == ()

@pytest.mark.parametrize("scan_type", list(ScanType))
def test_scan_types_and_default_observation_sources(setup, scan_type):
    scanner, history, files, _ = setup; summary = scanner.scan(write_file(files), scan_type=scan_type); saved = history.get_scan(summary.session_id)
    assert saved.session.scan_type is scan_type and saved.session.source is scan_type.default_source and summary.results[0].observation.source is scan_type.default_source and saved.session.status is ScanSessionStatus.COMPLETED

@pytest.mark.parametrize("method,directory", [("scan", False), ("scan", True), ("scan_file", False), ("scan_directory", True)])
def test_each_public_entrypoint_creates_exactly_one_session(setup, method, directory):
    scanner, history, files, _ = setup; path = write_file(files); result = getattr(scanner, method)(files if directory else path, ScanSource.FILE_MONITOR); saved = history.get_scan(result.session_id)
    assert len(history.recent_scans()) == 1 and saved.session.scan_type is ScanType.REAL_TIME and saved.session.counters["scanned_files"] == 1 and len(saved.results) == 1 and saved.results[0].session_id == result.session_id

def test_scan_type_and_explicit_source_are_independent_metadata(setup):
    scanner, history, files, _ = setup; result = scanner.scan(write_file(files), ScanSource.SCHEDULED, scan_type=ScanType.FULL); session = history.get_scan(result.session_id).session
    assert session.scan_type is ScanType.FULL and session.source is ScanSource.SCHEDULED and result.results[0].observation.source is ScanSource.SCHEDULED

def test_all_file_results_and_evidence_survive_reopening_and_file_removal(setup):
    scanner, _, files, database = setup; write_file(files, "normal.txt"); write_file(files, "empty.txt", b""); write_file(files, "test.txt", AUTOGUARD_TEST_CONTENT); write_file(files, "invoice.pdf.exe", b"harmless double-extension fixture"); summary = scanner.scan_directory(files)
    for path in files.iterdir(): path.unlink()
    history = ScanHistory(Database(database.path)); saved = history.get_scan(summary.session_id)
    assert saved.session.status is ScanSessionStatus.COMPLETED and saved.session.finished_at >= saved.session.started_at and saved.session.finished_at.utcoffset() == timedelta(0) and saved.session.error is None and saved.session.counters == summary.counts and len(saved.results) == 4
    for actual, original in zip(saved.results, summary.results):
        assert actual.path == original.path and actual.sha256 == original.sha256 == original.detection.sha256 and actual.result_category is original.status and actual.detection_status is original.detection.status and actual.detection_confidence == original.detection.confidence and actual.rule_name == original.detection.rule_name and actual.reason == original.reason and actual.detection_reason == original.detection.reason
    high = next(r for r in saved.results if r.detection_status is DetectionStatus.HIGH_CONFIDENCE)
    assert high.matched_signature_kind is SignatureKind.AUTOGUARD_TEST and high.matched_signature_name == "AutoGuard.Harmless.Test" and saved.session.counters["dangerous_detections"] == 1 and saved.session.counters["suspicious_detections"] == 1

def test_mixed_outcomes_persist_exact_summary_statistics(setup, monkeypatch):
    original, history, files, database = setup; scanner = Scanner(original.detector, original.threat_trail, max_file_size_bytes=64)
    write_file(files, "clean.txt"); write_file(files, "test.txt", AUTOGUARD_TEST_CONTENT); write_file(files, "invoice.pdf.exe"); write_file(files, "large.txt", b"x" * 65); write_file(files, "locked.txt"); write_file(files, "error.txt"); write_file(files, "unsupported.bin"); (files / "blocked").mkdir()
    real_open, real_lstat, real_scandir = open, Path.lstat, os.scandir
    def guarded_open(path, *args, **kwargs):
        if Path(path).name == "locked.txt": raise PermissionError(errno.EACCES, "file locked")
        if Path(path).name == "error.txt": raise OSError(errno.EIO, "read error")
        return real_open(path, *args, **kwargs)
    def guarded_lstat(path, *args, **kwargs):
        info = real_lstat(path, *args, **kwargs); return SimpleNamespace(st_mode=info.st_mode, st_file_attributes=0x400) if path.name == "unsupported.bin" else info
    def guarded_scandir(path):
        if Path(path).name == "blocked": raise PermissionError(errno.EACCES, "directory denied")
        return real_scandir(path)
    monkeypatch.setattr("app.hashing.open", guarded_open, raising=False); monkeypatch.setattr(Path, "lstat", guarded_lstat); monkeypatch.setattr("app.scanner.os.scandir", guarded_scandir)
    summary = scanner.scan_directory(files); saved = history.get_scan(summary.session_id)
    assert saved.session.counters == summary.counts == {"discovered_files": 7, "scanned_files": 3, "dangerous_detections": 1, "suspicious_detections": 1, "skipped_size": 1, "locked_files": 1, "unsupported_files": 1, "errors": 2, "file_errors": 1, "directory_issues": 1, "unclassified_entries": 0} and saved.session.status is ScanSessionStatus.INCOMPLETE and saved.session.error and saved.session.finished_at and len(saved.results) == 8 and all(r.sha256 is None for r in saved.results if r.result_category is not ScanStatus.SCANNED)
    with database.connection() as connection: assert connection.execute("SELECT COUNT(*) FROM observation_events").fetchone()[0] == 3

def test_missing_target_produces_failed_session_with_error(setup):
    scanner, history, files, _ = setup; summary = scanner.scan(files / "missing.txt"); saved = history.get_scan(summary.session_id)
    assert saved.session.status is ScanSessionStatus.FAILED and saved.session.finished_at is not None and "FileNotFoundError" in saved.session.error and saved.session.counters["errors"] == 1 and saved.session.counters["unclassified_entries"] == 1 and saved.session.counters["discovered_files"] == 0 and saved.results[0].sha256 is None

def test_only_skipped_files_are_incomplete_and_empty_directory_is_completed(setup):
    original, history, files, _ = setup; scanner = Scanner(original.detector, original.threat_trail, max_file_size_bytes=0)
    empty = scanner.scan_directory(files); skipped = scanner.scan_file(write_file(files))
    assert history.get_scan(empty.session_id).session.status is ScanSessionStatus.COMPLETED and history.get_scan(empty.session_id).results == () and history.get_scan(skipped.session_id).session.status is ScanSessionStatus.INCOMPLETE and history.get_scan(skipped.session_id).session.counters["skipped_size"] == 1

def test_detector_failure_keeps_available_hash(setup, monkeypatch):
    scanner, history, files, _ = setup; path = write_file(files)
    monkeypatch.setattr(scanner.detector, "detect_inspection", lambda *a: (_ for _ in ()).throw(RuntimeError("detector fixture failed")))
    result = scanner.scan_file(path); saved = history.get_scan(result.session_id)
    assert saved.session.status is ScanSessionStatus.FAILED and saved.results[0].sha256 == hashlib.sha256(path.read_bytes()).hexdigest() and saved.results[0].detection_status is None and saved.results[0].detection_confidence is None and "Detection failed" in saved.results[0].reason

def test_observation_failure_keeps_detection_and_processing_error(setup, monkeypatch):
    scanner, history, files, _ = setup
    monkeypatch.setattr(scanner.threat_trail, "record_fingerprint", lambda *a: (_ for _ in ()).throw(sqlite3.OperationalError("observation fixture failed")))
    result = scanner.scan_file(write_file(files, "test.txt", AUTOGUARD_TEST_CONTENT)); saved = history.get_scan(result.session_id)
    assert saved.session.status is ScanSessionStatus.FAILED and saved.session.counters["dangerous_detections"] == 1 and saved.session.counters["scanned_files"] == 0 and saved.results[0].result_category is ScanStatus.ERROR and saved.results[0].detection_status is DetectionStatus.HIGH_CONFIDENCE and saved.results[0].detection_reason == result.detection.reason and "Recording failed" in saved.results[0].reason

@pytest.mark.parametrize("error,status", [(RuntimeError("unexpected failure"), ScanSessionStatus.FAILED), (KeyboardInterrupt(), ScanSessionStatus.INCOMPLETE), (SystemExit("shutdown"), ScanSessionStatus.INCOMPLETE)])
def test_aborted_scans_preserve_already_committed_progress(setup, monkeypatch, error, status):
    scanner, history, files, _ = setup; write_file(files, "first.txt"); write_file(files, "second.txt"); process, calls = scanner._process_file, 0
    def abort_second(*args):
        nonlocal calls; calls += 1
        if calls == 2:
            running = history.recent_scans()[0]
            assert running.status is ScanSessionStatus.RUNNING and running.counters["scanned_files"] == 1 and len(history.get_scan(running.id).results) == 1; raise error
        return process(*args)
    monkeypatch.setattr(scanner, "_process_file", abort_second)
    with pytest.raises(type(error)): scanner.scan_directory(files)
    session = history.recent_scans()[0]
    assert session.status is status and session.finished_at >= session.started_at and type(error).__name__ in session.error and session.counters["scanned_files"] == 1 and len(history.get_scan(session.id).results) == 1

def test_history_creation_failure_prevents_scanning(setup, monkeypatch):
    scanner, history, files, database = setup; path = write_file(files)
    with database.connection() as connection: connection.execute("CREATE TRIGGER reject_start BEFORE INSERT ON scan_sessions BEGIN SELECT RAISE(ABORT, 'start blocked'); END")
    monkeypatch.setattr(scanner, "_process_file", lambda *a: pytest.fail("File was processed without a durable session"))
    with pytest.raises(ScanHistoryError, match="start blocked") as raised: scanner.scan(path)
    assert raised.value.session_id is None and history.recent_scans() == []

def test_history_result_failure_marks_session_failed_with_partial_totals(setup):
    scanner, history, files, database = setup; write_file(files, "first.txt"); write_file(files, "second.txt")
    with database.connection() as connection: connection.execute("CREATE TRIGGER reject_second BEFORE INSERT ON scan_results WHEN (SELECT COUNT(*) FROM scan_results WHERE session_id = NEW.session_id) = 1 BEGIN SELECT RAISE(ABORT, 'result blocked'); END")
    with pytest.raises(ScanHistoryError, match="result blocked") as raised: scanner.scan_directory(files)
    saved = history.get_scan(raised.value.session_id)
    assert saved.session.status is ScanSessionStatus.FAILED and saved.session.counters["scanned_files"] == len(saved.results) == 1 and "saving result for" in saved.session.error and saved.session.finished_at is not None

def test_result_and_counters_roll_back_together(setup):
    _, history, files, database = setup; session = history.start_session(ScanType.MANUAL, files); outcome = ScanResult(str(files / "large.txt"), ScanStatus.SKIPPED_SIZE, "test threshold")
    with database.connection() as connection: connection.execute("CREATE TRIGGER reject_counters BEFORE UPDATE OF skipped_size ON scan_sessions BEGIN SELECT RAISE(ABORT, 'counter blocked'); END")
    with pytest.raises(sqlite3.IntegrityError, match="counter blocked"): history.record_result(session.id, outcome)
    saved = history.get_scan(session.id); assert saved.results == () and saved.session == session

@pytest.mark.parametrize("permanent", [False, True])
def test_finalization_failure_is_never_reported_as_success(setup, permanent):
    scanner, history, files, database = setup; path = write_file(files); condition = "" if permanent else "WHEN NEW.status = 'COMPLETED'"
    with database.connection() as connection: connection.execute(f"CREATE TRIGGER reject_finish BEFORE UPDATE OF status ON scan_sessions {condition} BEGIN SELECT RAISE(ABORT, 'finish blocked'); END")
    with pytest.raises(ScanHistoryError, match="finish blocked") as raised: scanner.scan(path)
    saved = history.get_scan(raised.value.session_id); assert saved.session.counters["scanned_files"] == len(saved.results) == 1
    if permanent: assert saved.session.status is ScanSessionStatus.RUNNING and saved.session.finished_at is None and "could not finalize history" in str(raised.value)
    else: assert saved.session.status is ScanSessionStatus.FAILED and "finalizing history" in saved.session.error

def test_recent_history_orders_ties_limits_results_and_includes_running_scans(setup, monkeypatch):
    _, history, files, database = setup; assert history.recent_scans() == [] and history.get_scan("unknown") is None
    monkeypatch.setattr("app.scan_history._utc_now", lambda: "2026-09-14T12:00:00.000000+00:00")
    first = history.start_session(ScanType.MANUAL, files); history.finish_session(first.id)
    second = history.start_session(ScanType.USB, files); history.finish_session(second.id, error="device disconnected")
    third = history.start_session(ScanType.MATCHING_COPY, files); reopened = ScanHistory(Database(database.path))
    assert [s.id for s in reopened.recent_scans(2)] == [third.id, second.id] and [s.id for s in reopened.recent_scans()] == [third.id, second.id, first.id] and reopened.recent_scans()[0].status is ScanSessionStatus.RUNNING

@pytest.mark.parametrize("limit", [0, -1, True, 1.5])
def test_invalid_history_limit_is_rejected(setup, limit):
    with pytest.raises(ValueError, match="positive integer"): setup[1].recent_scans(limit)

def test_finalized_sessions_reject_appends_and_second_finalization(setup):
    _, history, files, _ = setup; first = history.start_session(ScanType.MANUAL, files); other = history.start_session(ScanType.MANUAL, files)
    result = ScanResult(str(files / "large.txt"), ScanStatus.SKIPPED_SIZE, "threshold", session_id=first.id)
    with pytest.raises(ValueError, match="different scan"): history.record_result(other.id, result)
    history.record_result(first.id, result); completed = history.finish_session(first.id)
    with pytest.raises(ValueError, match="already finalized"): history.record_result(first.id, result)
    with pytest.raises(ValueError, match="already finalized"): history.finish_session(first.id)
    assert history.get_scan(first.id).session == completed and len(history.get_scan(first.id).results) == 1

def test_concurrent_result_writes_do_not_lose_counters(setup):
    _, history, files, _ = setup; session = history.start_session(ScanType.MANUAL, files)
    record = lambda i: history.record_result(session.id, ScanResult(str(files / f"large-{i}.txt"), ScanStatus.SKIPPED_SIZE, "threshold"))
    with ThreadPoolExecutor(max_workers=4) as executor: recorded = list(executor.map(record, range(12)))
    final = history.finish_session(session.id)
    assert len({r.id for r in recorded}) == 12 and final.counters["discovered_files"] == final.counters["skipped_size"] == 12 and len(history.get_scan(session.id).results) == 12

def test_session_and_results_are_read_from_one_snapshot(setup, monkeypatch):
    _, writer, files, database = setup; session = writer.start_session(ScanType.MANUAL, files); reader_database = Database(database.path); real_connection = reader_database.connection
    @contextmanager
    def interleaved_connection():
        with real_connection() as connection:
            class Reader:
                def execute(self, sql, parameters=()):
                    cursor = connection.execute(sql, parameters)
                    if sql.startswith("SELECT * FROM scan_sessions"): writer.record_result(session.id, ScanResult(str(files / "large.txt"), ScanStatus.SKIPPED_SIZE, "threshold"))
                    return cursor
            yield Reader()
    monkeypatch.setattr(reader_database, "connection", interleaved_connection)
    snapshot = ScanHistory(reader_database).get_scan(session.id)
    assert snapshot.session.counters["discovered_files"] == 0 and snapshot.results == ()
    latest = writer.get_scan(session.id)
    assert latest.session.counters["discovered_files"] == len(latest.results) == 1

def test_phase3_database_upgrade_preserves_threat_trail_and_is_repeatable(tmp_path):
    legacy_schema = """
    CREATE TABLE file_observations (id INTEGER PRIMARY KEY, sha256 TEXT NOT NULL CHECK (length(sha256) = 64 AND sha256 NOT GLOB '*[^0-9a-f]*'), path TEXT NOT NULL CHECK (length(path) > 0), source TEXT NOT NULL CHECK (source IN ('manual', 'startup', 'scheduled', 'file_monitor', 'usb', 'matching_copy', 'recovery')), size_bytes INTEGER NOT NULL CHECK (size_bytes >= 0), first_seen TEXT NOT NULL, last_seen TEXT NOT NULL CHECK (last_seen >= first_seen), seen_count INTEGER NOT NULL DEFAULT 1 CHECK (seen_count >= 1), UNIQUE (sha256, path));
    CREATE TABLE observation_events (id INTEGER PRIMARY KEY, observation_id INTEGER NOT NULL REFERENCES file_observations(id) ON DELETE RESTRICT, source TEXT NOT NULL CHECK (source IN ('manual', 'startup', 'scheduled', 'file_monitor', 'usb', 'matching_copy', 'recovery')), observed_at TEXT NOT NULL);
    CREATE INDEX idx_observations_path ON file_observations(path); CREATE INDEX idx_events_observation_time ON observation_events(observation_id, observed_at, id);
    """
    database = Database(tmp_path / "legacy.db")
    with database.connection() as connection:
        connection.executescript(legacy_schema); original_schema = connection.execute("SELECT name, sql FROM sqlite_master ORDER BY name").fetchall()
    trail = ThreatTrail(database); path = write_file(tmp_path); observation = trail.record_file(path, ScanSource.USB); events = trail.get_events(observation.sha256); database.initialize(); database.initialize()
    assert trail.get_observations(observation.sha256) == [observation] and trail.get_events(observation.sha256) == events
    with database.connection() as connection:
        upgraded_schema = dict(connection.execute("SELECT name, sql FROM sqlite_master"))
        assert all(upgraded_schema[name] == sql for name, sql in original_schema) and {"scan_sessions", "scan_results"} <= upgraded_schema.keys() and connection.execute("PRAGMA foreign_keys").fetchone()[0] == 1
        with pytest.raises(sqlite3.IntegrityError, match="FOREIGN KEY"): connection.execute("INSERT INTO scan_results (session_id, path, result_category, entry_kind, reason, recorded_at) VALUES ('missing-session', 'file.txt', 'ERROR', 'file', 'fixture', '2026-09-14')")
    result = Scanner(Detector(load_signatures()), trail).scan(path); saved = ScanHistory(database).get_scan(result.session_id); database.initialize()
    assert ScanHistory(database).get_scan(result.session_id) == saved and trail.get_observations(observation.sha256)[0].seen_count == 2

def test_latest_detection_for_sha256_returns_newest_persisted_evidence(setup):
    scanner, history, files, _ = setup; path = write_file(files, "phase7-threat.txt", AUTOGUARD_TEST_CONTENT); first = scanner.scan(path, scan_type=ScanType.MANUAL); second = scanner.scan(path, scan_type=ScanType.REAL_TIME); sha256 = first.results[0].sha256
    latest = history.latest_detection_for_sha256(sha256)
    assert latest is not None and latest.session_id == second.session_id and latest.sha256 == sha256 and latest.detection_status is DetectionStatus.HIGH_CONFIDENCE
    with pytest.raises(ValueError, match="64 hexadecimal"): history.latest_detection_for_sha256("not-a-hash")