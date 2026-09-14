import errno, hashlib, os, sqlite3
from pathlib import Path
from types import SimpleNamespace

import pytest

from app.config import DEFAULT_MAX_FILE_SIZE_BYTES, AppConfig
from app.database import Database
from app.detector import Detector
from app.hashing import inspect_file, normalize_path
from app.models import DetectionStatus, ScanSource
from app.scanner import Scanner, ScanStatus
from app.signatures import AUTOGUARD_TEST_CONTENT, load_signatures
from app.threat_trail import ThreatTrail

@pytest.fixture
def setup(tmp_path: Path) -> tuple[Scanner, Path, ThreatTrail]:
    config = AppConfig(data_dir=tmp_path / "runtime"); config.create_directories()
    database = Database(config.database_path); database.initialize()
    trail = ThreatTrail(database); files = tmp_path / "files"; files.mkdir()
    return Scanner(Detector(load_signatures()), trail), files, trail

def write_file(root: Path, name: str, content: bytes = b"ordinary content") -> Path:
    path = root / name; path.parent.mkdir(parents=True, exist_ok=True); path.write_bytes(content)
    return path

def assert_file_counters(counts: dict[str, int]) -> None:
    assert counts["discovered_files"] == sum(counts[key] for key in ("scanned_files", "skipped_size", "locked_files", "unsupported_files", "file_errors"))

def test_single_file_hashes_once_and_records_same_fingerprint(setup, monkeypatch) -> None:
    scanner, files, trail = setup; path = write_file(files, "normal.txt"); inspections = []

    def inspect_once(*args, **kwargs):
        result = inspect_file(*args, **kwargs); inspections.append(result)
        return result

    def unexpected_read(*args, **kwargs): raise AssertionError("Detector or Threat Trail reread the file")

    monkeypatch.setattr("app.scanner.inspect_file", inspect_once)
    monkeypatch.setattr("app.detector.inspect_file", unexpected_read)
    monkeypatch.setattr("app.threat_trail.hash_file", unexpected_read)
    result = scanner.scan_file(path, ScanSource.STARTUP)

    assert result.status is ScanStatus.SCANNED
    assert len(inspections) == 1
    assert result.detection.sha256 == inspections[0].fingerprint.sha256
    assert result.observation.sha256 == result.detection.sha256
    assert result.observation.source is ScanSource.STARTUP
    assert result.observation.seen_count == 1
    assert len(trail.get_events(result.detection.sha256)) == 1
    assert path.read_bytes() == b"ordinary content"

def test_nested_directories_and_identical_content(setup) -> None:
    scanner, files, trail = setup
    write_file(files, "first.txt", b"same content"); write_file(files, "nested/second.txt", b"same content")
    write_file(files, "nested/deep/empty.txt", b""); write_file(files, "unknown.bin", b"\x00\xff\x01")
    write_file(files, "archive.zip", b"Archive bytes are hashed without extraction."); (files / "empty-directory").mkdir()

    summary = scanner.scan_directory(files, ScanSource.SCHEDULED)

    assert summary.counts["discovered_files"] == 5; assert summary.counts["scanned_files"] == 5; assert summary.counts["errors"] == 0
    assert summary.message == "No threats detected"
    assert all(result.observation.source is ScanSource.SCHEDULED for result in summary.results)
    digest = hashlib.sha256(b"same content").hexdigest()
    assert len(trail.get_observations(digest)) == 2; assert len(trail.get_events(digest)) == 2
    assert_file_counters(summary.counts)

def test_size_limit_is_checked_before_hashing_and_includes_boundary(setup, monkeypatch) -> None:
    original, files, trail = setup; scanner = Scanner(original.detector, trail, max_file_size_bytes=4)
    large = write_file(files, "large.txt", b"12345"); write_file(files, "boundary.txt", b"1234"); write_file(files, "empty.txt", b""); inspected = []

    def track_inspection(path, **kwargs):
        inspected.append(path); return inspect_file(path, **kwargs)

    monkeypatch.setattr("app.scanner.inspect_file", track_inspection)
    summary = scanner.scan(files)

    assert normalize_path(large) not in inspected
    assert len(inspected) == 2; assert summary.counts["discovered_files"] == 3
    assert summary.counts["scanned_files"] == 2; assert summary.counts["skipped_size"] == 1
    skipped = next(result for result in summary.results if result.status is ScanStatus.SKIPPED_SIZE)
    assert skipped.detection is None and skipped.observation is None
    assert "Scan incomplete" in summary.message
    assert_file_counters(summary.counts)

@pytest.mark.parametrize("error,status", [
    (PermissionError(errno.EACCES, "access denied"), ScanStatus.SKIPPED_LOCKED),
    (OSError(errno.EBUSY, "file busy"), ScanStatus.SKIPPED_LOCKED),
    (OSError(errno.EIO, "read failed"), ScanStatus.ERROR),
    (FileNotFoundError(errno.ENOENT, "file disappeared"), ScanStatus.ERROR),
])
def test_read_failures_are_reported_and_scan_continues(setup, monkeypatch, error, status) -> None:
    scanner, files, trail = setup; bad = write_file(files, "bad.txt", b"unreadable fixture"); write_file(files, "good.txt", b"readable fixture"); real_open = open

    def guarded_open(path, *args, **kwargs):
        if Path(path).name == bad.name: raise error
        return real_open(path, *args, **kwargs)

    monkeypatch.setattr("app.hashing.open", guarded_open, raising=False)
    summary = scanner.scan_directory(files)
    failed = next(result for result in summary.results if result.path == str(normalize_path(bad)))

    assert failed.status is status; assert failed.detection is None and failed.observation is None; assert failed.reason
    assert summary.counts["discovered_files"] == 2; assert summary.counts["scanned_files"] == 1
    assert summary.counts["locked_files"] == int(status is ScanStatus.SKIPPED_LOCKED)
    assert summary.counts["errors"] == int(status is ScanStatus.ERROR)
    assert trail.get_observations(hashlib.sha256(b"unreadable fixture").hexdigest()) == []
    assert_file_counters(summary.counts)

def test_inaccessible_directory_is_not_counted_as_a_file(setup, monkeypatch) -> None:
    scanner, files, _ = setup; write_file(files, "visible.txt"); write_file(files, "blocked/hidden.txt"); real_scandir = os.scandir

    def guarded_scandir(path):
        if Path(path).name == "blocked": raise PermissionError(errno.EACCES, "directory denied", str(path))
        return real_scandir(path)

    monkeypatch.setattr("app.scanner.os.scandir", guarded_scandir)
    summary = scanner.scan_directory(files)

    assert summary.counts["discovered_files"] == 1; assert summary.counts["scanned_files"] == 1; assert summary.counts["errors"] == 1
    assert summary.counts["directory_issues"] == 1; assert summary.counts["file_errors"] == 0
    issue = next(result for result in summary.results if result.kind == "directory")
    assert issue.status is ScanStatus.ERROR; assert "directory denied" in issue.reason; assert "Scan incomplete" in summary.message

def test_partial_directory_listing_keeps_already_discovered_files(setup, monkeypatch) -> None:
    scanner, files, _ = setup; write_file(files, "visible.txt"); real_scandir = os.scandir
    with real_scandir(files) as entries: entry = next(entries)

    class BrokenListing:
        def __enter__(self): return self
        def __exit__(self, *args): return False
        def __iter__(self):
            yield entry; raise OSError(errno.EIO, "listing interrupted")

    monkeypatch.setattr("app.scanner.os.scandir", lambda path: BrokenListing())
    summary = scanner.scan_directory(files)
    assert summary.counts["scanned_files"] == 1; assert summary.counts["discovered_files"] == 1
    assert summary.counts["directory_issues"] == 1; assert summary.counts["errors"] == 1

def test_mixed_outcomes_have_accurate_counters(setup, monkeypatch) -> None:
    original, files, trail = setup; scanner = Scanner(original.detector, trail, max_file_size_bytes=64)
    write_file(files, "normal.txt", b"hello"); write_file(files, "empty.txt", b"")
    write_file(files, "test-signature.txt", AUTOGUARD_TEST_CONTENT); write_file(files, "invoice.pdf.exe", b"harmless filename fixture")
    write_file(files, "example.cmd", b"powershell -EncodedCommand WA=="); write_file(files, "large.txt", b"x" * 65)
    write_file(files, "locked.txt"); write_file(files, "error.txt"); unsupported = write_file(files, "unsupported.bin"); real_lstat, real_open = Path.lstat, open

    def lstat(path, *args, **kwargs):
        info = real_lstat(path, *args, **kwargs)
        if path.name == unsupported.name: return SimpleNamespace(st_mode=info.st_mode, st_file_attributes=0x400)
        return info

    def guarded_open(path, *args, **kwargs):
        if Path(path).name == "locked.txt": raise PermissionError(errno.EACCES, "locked")
        if Path(path).name == "error.txt": raise OSError(errno.EIO, "read error")
        return real_open(path, *args, **kwargs)

    monkeypatch.setattr(Path, "lstat", lstat)
    monkeypatch.setattr("app.hashing.open", guarded_open, raising=False)
    summary = scanner.scan_directory(files)

    assert summary.counts == {"discovered_files": 9, "scanned_files": 5, "dangerous_detections": 1, "suspicious_detections": 2, "skipped_size": 1, "locked_files": 1, "unsupported_files": 1, "errors": 1, "file_errors": 1, "directory_issues": 0, "unclassified_entries": 0}
    assert len(summary.results) == 9; assert_file_counters(summary.counts)
    with trail.database.connection() as connection: assert connection.execute("SELECT COUNT(*) FROM observation_events").fetchone()[0] == 5
    assert "No threats detected" not in summary.message; assert all(path.exists() for path in files.iterdir())

def test_links_and_directory_loops_are_reported_without_following(setup) -> None:
    scanner, files, _ = setup; target = write_file(files, "normal.txt")
    try:
        (files / "alias.txt").symlink_to(target); (files / "loop").symlink_to(files, target_is_directory=True); (files / "broken.txt").symlink_to(files / "missing.txt")
    except OSError as error: pytest.skip(f"Symlink creation is unavailable: {error}")
    summary = scanner.scan_directory(files)
    assert summary.counts["discovered_files"] == 4; assert summary.counts["scanned_files"] == 1; assert summary.counts["unsupported_files"] == 3; assert summary.counts["errors"] == 0
    assert_file_counters(summary.counts)

@pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="FIFO files require POSIX")
def test_special_file_is_skipped_without_opening(setup, monkeypatch) -> None:
    scanner, files, _ = setup; pipe = files / "named-pipe"; os.mkfifo(pipe)

    def unexpected_inspection(*args, **kwargs): raise AssertionError("Special file was opened")

    monkeypatch.setattr("app.scanner.inspect_file", unexpected_inspection)
    assert scanner.scan_file(pipe).status is ScanStatus.SKIPPED_UNSUPPORTED

def test_file_growth_during_read_enforces_byte_limit(setup, monkeypatch) -> None:
    original, files, trail = setup; scanner = Scanner(original.detector, trail, max_file_size_bytes=8); path = write_file(files, "growing.txt", b"abc"); real_open = open; read_sizes = []

    class GrowingReader:
        def __init__(self, stream): self.stream = stream; self.changed = False
        def __enter__(self): return self
        def __exit__(self, *args): return self.stream.__exit__(*args)
        def fileno(self): return self.stream.fileno()
        def read(self, size):
            read_sizes.append(size); chunk = self.stream.read(size)
            if not self.changed:
                self.changed = True
                with path.open("ab") as writer: writer.write(b"0123456789")
            return chunk

    monkeypatch.setattr("app.hashing.open", lambda *args, **kwargs: GrowingReader(real_open(*args, **kwargs)), raising=False)
    result = scanner.scan_file(path)
    assert result.status is ScanStatus.SKIPPED_SIZE
    assert result.detection is None and result.observation is None
    assert max(read_sizes) <= 9

def test_changed_file_is_an_error_and_not_recorded(setup, monkeypatch) -> None:
    scanner, files, trail = setup; path = write_file(files, "changing.txt", b"initial"); real_fstat = os.fstat; calls = 0

    def change_file(descriptor):
        nonlocal calls; calls += 1
        if calls == 2:
            with path.open("ab") as writer: writer.write(b" changed")
        return real_fstat(descriptor)

    monkeypatch.setattr("app.hashing.os.fstat", change_file)
    result = scanner.scan_file(path)
    assert result.status is ScanStatus.ERROR; assert "FileChangedError" in result.reason; assert result.observation is None
    assert trail.get_observations(hashlib.sha256(b"initial").hexdigest()) == []

def test_recording_failure_preserves_dangerous_detection(setup, monkeypatch) -> None:
    scanner, files, trail = setup; path = write_file(files, "test.txt", AUTOGUARD_TEST_CONTENT)

    def fail_recording(*args, **kwargs): raise sqlite3.OperationalError("database is locked")

    monkeypatch.setattr(trail, "record_fingerprint", fail_recording)
    summary = scanner.scan(path); result = summary.results[0]
    assert result.status is ScanStatus.ERROR; assert result.observation is None
    assert result.detection.status is DetectionStatus.HIGH_CONFIDENCE
    assert summary.counts["scanned_files"] == 0; assert summary.counts["dangerous_detections"] == 1
    assert summary.counts["errors"] == 1; assert summary.counts["locked_files"] == 0
    assert "No threats detected" not in summary.message
    assert_file_counters(summary.counts)

def test_detector_failure_is_reported(setup, monkeypatch) -> None:
    scanner, files, _ = setup; path = write_file(files, "normal.txt")

    def fail_detection(*args, **kwargs): raise RuntimeError("rule failed")

    monkeypatch.setattr(scanner.detector, "detect_inspection", fail_detection)
    result = scanner.scan_file(path)
    assert result.status is ScanStatus.ERROR; assert "Detection failed" in result.reason
    assert result.detection is None and result.observation is None

def test_repeated_scans_keep_independent_counts_and_historical_events(setup) -> None:
    scanner, files, trail = setup; path = write_file(files, "normal.txt")
    first = scanner.scan(path, ScanSource.STARTUP); second = scanner.scan(path, ScanSource.SCHEDULED)
    assert first.counts["scanned_files"] == second.counts["scanned_files"] == 1
    observation = second.results[0].observation
    assert observation.seen_count == 2; assert observation.id == first.results[0].observation.id
    assert [event.source for event in trail.get_events(observation.sha256)] == [ScanSource.STARTUP, ScanSource.SCHEDULED]

def test_empty_directory_has_zero_counters(setup) -> None:
    scanner, files, _ = setup; summary = scanner.scan_directory(files)
    assert summary.results == (); assert all(value == 0 for value in summary.counts.values())
    assert summary.message == "No threats detected. No files were found"

def test_missing_path_and_wrong_target_types_are_explicit(setup) -> None:
    scanner, files, _ = setup; missing = scanner.scan(files / "missing.txt")
    assert missing.counts["discovered_files"] == 0; assert missing.counts["unclassified_entries"] == 1; assert missing.counts["errors"] == 1
    assert "No files were successfully scanned" in missing.message
    assert scanner.scan_file(files).status is ScanStatus.SKIPPED_UNSUPPORTED
    path = write_file(files, "normal.txt"); wrong_type = scanner.scan_directory(path)
    assert wrong_type.results[0].status is ScanStatus.SKIPPED_UNSUPPORTED

def test_active_database_is_explicitly_excluded(setup) -> None:
    scanner, _, trail = setup; summary = scanner.scan(trail.database.path)
    assert summary.counts["unsupported_files"] == 1; assert summary.counts["scanned_files"] == 0
    assert "active database" in summary.results[0].reason

def test_default_limit_and_zero_byte_limit(setup) -> None:
    original, files, trail = setup
    assert DEFAULT_MAX_FILE_SIZE_BYTES == 536870912; assert original.max_file_size_bytes == AppConfig().max_file_size_bytes
    scanner = Scanner(original.detector, trail, max_file_size_bytes=0)
    assert scanner.scan_file(write_file(files, "empty.txt", b"")).status is ScanStatus.SCANNED
    assert scanner.scan_file(write_file(files, "one.txt", b"x")).status is ScanStatus.SKIPPED_SIZE

@pytest.mark.parametrize("limit", [-1, True, 1.5])
def test_invalid_size_limit_is_rejected(setup, limit) -> None:
    scanner, _, trail = setup
    with pytest.raises(ValueError): Scanner(scanner.detector, trail, max_file_size_bytes=limit)
    with pytest.raises(ValueError): AppConfig(max_file_size_bytes=limit)