from app.scan_progress import ScanProgress
from app.hashing import OperationInterrupted, inspect_file


def test_discovery_has_no_percentage_or_eta_until_inventory_is_known():
    progress = ScanProgress.start(now=10)
    progress.record_result(now=11)
    progress.record_result(now=12)
    assert progress.snapshot(now=12)["phase"] == "discovering"
    assert progress.snapshot(now=12)["total"] is None
    assert progress.snapshot(now=12)["eta_seconds"] is None


def test_eta_uses_smoothed_measured_throughput_and_remaining_entries():
    progress = ScanProgress.start(now=0)
    progress.set_phase("scanning", total=20)
    progress.record_result(size_bytes=100, now=1)
    progress.record_result(size_bytes=200, now=2)
    assert progress.snapshot(now=2)["eta_seconds"] is None
    progress.record_result(size_bytes=300, now=3)
    snapshot = progress.snapshot(now=3)
    assert snapshot["eta_seconds"] is not None
    assert snapshot["eta_seconds"] > 0
    assert snapshot["processed"] == 3
    assert snapshot["total"] == 20
    assert snapshot["elapsed"] == 3
    assert snapshot["bytes_processed"] == 600


def test_unknown_total_does_not_produce_an_eta():
    progress = ScanProgress.start(now=0)
    progress.set_phase("scanning")
    for now in range(1, 6):
        progress.record_result(now=now)
    assert progress.snapshot(now=5)["eta_seconds"] is None


def test_result_count_expands_total_when_live_walk_finds_new_entries():
    progress = ScanProgress.start(now=0)
    progress.set_phase("scanning", total=2)
    for now in range(1, 5):
        progress.record_result(now=now)
    assert progress.snapshot(now=4)["total"] == 4


def test_hashing_checks_cancellation_between_chunks(tmp_path):
    target = tmp_path / "large.bin"
    target.write_bytes(b"x" * (1024 * 64))
    checks = 0

    def stopped():
        nonlocal checks
        checks += 1
        return checks >= 3

    try:
        inspect_file(target, chunk_size=1024, interrupt_check=stopped)
    except OperationInterrupted:
        pass
    else:
        raise AssertionError("hashing should stop after the cancellation flag is set")
    assert checks == 3
