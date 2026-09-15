from __future__ import annotations

import threading
import time
from pathlib import Path
from types import SimpleNamespace

from app.models import ScanResult, ScanStatus, ScanSummary, ScanType
from app.database import Database
from app.detector import Detector
from app.scanner import Scanner
from app.signatures import SignatureStore
from app.threat_trail import ThreatTrail
from app.ui.controller import AutoGuardUIController
from app.ui.messages import UIMessageBus


def wait_for(bus: UIMessageBus, kind: str, timeout: float = 2.0):
    deadline = time.monotonic() + timeout; seen = []
    while time.monotonic() < deadline:
        seen.extend(bus.drain())
        for message in seen:
            if message.kind == kind: return message, seen
        time.sleep(0.01)
    raise AssertionError(f"Timed out waiting for {kind}; saw {[m.kind for m in seen]}")


def test_message_bus_preserves_fifo_order():
    bus = UIMessageBus(); bus.publish("first", value=1); bus.publish("second", value=2)
    assert [message.kind for message in bus.drain()] == ["first", "second"]
    assert bus.pending() == 0


def test_message_bus_validates_kind_and_limit():
    bus = UIMessageBus()
    try: bus.publish("   ")
    except ValueError: pass
    else: raise AssertionError("empty message kind should be rejected")
    try: bus.drain(0)
    except ValueError: pass
    else: raise AssertionError("nonpositive drain limit should be rejected")


class FakeScanner:
    def __init__(self): self.thread_id = None
    def count_scan_entries(self, *args, **kwargs): raise AssertionError("UI must not pre-count scan entries")
    def scan(self, path, source, *, scan_type, on_result=None, on_discovered=None):
        self.thread_id = threading.get_ident(); result = ScanResult(str(path), ScanStatus.SCANNED, "No threat detected.")
        if on_discovered: on_discovered(str(path), "file")
        if on_result: on_result(result)
        time.sleep(0.04); return ScanSummary((result,), "session-1")


def fake_services(scanner):
    scheduler = SimpleNamespace(
        quick_paths=(Path("quick"),), full_paths=(Path("full"),),
        settings=SimpleNamespace(quick_interval_hours=24.0, full_interval_days=7.0),
    )
    return SimpleNamespace(scanner=scanner, scheduler=scheduler)


def test_controller_dispatches_manual_scan_off_calling_thread():
    bus = UIMessageBus(); scanner = FakeScanner(); controller = AutoGuardUIController(fake_services(scanner), bus)
    calling_thread = threading.get_ident(); started = time.monotonic()
    controller.start_scan("example.txt", scan_type=ScanType.MANUAL)
    elapsed = time.monotonic() - started; message, seen = wait_for(bus, "scan_completed")
    try:
        assert elapsed < 0.03
        assert scanner.thread_id is not None and scanner.thread_id != calling_thread
        discovered = next(item for item in seen if item.kind == "scan_discovered")
        assert discovered.payload["discovered"] == 1 and discovered.payload["processed"] == 0
        progress = next(item for item in seen if item.kind == "scan_result")
        assert progress.payload["processed"] == 1 and progress.payload["discovered"] == 1 and progress.payload["progress"] == 1.0
        assert message.payload["result"].session_id == "session-1"
    finally: controller.shutdown()


def test_controller_emits_task_failure_without_raising_on_ui_thread():
    class FailingScanner(FakeScanner):
        def scan(self, *args, **kwargs): raise PermissionError("simulated locked target")
    bus = UIMessageBus(); controller = AutoGuardUIController(fake_services(FailingScanner()), bus)
    controller.start_scan("locked.bin"); failure, _ = wait_for(bus, "task_failed")
    try:
        assert "PermissionError" in failure.payload["error"]
        assert "simulated locked target" in failure.payload["error"]
    finally: controller.shutdown()


def test_scan_progress_callback_failure_does_not_change_scanner_result(tmp_path):
    database = Database(tmp_path / "autoguard.db"); database.initialize()
    scanner = Scanner(Detector(SignatureStore()), ThreatTrail(database))
    target = tmp_path / "safe.txt"; target.write_text("harmless", encoding="utf-8")
    result = scanner.scan_file(target, on_result=lambda _: (_ for _ in ()).throw(RuntimeError("UI gone")))
    assert result.status is ScanStatus.SCANNED


def test_scanner_single_pass_discovery_matches_emitted_results(tmp_path):
    database = Database(tmp_path / "autoguard.db"); database.initialize(); scanner = Scanner(Detector(SignatureStore()), ThreatTrail(database))
    folder = tmp_path / "folder"; folder.mkdir(); (folder / "one.txt").write_text("one", encoding="utf-8")
    nested = folder / "nested"; nested.mkdir(); (nested / "two.txt").write_text("two", encoding="utf-8")
    discovered = []; emitted = []
    summary = scanner.scan(folder, on_discovered=lambda path, kind: discovered.append((path, kind)), on_result=emitted.append)
    assert len(discovered) == 2 == len(emitted) == len(summary.results)
    assert {path for path, _ in discovered} == {result.path for result in summary.results}


def test_controller_never_runs_metadata_precount_before_scan():
    bus = UIMessageBus(); scanner = FakeScanner(); controller = AutoGuardUIController(fake_services(scanner), bus)
    controller.start_scan("instant.txt"); _, seen = wait_for(bus, "scan_completed")
    try:
        kinds = [m.kind for m in seen]
        assert "scan_counting" not in kinds and "scan_total" not in kinds
        assert kinds.index("scan_started") < kinds.index("scan_discovered") < kinds.index("scan_result") < kinds.index("scan_completed")
    finally: controller.shutdown()