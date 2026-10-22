"""Phase 02: durable session sequence, bounded reads and request coordination."""
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from pathlib import Path
import sqlite3
import threading
import time
from types import SimpleNamespace

import pytest

from app.database import Database, SCHEMA
from app.detector import Detector
from app.models import DetectionResult, DetectionStatus, ScanResult, ScanStatus, ScanType, ScanSource, Signature, SignatureKind
from app.scan_history import ScanHistory
from app.scanner import Scanner
from app.signatures import SignatureStore
from app.threat_trail import ThreatTrail
from app.ui.activity_page import ActivityPage, date_bounds
from app.ui.controller import AutoGuardUIController
from app.ui.messages import UIMessage, UIMessageBus


@pytest.fixture
def history(tmp_path):
    database = Database(tmp_path / "history.db")
    database.initialize()
    return ScanHistory(database)


def outcome(index=0, status=ScanStatus.SCANNED, severity=DetectionStatus.NO_DETECTION, kind="file"):
    path = f"C:/example/file-{index}.txt"
    if status is not ScanStatus.SCANNED:
        return ScanResult(path, status, "Recorded skip or error", kind=kind)
    digest = f"{index:064x}"
    signature = Signature("Fixture", digest, SignatureKind.AUTOGUARD_TEST) if severity is DetectionStatus.HIGH_CONFIDENCE else None
    detection = DetectionResult(severity, 1.0 if signature else (0.5 if severity is DetectionStatus.LOW_CONFIDENCE else 0.0),
                                "Recorded detection reason", "fixture", digest, path, signature)
    return ScanResult(path, status, "Processed", detection=detection, sha256=digest)


def wait_message(bus, token, timeout=4):
    until = time.monotonic() + timeout
    while time.monotonic() < until:
        for message in bus.drain():
            if message.payload.get("request_id") == token:
                return message
        time.sleep(0.005)
    raise AssertionError(f"No response for {token}")


def test_order_restarts_and_includes_safe_detections_skips_and_errors(history):
    first = history.start_session(ScanType.QUICK, "C:/one")
    second = history.start_session(ScanType.USB, "C:/two")
    outcomes = [outcome(1), outcome(2, severity=DetectionStatus.LOW_CONFIDENCE),
                outcome(3, severity=DetectionStatus.HIGH_CONFIDENCE),
                outcome(4, ScanStatus.SKIPPED_SIZE), outcome(5, ScanStatus.ERROR),
                outcome(6, ScanStatus.ERROR, kind="directory")]
    for index, result in enumerate(outcomes):
        history.record_result(first.id, result)
        history.record_result(second.id, outcome(index + 20))
    for session in (first, second):
        page = history.result_page(session.id)
        assert page["guaranteed_order"]
        assert [item["order"] for item in page["items"]] == list(range(1, 7))
        assert all(item["result"].session_id == session.id for item in page["items"])
        assert [item["result"].processing_order for item in page["items"]] == list(range(1, 7))
    page = history.result_page(first.id)
    assert page["safe"] == 1
    assert page["session"].counters["scanned_files"] == 3
    assert page["session"].counters["errors"] == 2
    reopened = ScanHistory(Database(history.database.path))
    assert reopened.result_page(first.id)["items"] == page["items"]
    history.finish_session(first.id, interrupted=True)
    assert history.result_page(first.id)["session"].status.value == "INCOMPLETE"
    assert history.result_page(first.id)["total"] == 6


def test_scanner_records_actual_yield_order_and_resets_for_repeated_files(history, tmp_path):
    files = tmp_path / "files"
    files.mkdir()
    for name in ("z.txt", "a.txt", "b.txt"):
        (files / name).write_text("safe", encoding="utf-8")
    scanner = Scanner(Detector(SignatureStore()), ThreatTrail(history.database), history=history)
    for _ in range(2):
        observed = []
        summary = scanner.scan_directory(files, on_result=lambda result: observed.append(result.path))
        saved = history.result_page(summary.session_id)
        assert [row["result"].path for row in saved["items"]] == observed
        assert [row["order"] for row in saved["items"]] == [1, 2, 3]
        assert saved["safe"] == 3


def test_concurrent_sessions_allocate_orders_atomically(history):
    sessions = [history.start_session(ScanType.MANUAL, f"C:/{i}") for i in range(3)]
    jobs = [(session.id, outcome(index)) for session in sessions for index in range(15)]
    with ThreadPoolExecutor(max_workers=4) as executor:
        list(executor.map(lambda args: history.record_result(*args), jobs))
    for session in sessions:
        assert [item["order"] for item in history.result_page(session.id)["items"]] == list(range(1, 16))


def test_legacy_migration_keeps_evidence_and_does_not_invent_sequence(tmp_path):
    path = tmp_path / "legacy.db"
    with sqlite3.connect(path) as connection:
        connection.executescript(SCHEMA)
        connection.execute("INSERT INTO scan_sessions(id, scan_type, source_path, source, started_at) VALUES ('legacy', 'quick', 'C:/test', 'manual', ?)",
                           (datetime.now(timezone.utc).isoformat(),))
        for number in (41, 83):
            connection.execute("INSERT INTO scan_results(id, session_id, path, result_category, entry_kind, reason, recorded_at) VALUES (?, 'legacy', ?, 'ERROR', 'file', 'Original reason', ?)",
                               (number, f"C:/file-{number}", datetime.now(timezone.utc).isoformat()))
    database = Database(path)
    database.initialize()
    database.initialize()
    legacy = ScanHistory(database).result_page("legacy")
    assert not legacy["guaranteed_order"]
    assert [row["order"] for row in legacy["items"]] == [1, 2]
    assert [row["result"].id for row in legacy["items"]] == [41, 83]
    assert all(row["result"].processing_order is None and row["result"].reason == "Original reason" for row in legacy["items"])
    new = ScanHistory(database).start_session(ScanType.FULL, "C:/new")
    ScanHistory(database).record_result(new.id, outcome(1))
    assert ScanHistory(database).result_page(new.id)["items"][0]["order"] == 1


def test_bounded_pagination_and_filters_keep_same_day_sessions_separate(history):
    sessions = [history.start_session(ScanType.QUICK if i % 2 else ScanType.FULL, f"C:/{i}") for i in range(57)]
    for index in range(123):
        history.record_result(sessions[0].id, outcome(index))
    assert len(history.session_page()["items"]) == 50
    assert len(history.session_page(page=1)["items"]) == 7
    assert history.session_page()["items"][0]["session"].id == sessions[-1].id
    assert history.session_page(scan_type="quick")["total"] == 28
    history.finish_session(sessions[-1].id)
    assert history.session_page(status="COMPLETED")["total"] == 1
    assert history.session_page(start_at="2099-01-01")["total"] == 0
    for page, expected in ((0, 50), (1, 50), (2, 23)):
        result = history.result_page(sessions[0].id, page=page)
        assert len(result["items"]) == expected
        assert result["items"][0]["order"] == page * 50 + 1
    with pytest.raises(KeyError):
        history.result_page("missing")
    for invalid in (-1, True):
        with pytest.raises(ValueError):
            history.session_page(page=invalid)
    with pytest.raises(ValueError):
        history.result_page(sessions[0].id, page_size=1000)


def test_scheduled_filter_uses_stored_source_and_date_bounds_are_half_open(history):
    session = history.start_session(ScanType.FULL, "C:/scheduled", source=ScanSource.SCHEDULED)
    assert history.session_page(scan_type="scheduled")["items"][0]["session"].id == session.id
    assert history.session_page(scan_type="full")["total"] == 1
    bounds = date_bounds("Date", session.started_at.astimezone().date().isoformat())
    assert history.session_page(**bounds)["total"] == 1
    assert history.session_page(end_at=session.started_at.isoformat(timespec="microseconds"))["total"] == 0
    assert history.session_page(start_at=session.started_at.isoformat(timespec="microseconds"))["total"] == 1
    week = date_bounds("Week", "2026-10-22")
    start = datetime.fromisoformat(week["start_at"]).astimezone()
    end = datetime.fromisoformat(week["end_at"]).astimezone()
    assert start.weekday() == 0 and (end.date() - start.date()).days == 7
    assert date_bounds("All dates", "invalid") == {}
    with pytest.raises(ValueError):
        date_bounds("Date", "not-a-date")


def test_controller_reads_off_thread_and_coalesces_latest_navigation():
    entered, release = threading.Event(), threading.Event()
    calls, threads = [], []
    main_thread = threading.get_ident()
    def results(session_id, **kwargs):
        calls.append(session_id)
        threads.append(threading.get_ident())
        if session_id == "old":
            entered.set()
            assert release.wait(3)
        return {"selected": session_id}
    bus = UIMessageBus()
    history = SimpleNamespace(result_page=results)
    controller = AutoGuardUIController(SimpleNamespace(scanner=SimpleNamespace(history=history)), bus)
    try:
        controller.request_activity_view(1, session_id="old")
        assert entered.wait(2)
        controller.request_activity_view(2, session_id="discard")
        controller.request_activity_view(3, session_id="new")
        release.set()
        message = wait_message(bus, 3)
        assert message.payload["result"] == {"selected": "new"}
        assert calls == ["old", "new"]
        assert all(thread != main_thread for thread in threads)
    finally:
        release.set()
        controller.shutdown()


def test_controller_error_returns_token_and_reader_recovers(history):
    bus = UIMessageBus()
    controller = AutoGuardUIController(SimpleNamespace(scanner=SimpleNamespace(history=history)), bus)
    try:
        controller.request_activity_view(1, session_id="missing")
        assert wait_message(bus, 1).kind == "activity_view_error"
        controller.request_activity_view(2)
        assert wait_message(bus, 2).payload["result"]["total"] == 0
    finally:
        controller.shutdown()


def test_page_ignores_stale_responses_and_hidden_results():
    page = SimpleNamespace(_request_id=8, _visible=True, _loading=True)
    # Any attempt to update Tk on these rejected responses would raise because
    # the fake has no widgets or timers.
    for kind in ("activity_view_data", "activity_view_error"):
        ActivityPage.handle_message(page, UIMessage(kind, {"request_id": 7}))
    page._visible = False
    ActivityPage.handle_message(page, UIMessage("activity_view_data", {"request_id": 8}))
    assert page._loading


def test_idle_dashboard_does_not_queue_reads_and_live_requests_are_coalesced():
    refreshes = []
    page = SimpleNamespace(_automatic_signature=None, scan_data_changed=lambda: refreshes.append("live"),
                           refresh_from_state=lambda reason: refreshes.append("final"))
    for _ in range(10):
        ActivityPage.handle_message(page, UIMessage("dashboard_data", {"result": {"active_scan": None}}))
    assert refreshes == []
    progress = {"result": {"active_scan": {"processed": 4}}}
    ActivityPage.handle_message(page, UIMessage("dashboard_data", progress))
    ActivityPage.handle_message(page, UIMessage("dashboard_data", progress))
    assert refreshes == ["live"]
    ActivityPage.handle_message(page, UIMessage("dashboard_data", {"result": {"active_scan": None}}))
    assert refreshes == ["live", "final"]


def test_large_session_page_uses_index_and_only_materializes_50_results(history):
    session = history.start_session(ScanType.FULL, "C:/large")
    timestamp = session.started_at.isoformat(timespec="microseconds")
    with history.database.connection() as connection:
        connection.executemany(
            """INSERT INTO scan_results(session_id, path, result_category, entry_kind, reason, recorded_at, processing_order)
               VALUES (?, ?, 'SKIPPED_UNSUPPORTED', 'file', 'Skipped fixture', ?, ?)""",
            ((session.id, f"C:/file-{i}.bin", timestamp, i) for i in range(1, 20001)),
        )
        connection.execute("UPDATE scan_sessions SET discovered_files=20000, unsupported_files=20000 WHERE id=?", (session.id,))
        plan = connection.execute(
            "EXPLAIN QUERY PLAN SELECT * FROM scan_results WHERE session_id=? ORDER BY processing_order, id LIMIT 50 OFFSET 19950",
            (session.id,),
        ).fetchall()
        assert not any("TEMP B-TREE" in row["detail"] for row in plan)
        assert any("INDEX" in row["detail"] for row in plan)
    page = history.result_page(session.id, page=399)
    assert page["total"] == 20000
    assert len(page["items"]) == 50
    assert page["items"][0]["order"] == 19951 and page["items"][-1]["order"] == 20000
    assert history.latest_session_detection(session.id) is None


def page_double():
    calls, states = [], []
    page = SimpleNamespace(
        _request_id=1, _visible=True, _loading=True, _pending_final=False, _pending_live=False,
        _data={"items": [], "total": 0, "page": 0, "page_size": 50}, _watchdog_id="watchdog", _live_job=None,
        _page=0, _session_id=None, _filters={}, _last_live_read=time.monotonic(),
        _cancel_timer=lambda name: None, _update_pager=lambda: None,
        loading_label=SimpleNamespace(configure=lambda **kwargs: None),
        controller=SimpleNamespace(request_activity_view=lambda token, **kwargs: calls.append(token),
                                   cancel_activity_view=lambda: calls.append("cancel")),
        after=lambda delay, callback: "timer", _state=lambda *args, **kwargs: states.append(args),
    )
    page.refresh = lambda: ActivityPage.refresh(page)
    return page, calls, states


def test_final_event_during_read_is_not_lost():
    page, calls, _ = page_double()
    ActivityPage.refresh_from_state(page, "scan_completed")
    assert page._pending_final and not calls
    ActivityPage.handle_message(page, UIMessage("activity_view_data", {"request_id": 1, "result": page._data}))
    assert calls == [2]
    assert page._loading and not page._pending_final


def test_timeout_invalidates_late_response_and_can_retry():
    page, calls, states = page_double()
    ActivityPage._timeout(page, 1)
    assert not page._loading and page._data is None
    assert calls == ["cancel"] and states[0][0] == "Unable to load scan results"
    ActivityPage.handle_message(page, UIMessage("activity_view_data", {"request_id": 1, "result": {}}))
    assert page._data is None
    page.refresh()
    assert calls[-1] == 3 and page._loading


def test_high_frequency_results_schedule_one_read_without_polling():
    jobs = []
    page = SimpleNamespace(_visible=True, _session_id=None, _live_job=None, _loading=True,
                           _pending_live=False, _last_live_read=time.monotonic())
    page.after = lambda delay, callback: jobs.append((delay, callback)) or "timer"
    page._live_refresh = lambda: ActivityPage._live_refresh(page)
    for _ in range(500):
        ActivityPage.scan_data_changed(page)
    assert len(jobs) == 1 and jobs[0][0] > 3000
    jobs[0][1]()
    assert page._pending_live and len(jobs) == 1 and page._live_job is None


def test_unchanged_background_history_does_not_reload():
    changes = []
    page = SimpleNamespace(_automatic_signature=None, _history_revision=None,
                           scan_data_changed=lambda: changes.append("change"))
    revision = (("session-1", "COMPLETED", 4),)
    for _ in range(5):
        ActivityPage.handle_message(page, UIMessage("dashboard_data", {"result": {"scan_history_revision": revision}}))
    assert changes == ["change"]
