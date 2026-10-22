from __future__ import annotations

from datetime import date, datetime, time, timedelta, timezone
import time as clock

import pytest

from app.database import Database
from app.models import DetectionResult, DetectionStatus, ScanResult, ScanSource, ScanStatus, ScanType
from app.scan_history import ScanHistory
from app.ui.activity_page import ActivityPage, FILE_TABLE_COLUMNS, scroll_activity_rows, truncate_filename
from app.ui.controller import AutoGuardUIController
from app.ui.messages import UIMessageBus


@pytest.fixture
def history(tmp_path):
    database = Database(tmp_path / "activity.db")
    database.initialize()
    return ScanHistory(database)


def local_stamp(day: date, clock: time) -> str:
    local = datetime.combine(day, clock).astimezone()
    return local.astimezone(timezone.utc).isoformat(timespec="microseconds")


def insert_result(connection, session_id, index, recorded_at, *, status="SCANNED", detection="NO_DETECTION"):
    if status == "SCANNED":
        digest = f"{index % 16**64:064x}"
        signature = ("Fixture", "autoguard_test") if detection == "HIGH_CONFIDENCE" else (None, None)
        connection.execute(
            """INSERT INTO scan_results
               (session_id,path,sha256,result_category,entry_kind,detection_status,detection_confidence,
                rule_name,reason,detection_reason,matched_signature_name,matched_signature_kind,recorded_at)
               VALUES (?, ?, ?, 'SCANNED', 'file', ?, 0.5, 'fixture', 'fixture', 'fixture', ?, ?, ?)""",
            (session_id, f"C:/files/file-{index:05}.dat", digest, detection, *signature, recorded_at),
        )
    else:
        connection.execute(
            """INSERT INTO scan_results
               (session_id,path,result_category,entry_kind,reason,recorded_at)
               VALUES (?, ?, ?, 'file', 'fixture', ?)""",
            (session_id, f"C:/files/file-{index:05}.dat", status, recorded_at),
        )


def insert_session(connection, session_id, scan_type, source="manual"):
    now = datetime.now(timezone.utc).isoformat(timespec="microseconds")
    connection.execute(
        """INSERT INTO scan_sessions(id,scan_type,source_path,source,started_at,result_order_version)
           VALUES (?, ?, 'C:/fixture', ?, ?, 1)""",
        (session_id, scan_type, source, now),
    )


def test_date_page_groups_many_realtime_sessions_into_one_local_date(history):
    today = date.today()
    start = local_stamp(today, time(9, 0))
    with history.database.connection() as connection:
        for index in range(500):
            session_id = f"realtime-{index:04}"
            insert_session(connection, session_id, "real_time", "file_monitor")
            insert_result(connection, session_id, index, start)

    page = history.scan_date_page()
    assert page["total"] == 1
    assert len(page["items"]) == 1
    assert page["items"][0]["local_date"] == today.isoformat()
    assert page["items"][0]["total"] == 500
    assert page["items"][0]["safe"] == 500


def test_daily_file_pages_include_all_outcomes_and_keep_daily_order_continuous(history):
    today = date.today()
    stamp = local_stamp(today, time(10, 0))
    with history.database.connection() as connection:
        insert_session(connection, "mixed-1", "quick", "scheduled")
        insert_session(connection, "mixed-2", "real_time", "file_monitor")
        insert_result(connection, "mixed-1", 1, stamp)
        insert_result(connection, "mixed-1", 2, stamp, detection="LOW_CONFIDENCE")
        insert_result(connection, "mixed-2", 3, stamp, detection="HIGH_CONFIDENCE")
        insert_result(connection, "mixed-2", 4, stamp, status="SKIPPED_LOCKED")
        insert_result(connection, "mixed-2", 5, stamp, status="ERROR")
        for index in range(6, 1006):
            insert_result(connection, "mixed-2", index, stamp)

    first = history.daily_results_page(today.isoformat(), page=0)
    second = history.daily_results_page(today.isoformat(), page=1)
    assert first["summary"] == {
        "total": 1005, "safe": 1001, "suspicious": 1,
        "dangerous": 1, "skipped": 1, "errors": 1,
    }
    assert [item["order"] for item in first["items"]] == list(range(1, 51))
    assert [item["order"] for item in second["items"]] == list(range(51, 101))
    assert first["items"][0]["result"].id < first["items"][1]["result"].id
    assert first["items"][0]["scan_type"] is ScanType.QUICK
    assert first["items"][0]["source"] is ScanSource.SCHEDULED
    assert history.daily_results_page(today.isoformat(), status="dangerous")["items"][0]["order"] == 3
    assert history.daily_results_page(today.isoformat(), scan_type="real_time")["total"] == 1003
    assert history.daily_results_page(today.isoformat(), search="file-00002")["items"][0]["order"] == 2


def test_local_midnight_boundary_and_date_pagination(history):
    today = date.today()
    yesterday = today - timedelta(days=1)
    before_midnight = local_stamp(yesterday, time(23, 59, 59))
    after_midnight = local_stamp(today, time(0, 0, 1))
    with history.database.connection() as connection:
        insert_session(connection, "boundary", "full")
        insert_result(connection, "boundary", 1, before_midnight)
        insert_result(connection, "boundary", 2, after_midnight)
        for offset in range(1, 35):
            day = today - timedelta(days=offset + 1)
            session_id = f"day-{offset}"
            insert_session(connection, session_id, "quick")
            insert_result(connection, session_id, offset + 2, local_stamp(day, time(12, 0)))

    newest = history.scan_date_page(page_size=10)
    older = history.scan_date_page(page=1, page_size=10)
    days = [item["local_date"] for item in newest["items"] + older["items"]]
    assert days[0] == today.isoformat()
    assert days[1] == yesterday.isoformat()
    assert len(days) == len(set(days)) == 20
    assert newest["total"] == 36
    assert history.daily_results_page(yesterday.isoformat())["total"] == 1
    assert history.daily_results_page(today.isoformat())["total"] == 1


def test_daily_page_unifies_all_scan_types_for_the_same_date(history):
    today = date.today()
    stamp = local_stamp(today, time(14, 0))
    variants = (
        ("real_time", "file_monitor"), ("quick", "manual"), ("full", "manual"),
        ("manual", "manual"), ("startup", "startup"),
        ("scheduled", "scheduled"), ("usb", "usb"),
    )
    with history.database.connection() as connection:
        for index, (kind, source) in enumerate(variants):
            session_id = f"kind-{kind}"
            insert_session(connection, session_id, kind, source)
            insert_result(connection, session_id, index, stamp)
    page = history.daily_results_page(today.isoformat())
    assert page["total"] == len(variants)
    assert {item["scan_type"].value for item in page["items"]} == {kind for kind, _ in variants}
    assert [item["order"] for item in page["items"]] == list(range(1, len(variants) + 1))


def test_empty_activity_and_indexed_date_scan(history):
    assert history.scan_date_page()["items"] == []
    today = date.today().isoformat()
    page = history.daily_results_page(today)
    assert page["total"] == 0 and page["items"] == []
    with history.database.connection() as connection:
        plan = connection.execute(
            "EXPLAIN QUERY PLAN SELECT * FROM scan_results WHERE entry_kind='file' AND recorded_at >= ? AND recorded_at < ? ORDER BY recorded_at,id LIMIT 50",
            ("2026-01-01T00:00:00+00:00", "2026-01-02T00:00:00+00:00"),
        ).fetchall()
        assert any("idx_scan_results_kind_recorded_id" in row["detail"] for row in plan)


def test_activity_pages_ten_thousand_results_without_materializing_history(history):
    today = date.today()
    stamp = local_stamp(today, time(12, 0))
    with history.database.connection() as connection:
        insert_session(connection, "large-activity", "real_time", "file_monitor")
        connection.executemany(
            """INSERT INTO scan_results
               (session_id,path,sha256,result_category,entry_kind,detection_status,detection_confidence,
                rule_name,reason,detection_reason,recorded_at)
               VALUES ('large-activity', 'C:/files/repeated.txt', ?, 'SCANNED', 'file',
                       'NO_DETECTION', 0.0, 'fixture', 'safe', 'fixture', ?)""",
            ((f"{index:064x}", stamp) for index in range(10_000)),
        )
    page = history.daily_results_page(today.isoformat(), page=199)
    assert page["total"] == 10_000
    assert len(page["items"]) == 50
    assert [item["order"] for item in page["items"]] == list(range(9951, 10_001))


def test_history_change_notifications_are_only_published_while_activity_is_visible(history):
    session = history.start_session(ScanType.REAL_TIME, "C:/monitored", ScanSource.FILE_MONITOR)
    bus = UIMessageBus()
    controller = AutoGuardUIController(type("Services", (), {
        "scanner": type("Scanner", (), {"history": history})()
    })(), bus)
    path = "C:/monitored/file.txt"
    detection = DetectionResult(DetectionStatus.NO_DETECTION, 0.0, "Safe fixture", "fixture", "a" * 64, path)
    try:
        controller.set_activity_view_active(True)
        history.record_result(session.id, ScanResult(
            path, ScanStatus.SCANNED, "Processed", detection=detection, sha256="a" * 64
        ))
        messages = bus.drain()
        changed = next(message for message in messages if message.kind == "scan_history_changed")
        assert changed.payload["session_id"] == session.id
        assert changed.payload["local_date"] == date.today().isoformat()

        controller.set_activity_view_active(False)
        history.record_result(session.id, ScanResult(
            path, ScanStatus.SCANNED, "Processed", detection=detection, sha256="a" * 64
        ))
        assert not any(message.kind == "scan_history_changed" for message in bus.drain())
    finally:
        controller.shutdown()


def test_activity_controller_routes_requests_to_date_and_daily_page(history):
    today = date.today()
    stamp = local_stamp(today, time(12, 0))
    with history.database.connection() as connection:
        insert_session(connection, "request-session", "quick")
        insert_result(connection, "request-session", 1, stamp)
    bus = UIMessageBus()
    controller = AutoGuardUIController(type("Services", (), {
        "scanner": type("Scanner", (), {"history": history})()
    })(), bus)
    try:
        controller.set_activity_view_active(True)
        controller.request_activity_view(1)
        date_message = None
        for _ in range(200):
            date_message = next((message for message in bus.drain()
                                 if message.kind == "activity_view_data" and message.payload.get("request_id") == 1), None)
            if date_message: break
            clock.sleep(0.005)
        assert date_message is not None and date_message.payload["result"]["items"][0]["local_date"] == today.isoformat()

        controller.request_activity_view(2, local_date=today.isoformat(), page=0)
        daily_message = None
        for _ in range(200):
            daily_message = next((message for message in bus.drain()
                                  if message.kind == "activity_view_data" and message.payload.get("request_id") == 2), None)
            if daily_message: break
            clock.sleep(0.005)
        assert daily_message is not None
        assert daily_message.payload["result"]["items"][0]["order"] == 1
    finally:
        controller.shutdown()


def test_activity_can_patch_daily_summary_without_rebuilding_unchanged_rows():
    filters = {"status": "all", "scan_type": None, "search": ""}
    old = {"local_date": "2026-10-23", "items": [
        {"result": type("Result", (), {"id": 11})(), "order": 1},
    ]}
    current = {"local_date": "2026-10-23", "items": [
        {"result": type("Result", (), {"id": 11})(), "order": 1},
    ]}
    page = type("Page", (), {
        "_selected_date": "2026-10-23", "_page": 0, "_filters": filters,
        "_render_key": ("2026-10-23", 0, tuple(sorted(filters.items()))),
    })()
    assert ActivityPage._can_patch_daily_page(page, old, current)
    current["items"].append({"result": type("Result", (), {"id": 12})(), "order": 2})
    assert not ActivityPage._can_patch_daily_page(page, old, current)


def test_activity_filename_truncation_is_pixel_bounded_and_unicode_safe():
    measure = lambda value: len(value) * 10
    assert truncate_filename("document.pdf", 200, measure) == "document.pdf"
    truncated = truncate_filename("가나다라마바사-日本語資料.txt", 100, measure)
    assert truncated.endswith("…") and measure(truncated) <= 100
    assert truncate_filename("非常に長いファイル名.txt", 5, measure) == "…"


def test_activity_table_defines_aligned_columns_and_requested_proportions():
    assert [column[1] for column in FILE_TABLE_COLUMNS] == [
        "#", "Filename", "Scan Type", "Detection Result", "Time Scanned", "Details"
    ]
    assert sum(column[2] for column in FILE_TABLE_COLUMNS) == pytest.approx(1.0)
    assert dict((column[0], column[2]) for column in FILE_TABLE_COLUMNS)["filename"] == 0.38


def test_filename_truncation_preserves_hangul_and_japanese_codepoints():
    filename = "".join(map(chr, (0xAC00, 0xB098, 0xB2E4, 0x65E5, 0x672C, 0x8A9E))) + ".txt"
    measure = lambda value: len(value) * 12
    value = truncate_filename(filename, 72, measure)
    assert value.endswith(chr(0x2026))
    assert value.startswith("".join(map(chr, (0xAC00, 0xB098, 0xB2E4))))
    assert measure(value) <= 72


@pytest.mark.parametrize(
    ("event", "platform", "expected"),
    [
        (type("Wheel", (), {"delta": 120, "num": None})(), "win32", -1),
        (type("Wheel", (), {"delta": -240, "num": None})(), "win32", 2),
        (type("Wheel", (), {"delta": 0, "num": 4})(), "linux", -1),
        (type("Wheel", (), {"delta": 0, "num": 5})(), "linux", 1),
    ],
)
def test_activity_table_wheel_scroll_is_consumed_by_inner_table(event, platform, expected):
    class Table:
        def __init__(self):
            self.calls = []

        def yview_scroll(self, amount, units):
            self.calls.append((amount, units))

    table = Table()
    assert scroll_activity_rows(table, event, platform=platform) == "break"
    assert table.calls == [(expected, "units")]


def test_activity_table_wheel_bindings_are_local_to_table_widgets():
    import inspect

    source = inspect.getsource(ActivityPage._render_files)
    assert 'widget.bind("<MouseWheel>"' in source
    assert 'widget.bind("<Button-4>"' in source
    assert 'widget.bind("<Button-5>"' in source
    assert "bind_all" not in source
