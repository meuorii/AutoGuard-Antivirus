"""Windows Phase 02 smoke test with temporary evidence; no protection services.

Run from the project root: python -m tools.check_activity_sessions
"""
from pathlib import Path
import tempfile
import time
import traceback
from types import SimpleNamespace

import customtkinter as ctk
from PIL import ImageGrab

from app.database import Database
from app.models import DetectionResult, DetectionStatus, ScanResult, ScanStatus, ScanType
from app.scan_history import ScanHistory
from app.ui import theme
from app.ui.activity_page import ActivityPage
from app.ui.controller import AutoGuardUIController
from app.ui.messages import UIMessage, UIMessageBus
from app.ui.sidebar import Sidebar


def main():
    with tempfile.TemporaryDirectory(prefix="autoguard-activity-") as temporary:
        database = Database(Path(temporary) / "history.db")
        database.initialize()
        history = ScanHistory(database)
        full = history.start_session(ScanType.FULL, "C:/Example")
        for number in range(123):
            path = "C:/Example/" + "long-folder-name/" * 4 + f"safe-file-{number + 1}.txt"
            detection = DetectionResult(DetectionStatus.NO_DETECTION, 0.0, "No threat detected", "fixture", "a" * 64, path)
            history.record_result(full.id, ScanResult(path, ScanStatus.SCANNED, "Successfully scanned", detection=detection, sha256="a" * 64))
        history.finish_session(full.id)
        legacy = history.start_session(ScanType.QUICK, "C:/Legacy")
        history.record_result(legacy.id, ScanResult("C:/Legacy/skipped.bin", ScanStatus.SKIPPED_SIZE, "File exceeds the configured size limit"))
        history.finish_session(legacy.id)
        with database.connection() as connection:
            connection.execute("UPDATE scan_sessions SET result_order_version=0 WHERE id=?", (legacy.id,))
            connection.execute("UPDATE scan_results SET processing_order=NULL WHERE session_id=?", (legacy.id,))
        running = history.start_session(ScanType.USB, "E:/Example")

        root = ctk.CTk()
        root.geometry("1080x680+20+20")
        root.minsize(1080, 680)
        root.grid_columnconfigure(1, weight=1)
        root.grid_rowconfigure(0, weight=1)
        bus = UIMessageBus()
        controller = AutoGuardUIController(SimpleNamespace(scanner=SimpleNamespace(history=history)), bus)
        sidebar = Sidebar(root, lambda key: None)
        sidebar.grid(row=0, column=0, sticky="nsw")
        sidebar.set_active("activity")
        page = ActivityPage(root, controller)
        page.grid(row=0, column=1, sticky="nsew")
        failures = []
        def on_error(*error):
            traceback.print_exception(*error)
            failures.append(error)
            root.quit()
        root.report_callback_exception = on_error
        references = []
        live_references = []

        def screenshot(name):
            root.update_idletasks()
            if page._detail_widgets:
                for label in (page._detail_widgets["stats"], page._detail_widgets["note"]):
                    assert label.winfo_height() >= label._label.winfo_reqheight(), (label.winfo_geometry(), label._label.winfo_reqheight(), label.cget("text"))
            directory = Path(".pytest_cache")
            directory.mkdir(exist_ok=True)
            x, y = root.winfo_rootx(), root.winfo_rooty()
            ImageGrab.grab(bbox=(x, y, x + root.winfo_width(), y + root.winfo_height())).save(directory / name)

        def session_list():
            assert page._data["total"] == 3
            assert len(page._data["items"]) == 3
            for setting in theme.TEXT_SCALES:
                theme.set_text_size(setting)
                root.update_idletasks()
            root.after(300, lambda: (screenshot("activity-sessions.png"), page.open_session(full.id)))

        def first_files():
            assert len(page._data["items"]) == 50
            assert [item["order"] for item in page._data["items"]] == list(range(1, 51))
            assert len(page.content.winfo_children()) == 52  # header, 50 cards, bottom pager
            references.extend(page.content.winfo_children())
            root.after(300, lambda: (screenshot("activity-session-files.png"), page.refresh()))

        def unchanged_files():
            assert tuple(references) == tuple(page.content.winfo_children()), "Unchanged data recreated file rows"
            page.change_page(1)

        def second_files():
            assert page._data["items"][0]["order"] == 51
            page.change_page(1)

        def last_files():
            assert len(page._data["items"]) == 23
            assert page._data["items"][-1]["order"] == 123
            page.back_to_sessions()

        def choose_legacy():
            assert page._page == 0
            page.open_session(legacy.id)

        def legacy_files():
            assert not page._data["guaranteed_order"]
            assert page._data["items"][0]["order"] == 1
            page.back_to_sessions()

        def filter_scans():
            page._toggle_filters()
            page.type_value.set("Quick")
            page.apply_filters()

        def filtered():
            assert page._data["total"] == 1
            assert page._data["items"][0]["session"].id == legacy.id
            page.status_value.set("Completed")
            page.apply_filters()

        def no_matches():
            assert page._data["total"] == 0
            page.type_value.set("All scan types")
            page.status_value.set("All statuses")
            page.apply_filters()

        def choose_running():
            page.open_session(running.id)

        def stop_scan():
            assert page._data["total"] == 0 and page._data["session"].status.value == "RUNNING"
            history.record_result(running.id, ScanResult("E:/Example/unreadable.bin", ScanStatus.ERROR, "File could not be read"))
            page.refresh()

        def live_one():
            assert page._data["total"] == 1
            live_references.extend(page.content.winfo_children())
            history.record_result(running.id, ScanResult("E:/Example/large.bin", ScanStatus.SKIPPED_SIZE, "File exceeds size limit"))
            page.refresh()

        def live_two():
            assert page._data["total"] == 2
            assert all(widget in page.content.winfo_children() for widget in live_references), "Appending a live result rebuilt existing rows"
            history.finish_session(running.id, interrupted=True)
            page.refresh_from_state("scan_stopped")

        def stopped():
            assert page._data["session"].status.value == "INCOMPLETE"
            assert page._data["total"] == 2 and page._data["items"][0]["order"] == 1
            assert all(widget in page.content.winfo_children() for widget in live_references), "Final status rebuilt unchanged rows"
            assert page._live_job is None and page._watchdog_id is None
            for _ in range(10):
                page.handle_message(UIMessage("dashboard_data", {"result": {"active_scan": None}}))
            assert not page._loading
            page.on_hide()
            print("PASS session list, all text sizes, 50-row pagination, unchanged-widget reuse, legacy labels, filters, empty state, stopped scan, and idle behavior", flush=True)

        steps = iter((session_list, first_files, unchanged_files, second_files, last_files,
                      choose_legacy, legacy_files, filter_scans, filtered, no_matches,
                      choose_running, stop_scan, live_one, live_two, stopped))
        deadline = time.monotonic() + 45
        def pump():
            if time.monotonic() > deadline:
                raise AssertionError("Activity smoke check timed out")
            answered = False
            for message in bus.drain():
                page.handle_message(message)
                answered |= message.kind in {"activity_view_data", "activity_view_error"}
            if answered:
                root.after(120, pump)
                return
            if not page._loading and page._data is not None:
                step = next(steps, None)
                if step is None:
                    root.quit()
                    return
                step()
                print("PASS " + step.__name__, flush=True)
            root.after(400, pump)
        try:
            root.attributes("-topmost", True)
            page.on_show()
            root.after(500, pump)
            root.mainloop()
            assert not failures, failures
        finally:
            root.destroy()
            controller.shutdown()


if __name__ == "__main__":
    main()
