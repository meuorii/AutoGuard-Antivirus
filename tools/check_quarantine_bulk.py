"""Windows Phase 03 smoke check using disposable quarantine objects only.

Run from the repository root: python -m tools.check_quarantine_bulk
"""
import hashlib
from pathlib import Path
import tempfile
import time
import traceback
from types import SimpleNamespace

import customtkinter as ctk
from PIL import ImageGrab

from app.database import Database
from app.incidents import IncidentService
from app.models import ScanSource
from app.quarantine import QuarantineService
from app.ui import theme
from app.ui.controller import AutoGuardUIController
from app.ui.messages import UIMessageBus
from app.ui.quarantine_page import QuarantinePage
from app.ui.sidebar import Sidebar


def main():
    with tempfile.TemporaryDirectory(prefix="autoguard-bulk-") as temporary:
        database = Database(Path(temporary) / "history.db")
        database.initialize()
        incidents = IncidentService(database)
        quarantine = QuarantineService(database, Path(temporary) / "storage", incidents)
        saved = {}
        for number in range(120):
            path = Path(temporary) / f"file-{number:03d}.bin"
            data = f"ordinary quarantine fixture {number}".encode()
            path.write_bytes(data)
            digest = hashlib.sha256(data).hexdigest()
            incident = incidents.create_incident(digest, path, ScanSource.MANUAL, "Fixture")
            item = quarantine.quarantine_file(incident.id, path, digest, "UI fixture", ScanSource.MANUAL)
            saved[item.quarantine_id] = item

        root = ctk.CTk()
        root.geometry("1080x680+20+20")
        root.minsize(1080, 680)
        root.grid_columnconfigure(1, weight=1)
        root.grid_rowconfigure(0, weight=1)
        bus = UIMessageBus()
        services = SimpleNamespace(quarantine=quarantine, incidents=incidents,
                                   recovery=SimpleNamespace(list_attempts=lambda ref: []))
        controller = AutoGuardUIController(services, bus)
        reads, submissions = [], []
        actual_load, actual_delete = controller.load_quarantine, controller.delete_quarantine_many
        controller.load_quarantine = lambda: reads.append(True) or actual_load()
        controller.delete_quarantine_many = lambda refs: submissions.append(refs) or actual_delete(refs)
        sidebar = Sidebar(root, lambda key: None)
        sidebar.grid(row=0, column=0, sticky="nsw")
        sidebar.set_active("quarantine")
        page = QuarantinePage(root, controller)
        page.grid(row=0, column=1, sticky="nsew")
        failures, handles, selected, snapshots = [], [], [], []
        def on_error(*error):
            traceback.print_exception(*error)
            failures.append(error)
            root.quit()
        root.report_callback_exception = on_error

        def no_restore(widget):
            if isinstance(widget, ctk.CTkButton):
                assert "restore" not in widget.cget("text").lower()
            for child in widget.winfo_children():
                no_restore(child)

        def capture(name):
            root.update_idletasks()
            cache = Path(".pytest_cache")
            cache.mkdir(exist_ok=True)
            x, y = root.winfo_rootx(), root.winfo_rooty()
            ImageGrab.grab(bbox=(x, y, x + root.winfo_width(), y + root.winfo_height())).save(cache / name)

        def initial():
            assert len(page._list_data["items"]) == 120
            assert len(page._selection_widgets) == 50
            no_restore(page)
            first = next(iter(page._selection_widgets))
            page._selection_widgets[first][1].toggle()
            assert page._selected == {first}
            page._select_all()
            assert len(page._selected) == 120
            page._change_page(1)
            assert len(page._selected) == 120 and len(page._selection_widgets) == 50
            other = next(iter(page._selection_widgets))
            page._selection_widgets[other][1].toggle()
            assert len(page._selected) == 119
            page._filter_value.set("file-00")
            page._apply_filter()
            assert not page._selected and len(page._filtered_items()) == 10
            page._select_all()
            selected.extend(sorted(page._selected))
            page._delete_selected()

        def cancel():
            assert page._confirmation.winfo_exists()
            page._confirmation.cancel_button.invoke()
            assert not submissions and not page._batch_busy
            assert all(Path(saved[ref].stored_path).is_file() for ref in selected)
            snapshots.extend(page.body.winfo_children())
            page._delete_selected()

        def confirm_partial():
            # A real Windows read handle makes one selected object undeletable.
            handles.append(open(saved[selected[0]].stored_path, "rb"))
            Path(saved[selected[1]].original_path).write_bytes(b"unrelated replacement original")
            dialog = page._confirmation
            dialog.confirm_button.invoke()
            dialog.confirm()  # A repeated queued activation must be harmless.
            assert page._batch_busy and len(submissions) == 1
            assert page._delete_selected_button.cget("state") == "disabled"
            page._delete_selected()
            assert len(submissions) == 1

        def partial_done():
            assert len(page._batch_results) == 10
            assert sum(result["deleted"] for result in page._batch_results) == 9
            assert page._selected == {selected[0]}
            assert len(page._filtered_items()) == 1
            assert len(reads) == 2, reads  # initial read plus one final batch refresh
            assert Path(saved[selected[1]].original_path).read_bytes() == b"unrelated replacement original"
            assert Path(saved[selected[0]].stored_path).is_file()
            assert all(widget not in page.body.winfo_children() for widget in snapshots)
            handles.pop().close()
            capture("quarantine-bulk-results.png")
            page._delete_selected()

        def confirm_retry():
            page._confirmation.confirm_button.invoke()

        def retry_done():
            assert len(page._batch_results) == 1 and page._batch_results[0]["deleted"]
            assert not page._selected
            assert page._delete_selected_button.cget("state") == "disabled"
            assert len(reads) == 3
            page._filter_value.set("")
            page._apply_filter()
            assert len(page._filtered_items()) == 110
            for setting in theme.TEXT_SCALES:
                theme.set_text_size(setting)
                root.update_idletasks()
            page._deselect_all()
            assert page._pager_buttons[0].cget("state") == "disabled"
            ref = page._filtered_items()[0]["item_ref"]
            controller.open_quarantine_details(ref)

        def details():
            assert page._detail_data is not None
            no_restore(page)
            assert "can_restore" not in page._detail_data
            with database.connection() as connection:
                assert connection.execute("SELECT COUNT(*) FROM quarantine_items").fetchone()[0] == 120
                assert connection.execute("SELECT COUNT(*) FROM quarantine_deletion_attempts").fetchone()[0] == 11
                assert not connection.execute("PRAGMA foreign_key_check").fetchall()
            print("PASS individual selection, all filtered pages, filter clearing, Cancel, confirmed partial deletion, locked-file retry, single batch refresh, unchanged originals, and no Restore actions", flush=True)

        steps = iter((initial, cancel, confirm_partial, partial_done, confirm_retry, retry_done, details))
        deadline = time.monotonic() + 60
        def pump():
            if time.monotonic() > deadline:
                raise AssertionError("Quarantine UI smoke check timed out")
            answered = False
            for message in bus.drain():
                page.handle_message(message)
                answered |= message.kind.endswith("_data") or message.kind == "quarantine_batch_deleted"
            if answered:
                root.after(300, pump)
                return
            if not page._loading and not page._batch_busy:
                step = next(steps, None)
                if step is None:
                    root.quit()
                    return
                step()
                print("PASS " + step.__name__, flush=True)
            root.after(350, pump)
        try:
            root.attributes("-topmost", True)
            page.on_show()
            root.after(500, pump)
            root.mainloop()
            assert not failures, failures
        finally:
            for handle in handles:
                handle.close()
            root.destroy()
            controller.shutdown()


if __name__ == "__main__":
    main()
