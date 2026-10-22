"""Phase 03: guarded disposal, audit preservation and UI selection contracts."""
import hashlib
from contextlib import contextmanager
import os
from pathlib import Path
import threading
import sqlite3
import time
from types import SimpleNamespace
from uuid import uuid4

import pytest

from app.database import Database
from app.incidents import IncidentService
from app.models import ScanSource
from app.quarantine import QuarantineService, QuarantineState, QuarantineIntegrityStatus
from app.ui.components.dialogs import ConfirmDialog
from app.ui.controller import AutoGuardUIController
from app.ui.messages import UIMessage, UIMessageBus
from app.ui.quarantine_page import QuarantinePage


@pytest.fixture
def storage(tmp_path):
    database = Database(tmp_path / "history.db")
    database.initialize()
    incidents = IncidentService(database)
    quarantine = QuarantineService(database, tmp_path / "isolated", incidents)
    sequence = 0
    def make():
        nonlocal sequence
        sequence += 1
        source = tmp_path / f"original-{sequence}.bin"
        data = f"ordinary fixture {sequence}".encode()
        source.write_bytes(data)
        digest = hashlib.sha256(data).hexdigest()
        incident = incidents.create_incident(digest, source, ScanSource.MANUAL, "Quarantine fixture")
        item = quarantine.quarantine_file(incident.id, source, digest, "Selected fixture", ScanSource.MANUAL)
        assert item.state is QuarantineState.QUARANTINED
        return item
    return quarantine, database, incidents, make


def attempts(database):
    with database.connection() as connection:
        return [dict(row) for row in connection.execute("SELECT * FROM quarantine_deletion_attempts ORDER BY rowid")]


def test_delete_selected_only_preserves_originals_evidence_and_foreign_keys(storage):
    service, database, incidents, make = storage
    first, second, untouched = make(), make(), make()
    Path(first.original_path).write_bytes(b"new unrelated original content")
    original_evidence = incidents.get_incident(first.incident_id)
    # Keep an existing recovery FK to demonstrate that disposal never deletes
    # metadata required by historical reporting.
    now = first.created_at.isoformat()
    with database.connection() as connection:
        connection.execute("""INSERT INTO quarantine_recovery_attempts
            (id, quarantine_id, incident_id, attempted_at, finished_at, requested_path, status, error)
            VALUES (?, ?, ?, ?, ?, ?, 'FAILED', 'Historical fixture')""",
            (str(uuid4()), first.quarantine_id, first.incident_id, now, now, first.original_path))
    outcomes = service.delete_quarantine_objects((first.quarantine_id, second.quarantine_id))
    assert all(item["deleted"] and item["status"] == "DELETED" for item in outcomes), outcomes
    assert not Path(first.stored_path).exists() and not Path(second.stored_path).exists()
    assert Path(untouched.stored_path).is_file()
    assert Path(first.original_path).read_bytes() == b"new unrelated original content"
    saved = service.get_item(first.quarantine_id)
    assert saved.state is QuarantineState.FAILED and saved.deleted_at is not None
    assert saved.sha256 == first.sha256 and saved.verified_sha256 == first.verified_sha256
    assert saved.integrity_status is QuarantineIntegrityStatus.VERIFIED
    assert incidents.get_incident(first.incident_id) == original_evidence
    assert [row["status"] for row in attempts(database)] == ["DELETED", "DELETED"]
    with database.connection() as connection:
        assert connection.execute("SELECT COUNT(*) FROM quarantine_items").fetchone()[0] == 3
        assert connection.execute("SELECT COUNT(*) FROM quarantine_recovery_attempts").fetchone()[0] == 1
        assert connection.execute("PRAGMA foreign_key_check").fetchall() == []


def test_partial_failure_does_not_mark_failed_unlink_deleted(storage, monkeypatch):
    service, database, _, make = storage
    first, locked = make(), make()
    from app import quarantine as module
    real_unlink = module._unlink_quarantine_object
    def unlink(target):
        if str(target) == locked.stored_path:
            raise PermissionError("Fixture: object is locked")
        real_unlink(target)
    monkeypatch.setattr(module, "_unlink_quarantine_object", unlink)
    result = service.delete_quarantine_objects((first.quarantine_id, locked.quarantine_id))
    assert [item["deleted"] for item in result] == [True, False]
    assert "locked" in result[1]["message"]
    assert Path(locked.stored_path).exists()
    assert service.get_item(locked.quarantine_id).state is QuarantineState.QUARANTINED
    assert service.get_item(locked.quarantine_id).deleted_at is None
    assert [row["status"] for row in attempts(database)] == ["DELETED", "FAILED"]


@pytest.mark.skipif(os.name != "nt", reason="Windows sharing semantics")
def test_real_windows_locked_object_returns_failure(storage):
    service, database, _, make = storage
    item = make()
    with open(item.stored_path, "rb"):
        result = service.delete_quarantine_objects((item.quarantine_id,))[0]
        assert not result["deleted"], result
    assert Path(item.stored_path).exists()
    assert service.get_item(item.quarantine_id).state is QuarantineState.QUARANTINED
    assert attempts(database)[0]["status"] == "FAILED"
    assert service.delete_quarantine_objects((item.quarantine_id,))[0]["deleted"]


def test_missing_invalid_unknown_and_unfinished_items_are_audited(storage):
    service, database, _, make = storage
    missing, pending = make(), make()
    Path(missing.stored_path).unlink()
    with database.connection() as connection:
        connection.execute("UPDATE quarantine_items SET state='PENDING' WHERE quarantine_id=?", (pending.quarantine_id,))
    outcomes = service.delete_quarantine_objects((missing.quarantine_id, pending.quarantine_id, "../../unrelated", str(uuid4())))
    assert [item["status"] for item in outcomes] == ["MISSING", "REJECTED", "REJECTED", "REJECTED"]
    assert not any(item["deleted"] for item in outcomes)
    assert Path(pending.stored_path).exists()
    assert service.get_item(pending.quarantine_id).state is QuarantineState.PENDING
    assert service.get_item(missing.quarantine_id).deleted_at is None
    assert len(attempts(database)) == 4


def test_tampered_stored_path_cannot_delete_original_or_unrelated_file(storage, tmp_path):
    service, database, _, make = storage
    item = make()
    outside = tmp_path / "unrelated.bin"
    outside.write_bytes(b"must remain")
    with database.connection() as connection:
        connection.execute("UPDATE quarantine_items SET stored_path=? WHERE quarantine_id=?", (str(outside), item.quarantine_id))
    result = service.delete_quarantine_objects((item.quarantine_id,))[0]
    assert not result["deleted"] and result["status"] == "REJECTED"
    assert outside.read_bytes() == b"must remain"
    assert Path(item.stored_path).is_file()
    assert service.get_item(item.quarantine_id).deleted_at is None


def test_directory_at_object_path_is_not_deleted(storage):
    service, _, _, make = storage
    item = make()
    target = Path(item.stored_path)
    target.unlink()
    target.mkdir()
    child = target / "unrelated.txt"
    child.write_text("keep", encoding="utf-8")
    result = service.delete_quarantine_objects((item.quarantine_id,))[0]
    assert result["status"] == "REJECTED" and not result["deleted"]
    assert child.read_text() == "keep"


def test_repeated_request_and_duplicate_ids_do_not_delete_again(storage):
    service, database, _, make = storage
    item = make()
    first = service.delete_quarantine_objects((item.quarantine_id, item.quarantine_id))
    assert len(first) == 1 and first[0]["deleted"]
    # A later unrelated file at the old storage name must not be deleted again.
    Path(item.stored_path).write_bytes(b"unrelated replacement")
    repeated = service.delete_quarantine_objects((item.quarantine_id,))[0]
    assert not repeated["deleted"] and repeated["status"] == "ALREADY_DELETED"
    assert Path(item.stored_path).read_bytes() == b"unrelated replacement"
    assert [row["status"] for row in attempts(database)] == ["DELETED", "ALREADY_DELETED"]


def test_existing_inflight_claim_refuses_duplicate_request(storage):
    service, database, _, make = storage
    item = make()
    with database.connection() as connection:
        connection.execute("""INSERT INTO quarantine_deletion_attempts
            (id, batch_id, requested_id, quarantine_id, incident_id, attempted_at, status, message)
            VALUES (?, ?, ?, ?, ?, ?, 'RUNNING', 'Existing claim')""",
            (str(uuid4()), str(uuid4()), item.quarantine_id, item.quarantine_id, item.incident_id, item.created_at.isoformat()))
    result = service.delete_quarantine_objects((item.quarantine_id,))[0]
    assert result["status"] == "REJECTED" and not result["deleted"]
    assert Path(item.stored_path).is_file()


def test_controller_batches_on_worker_and_rejects_overlapping_submissions():
    entered, release = threading.Event(), threading.Event()
    threads = []
    def delete(ids):
        threads.append(threading.get_ident())
        entered.set()
        assert release.wait(3)
        return [{"item_ref": ids[0], "deleted": True, "message": "Deleted"},
                {"item_ref": ids[1], "deleted": False, "message": "Locked"}]
    bus = UIMessageBus()
    controller = AutoGuardUIController(SimpleNamespace(quarantine=SimpleNamespace(delete_quarantine_objects=delete)), bus)
    try:
        assert controller.delete_quarantine_many(("one", "two"))
        assert entered.wait(2)
        assert not controller.delete_quarantine_many(("two",))
        release.set()
        until = time.monotonic() + 3
        result = None
        messages = []
        while time.monotonic() < until and result is None:
            for message in bus.drain():
                messages.append(message.kind)
                if message.kind == "quarantine_batch_deleted":
                    result = message.payload["result"]
            time.sleep(0.005)
        assert result["deleted_count"] == 1 and result["failed_count"] == 1
        assert threads == [threads[0]] and threads[0] != threading.get_ident()
        assert messages.count("quarantine_batch_deleted") == 1
        assert "quarantine_deleted" not in messages
    finally:
        release.set()
        controller.shutdown()


def test_selection_scope_survives_pages_and_clears_when_filter_applied():
    updates = []
    items = [{"item_ref": str(i), "name": f"file-{i}", "original_location": "C:/test"} for i in range(120)]
    page = SimpleNamespace(_batch_busy=False, _selected=set(), _list_data={"items": items}, _filter_text="", _page=0)
    page._filtered_items = lambda: QuarantinePage._filtered_items(page)
    page._update_selection = lambda: updates.append(len(page._selected))
    QuarantinePage._select_all(page)
    assert len(page._selected) == 120
    page._page = 1
    QuarantinePage._toggle_item(page, "3")
    assert len(page._selected) == 119 and "3" not in page._selected
    page._filter_value = SimpleNamespace(get=lambda: "file-11")
    page._render_list = lambda data: None
    QuarantinePage._apply_filter(page)
    assert page._selected == set() and page._page == 0
    QuarantinePage._select_all(page)
    assert page._selected == {"11", *(str(i) for i in range(110, 120))}
    QuarantinePage._deselect_all(page)
    assert not page._selected


def test_confirmation_cancel_does_not_submit_and_snapshot_is_immutable(monkeypatch):
    from app.ui import quarantine_page as module
    dialogs = []
    def dialog(*args, **kwargs):
        dialogs.append(kwargs)
        return SimpleNamespace(winfo_exists=lambda: False)
    monkeypatch.setattr(module, "ConfirmDialog", dialog)
    submissions = []
    page = SimpleNamespace(_batch_busy=False, _confirmation=None, _start_delete=lambda refs: submissions.append(refs))
    refs = ["one", "two"]
    QuarantinePage._confirm_delete(page, refs)
    assert not submissions
    # Cancel is simply closing the modal; the only deletion entry is on_confirm.
    refs.append("three")
    dialogs[0]["on_confirm"]()
    assert submissions == [("one", "two")]
    assert dialogs[0]["danger"] and dialogs[0]["confirm_text"] == "Delete Permanently"


def test_restore_is_absent_from_visible_actions_but_backend_remains():
    root = Path(__file__).resolve().parents[1]
    for path in ("app/ui/quarantine_page.py", "app/ui/quarantine_details_page.py", "app/ui/components/dialogs.py"):
        source = (root / path).read_text(encoding="utf-8")
        assert 'text="Restore"' not in source and "on_restore" not in source and "RestoreDialog" not in source
    assert not hasattr(AutoGuardUIController, "restore_quarantine")
    from app.recovery import RecoveryService
    assert callable(RecoveryService.restore)


def test_loading_navigation_renders_cached_data_but_idle_reload_reuses_widgets():
    rendered = []
    data = {"items": [], "isolated_count": 0}
    page = SimpleNamespace(_detail_ref=None, _loading=True, _batch_busy=False, _list_data=data,
                           _force_render=True, _discard_read=False, _cancel_watchdog=lambda: None, _render_list=rendered.append)
    QuarantinePage.handle_message(page, UIMessage("quarantine_data", {"result": data}))
    assert rendered == [data]
    page._force_render = False
    page._loading = True
    QuarantinePage.handle_message(page, UIMessage("quarantine_data", {"result": data}))
    assert rendered == [data]


def test_batch_completion_keeps_failed_selection_and_requests_one_refresh():
    refreshes = []
    page = SimpleNamespace(_batch_busy=True, _selected={"deleted", "locked"}, _detail_ref=None,
                           _refresh_current=lambda: refreshes.append("refresh"))
    QuarantinePage.handle_message(page, UIMessage("quarantine_batch_deleted", {"result": {
        "items": [{"item_ref": "deleted", "deleted": True}, {"item_ref": "locked", "deleted": False}],
        "deleted_count": 1, "failed_count": 1, "message": "1 deleted, 1 failed", "tone": "warning",
    }}))
    assert not page._batch_busy
    assert page._selected == {"locked"}
    assert refreshes == ["refresh"] and len(page._batch_results) == 2


def test_confirm_dialog_confirm_and_cancel_are_once_only(monkeypatch):
    from app.ui.components import dialogs
    destroyed, callbacks = [], []
    monkeypatch.setattr(dialogs.ctk.CTkToplevel, "destroy", lambda self: destroyed.append(True))
    fake = SimpleNamespace(_decision_made=False, _on_confirm=lambda: callbacks.append("delete"))
    # Bind to an uninitialized instance so super() uses the actual class while
    # the underlying Tk destruction is safely stubbed out.
    fake = object.__new__(ConfirmDialog)
    fake._decision_made = False
    fake._on_confirm = lambda: callbacks.append("delete")
    ConfirmDialog.destroy(fake)
    ConfirmDialog.confirm(fake)
    assert callbacks == []
    fake._decision_made = False
    ConfirmDialog.confirm(fake)
    ConfirmDialog.confirm(fake)
    assert callbacks == ["delete"]


def test_reparse_flag_is_rejected_before_any_storage_deletion(storage, monkeypatch):
    service, _, _, make = storage
    item = make()
    original_lstat = Path.lstat
    def lstat(path, *args, **kwargs):
        info = original_lstat(path, *args, **kwargs)
        if path == Path(item.stored_path):
            return SimpleNamespace(st_mode=info.st_mode, st_file_attributes=0x400)
        return info
    monkeypatch.setattr(Path, "lstat", lstat)
    result = service.delete_quarantine_objects((item.quarantine_id,))[0]
    assert result["status"] == "REJECTED" and not result["deleted"]
    assert Path(item.stored_path).exists()


def test_database_finalization_failure_preserves_claim_and_blocks_repeated_disposal(storage, monkeypatch):
    service, database, _, make = storage
    item = make()
    original = database.connection
    @contextmanager
    def fail_finalization():
        with original() as connection:
            class Proxy:
                def execute(self, sql, parameters=()):
                    if "UPDATE quarantine_items SET state='FAILED', deleted_at=" in sql:
                        raise sqlite3.OperationalError("Fixture: metadata finalization failed")
                    return connection.execute(sql, parameters)
            yield Proxy()
    monkeypatch.setattr(database, "connection", fail_finalization)
    result = service.delete_quarantine_objects((item.quarantine_id,))[0]
    assert not result["deleted"] and result["status"] == "RECONCILIATION_REQUIRED"
    assert not Path(item.stored_path).exists()
    assert service.get_item(item.quarantine_id).deleted_at is None
    assert attempts(database)[0]["status"] == "RUNNING"
    Path(item.stored_path).write_bytes(b"new unrelated replacement")
    retry = service.delete_quarantine_objects((item.quarantine_id,))[0]
    assert retry["status"] == "REJECTED"
    assert Path(item.stored_path).read_bytes() == b"new unrelated replacement"


def test_filter_entry_write_trace_is_removed_before_widget_destruction():
    import tkinter as tk
    try:
        interpreter = tk.Tcl()
    except tk.TclError as error:
        pytest.skip(f"Tcl runtime is unavailable in this Python installation: {error}")
    variable = tk.StringVar(master=interpreter, value="")
    invoked = []
    callback = variable.trace_add("write", lambda *args: invoked.append(True))
    page = SimpleNamespace(_filter_entry=SimpleNamespace(_textvariable_callback_name=callback), _filter_value=variable)
    QuarantinePage._detach_filter_entry(page)
    variable.set("new filter")
    assert invoked == [] and not variable.trace_info() and page._filter_entry is None


def test_stale_read_after_batch_is_discarded_instead_of_rendered():
    rendered = []
    page = SimpleNamespace(_detail_ref=None, _loading=True, _batch_busy=False, _discard_read=True,
                           _cancel_watchdog=lambda: None, _render_list=rendered.append)
    QuarantinePage.handle_message(page, UIMessage("quarantine_data", {"result": {"items": [{"item_ref": "old"}]}}))
    assert rendered == [] and page._reload_pending and not page._discard_read
