"""Paginated session history and session-local file evidence, on the Tk thread."""
from __future__ import annotations

from datetime import date, datetime, time as day_time, timedelta, timezone
import time

import customtkinter as ctk

from app.models import DetectionStatus, ScanStatus, ScanType
from app.ui import theme
from app.ui.base_page import BasePage
from app.ui.components import StateCard, StatusBadge


LOAD_TIMEOUT_MS = 20000
LIVE_THROTTLE_MS = 4000
TYPE_LABELS = {"All scan types": None, "Quick": "quick", "Full": "full", "Custom": "manual",
               "Scheduled": "scheduled", "Startup": "startup", "USB": "usb",
               "Real-time": "real_time", "Matching copies": "matching_copy", "Recovery": "recovery"}
STATUS_LABELS = {"All statuses": None, "Running": "RUNNING", "Completed": "COMPLETED",
                 "Incomplete / stopped": "INCOMPLETE", "Failed": "FAILED"}


def date_bounds(mode: str, value: str) -> dict:
    """Local calendar days/weeks converted to UTC half-open query bounds."""
    if mode == "All dates":
        return {}
    selected = date.fromisoformat(value.strip())
    if mode == "Week":
        selected -= timedelta(days=selected.weekday())
    end = selected + timedelta(days=7 if mode == "Week" else 1)
    return {"start_at": datetime.combine(selected, day_time.min).astimezone(timezone.utc).isoformat(timespec="microseconds"),
            "end_at": datetime.combine(end, day_time.min).astimezone(timezone.utc).isoformat(timespec="microseconds")}


def scan_label(session):
    label = "Custom" if session.scan_type is ScanType.MANUAL else session.scan_type.value.replace("_", " ").title()
    if session.scan_type is ScanType.USB:
        label = "USB"
    source = session.source.value
    if source in {"scheduled", "startup", "usb"} and source != session.scan_type.value:
        return label + " Scan · " + ("USB" if source == "usb" else source.title())
    return label + " Scan"


def duration(session):
    end = session.finished_at or datetime.now(timezone.utc)
    seconds = max(0, int((end - session.started_at).total_seconds()))
    minutes, seconds = divmod(seconds, 60)
    hours, minutes = divmod(minutes, 60)
    return f"{hours:d}h {minutes:02d}m {seconds:02d}s" if hours else f"{minutes:d}m {seconds:02d}s"


class ActivityPage(BasePage):
    title = "Activity"
    subtitle = "Scan sessions and the files recorded within each scan"

    def __init__(self, master, controller, **kwargs):
        super().__init__(master, controller, **kwargs)
        self._session_id = None
        self._page = 0
        self._list_page = 0
        self._list_scroll = 0.0
        self._filters = {}
        self._filters_open = False
        self._data = None
        self._loading = False
        self._visible = False
        self._request_id = 0
        self._pending_final = False
        self._pending_live = False
        self._live_job = None
        self._watchdog_id = None
        self._last_live_read = 0.0
        self._automatic_signature = None
        self._history_revision = None
        self._reset_scroll = False
        self._restore_list_scroll = False
        self._view_key = None
        self._rendered_items = ()
        self._list_widgets = {}
        self._detail_widgets = {}
        self._bottom_frame = self._bottom_next = self._bottom_previous = None
        self._build_toolbar()
        self.content = ctk.CTkFrame(self.body, fg_color="transparent", height=1)
        self.content.grid(row=1, column=0, sticky="ew", padx=8)
        self.content.grid_columnconfigure(0, weight=1)
        self._state("Scan history", "Open Activity to load saved scan sessions.")

    def _button(self, master, text, command, **kwargs):
        return theme.Button(master, text=text, command=command, fg_color=theme.SURFACE_ALT,
                            hover_color=theme.SURFACE_HOVER, text_color=theme.TEXT, **kwargs)

    def _build_toolbar(self):
        bar = ctk.CTkFrame(self.body, fg_color="transparent", height=1)
        bar.grid(row=0, column=0, padx=8, pady=(0, 12), sticky="ew")
        bar.grid_columnconfigure(0, weight=1)
        self.back = self._button(bar, "Back to Activity", self.back_to_sessions)
        self.back.grid(row=0, column=0, sticky="w", pady=(0, 10))
        self.back.grid_remove()
        self.filter_toggle = self._button(bar, "Filter scans", self._toggle_filters)
        self.filter_toggle.grid(row=0, column=0, sticky="w", pady=(0, 10))
        self._button(bar, "Refresh", self.refresh, width=110).grid(row=0, column=1, sticky="e", pady=(0, 10))
        self.filter_panel = ctk.CTkFrame(bar, fg_color=theme.SURFACE, height=1)
        self.filter_panel.grid(row=1, column=0, columnspan=2, sticky="ew", pady=(0, 12))
        self.filter_panel.grid_remove()
        self.filter_panel.grid_columnconfigure((0, 1), weight=1)
        theme.Label(self.filter_panel, text="Date or week (YYYY-MM-DD; weeks start Monday)",
                    anchor="w", text_color=theme.TEXT_MUTED).grid(row=0, column=0, columnspan=2, padx=12, pady=(10, 4), sticky="ew")
        self.date_mode = ctk.StringVar(value="All dates")
        self.date_value = ctk.StringVar(value=date.today().isoformat())
        self.type_value = ctk.StringVar(value="All scan types")
        self.status_value = ctk.StringVar(value="All statuses")
        self._menu(self.filter_panel, self.date_mode, ("All dates", "Date", "Week")).grid(row=1, column=0, padx=12, pady=4, sticky="ew")
        self.date_entry = ctk.CTkEntry(self.filter_panel, textvariable=self.date_value, font=theme.font(), height=44)
        self.date_entry.grid(row=1, column=1, padx=12, pady=4, sticky="ew")
        self.date_entry.bind("<Return>", lambda event: self.apply_filters())
        self._menu(self.filter_panel, self.type_value, TYPE_LABELS).grid(row=2, column=0, padx=12, pady=4, sticky="ew")
        self._menu(self.filter_panel, self.status_value, STATUS_LABELS).grid(row=2, column=1, padx=12, pady=4, sticky="ew")
        self._button(self.filter_panel, "Apply filters", self.apply_filters).grid(row=3, column=0, padx=12, pady=(4, 10), sticky="w")
        pager = ctk.CTkFrame(bar, fg_color="transparent", height=1)
        pager.grid(row=2, column=0, columnspan=2, sticky="ew")
        pager.grid_columnconfigure(1, weight=1)
        self.previous = self._button(pager, "Previous", lambda: self.change_page(-1), width=110)
        self.previous.grid(row=0, column=0, sticky="w")
        self.page_label = theme.Label(pager, text="Page 1", text_color=theme.TEXT_MUTED)
        self.page_label.grid(row=0, column=1, padx=8, sticky="ew")
        self.next = self._button(pager, "Next", lambda: self.change_page(1), width=100)
        self.next.grid(row=0, column=2, sticky="e")
        self.loading_label = theme.Label(bar, text="", anchor="w", text_color=theme.TEXT_MUTED)
        self.loading_label.grid(row=3, column=0, columnspan=2, sticky="ew", pady=(6, 0))
        self._update_pager()

    def _menu(self, master, variable, values):
        return ctk.CTkOptionMenu(master, variable=variable, values=list(values), height=44, width=180,
                                 font=theme.font(), dropdown_font=theme.font(), fg_color=theme.SURFACE_ALT,
                                 button_color=theme.SURFACE_HOVER, text_color=theme.TEXT)

    def _cancel_timer(self, name):
        job = getattr(self, name)
        if job is not None:
            self.after_cancel(job)
            setattr(self, name, None)

    def on_show(self):
        self._visible = True
        self.refresh()

    def on_hide(self):
        self._visible = False
        self._request_id += 1
        self._loading = False
        self._pending_final = False
        self._pending_live = False
        self._cancel_timer("_live_job")
        self._cancel_timer("_watchdog_id")
        self.controller.cancel_activity_view()

    def destroy(self):
        self.on_hide()
        super().destroy()

    def apply_filters(self):
        try:
            filters = date_bounds(self.date_mode.get(), self.date_value.get())
            filters.update(scan_type=TYPE_LABELS[self.type_value.get()], status=STATUS_LABELS[self.status_value.get()])
        except ValueError:
            self.loading_label.configure(text="Enter a valid date as YYYY-MM-DD, then apply filters.")
            return
        self._filters = filters
        self._filters_open = False
        self.filter_panel.grid_remove()
        self.filter_toggle.configure(text="Filter scans · active" if any(filters.values()) else "Filter scans")
        self._page = self._list_page = 0
        self._navigate()

    def _toggle_filters(self):
        self._filters_open = not self._filters_open
        if self._filters_open:
            self.filter_panel.grid()
        else:
            self.filter_panel.grid_remove()

    def open_session(self, session_id):
        self._list_page = self._page
        self._list_scroll = self.body._parent_canvas.yview()[0]
        self._session_id = session_id
        self._page = 0
        self.back.grid()
        self.filter_toggle.grid_remove()
        self.filter_panel.grid_remove()
        self._navigate()

    def back_to_sessions(self):
        self._session_id = None
        self._page = self._list_page
        self.back.grid_remove()
        self.filter_toggle.grid()
        if self._filters_open:
            self.filter_panel.grid()
        self._navigate(reset_scroll=False)

    def change_page(self, delta):
        self._page = max(0, self._page + delta)
        self._navigate()

    def _navigate(self, reset_scroll=True):
        self._request_id += 1
        self._loading = False
        self._data = None
        self._pending_final = False
        self._pending_live = False
        self._cancel_timer("_watchdog_id")
        self._cancel_timer("_live_job")
        self._reset_scroll = reset_scroll
        self._restore_list_scroll = not reset_scroll and not self._session_id
        self._state("Loading scan results…" if self._session_id else "Loading scan sessions…", "Reading saved history in the background.")
        self.refresh()

    def refresh(self):
        if not self._visible:
            return
        if self._loading:
            self._pending_final = True
            return
        self._cancel_timer("_live_job")
        self._request_id += 1
        self._loading = True
        self._last_live_read = time.monotonic()
        self.loading_label.configure(text="Updating saved results…" if self._data else "Loading…")
        self._update_pager()
        token = self._request_id
        self._watchdog_id = self.after(LOAD_TIMEOUT_MS, lambda: self._timeout(token))
        self.controller.request_activity_view(token, session_id=self._session_id, page=self._page, filters=self._filters)

    def _timeout(self, token):
        self._watchdog_id = None
        if token == self._request_id and self._loading:
            self._request_id += 1
            self.controller.cancel_activity_view()
            self._loading = False
            self._data = None
            self._pending_final = False
            self._pending_live = False
            self.loading_label.configure(text="Loading timed out. Please retry.")
            self._state("Unable to load scan results", "The database did not respond in time. Your scan evidence is unchanged.", retry=True)
            self._update_pager()

    def scan_data_changed(self, session_id=None):
        if not self._visible or self._live_job is not None:
            return
        if self._session_id:
            if session_id and session_id != self._session_id:
                return
            if self._data and self._data["session"].status.value != "RUNNING":
                return
        delay = max(100, LIVE_THROTTLE_MS - int((time.monotonic() - self._last_live_read) * 1000))
        self._live_job = self.after(delay, self._live_refresh)

    def _live_refresh(self):
        self._live_job = None
        if self._loading:
            self._pending_live = True
        else:
            self.refresh()

    def refresh_from_state(self, reason=""):
        if reason.startswith("scan_"):
            self._pending_live = False
            self._cancel_timer("_live_job")
            self.refresh()

    def handle_message(self, message):
        if message.kind in {"task_finished", "task_failed"}:
            task = message.payload.get("task", "")
            if task.startswith("scan:") or task in {"quick-scan", "full-scan"}:
                self.refresh_from_state("scan_finished")
            return
        if message.kind == "dashboard_data":
            snapshot = message.payload.get("result", {})
            revision = snapshot.get("scan_history_revision")
            if revision is not None and revision != self._history_revision:
                self._history_revision = revision
                self.scan_data_changed()
            active = snapshot.get("active_scan")
            signature = tuple(active.get(key) for key in ("started_at", "processed", "discovered", "errors")) if active else None
            if signature != self._automatic_signature:
                previous = self._automatic_signature
                self._automatic_signature = signature
                if signature is None and previous is not None:
                    self.refresh_from_state("scan_completed")
                elif signature is not None:
                    self.scan_data_changed()
            return
        if message.kind not in {"activity_view_data", "activity_view_error"}:
            return
        if message.payload.get("request_id") != self._request_id or not self._visible or not self._loading:
            return
        self._cancel_timer("_watchdog_id")
        self._loading = False
        self.loading_label.configure(text="")
        if message.kind == "activity_view_error":
            self._data = None
            self._state("Unable to load scan results", message.payload.get("error", "Please try again."), retry=True)
        else:
            data = message.payload["result"]
            changed = data != self._data
            self._data = data
            if changed:
                position = self.body._parent_canvas.yview()[0]
                self._render_data()
                target = 0.0 if self._reset_scroll else (self._list_scroll if self._restore_list_scroll else position)
                token = self._request_id
                self.after_idle(lambda: self._restore_scroll(token, target))
                self._reset_scroll = False
                self._restore_list_scroll = False
        self._update_pager()
        if self._pending_final:
            self._pending_final = False
            self.refresh()
        elif self._pending_live:
            self._pending_live = False
            self.scan_data_changed()

    def _restore_scroll(self, token, target):
        if token == self._request_id and self._visible:
            self.body._parent_canvas.yview_moveto(target)

    def _update_pager(self):
        total = self._data["total"] if self._data else 0
        size = self._data["page_size"] if self._data else 50
        pages = max(1, (total + size - 1) // size)
        self.page_label.configure(text=f"Page {self._page + 1} of {pages} · {total:,} {'records' if self._session_id else 'sessions'}")
        self.previous.configure(state="normal" if self._page and not self._loading else "disabled")
        self.next.configure(state="normal" if (self._page + 1) * size < total and not self._loading else "disabled")
        if self._bottom_next is not None:
            self._bottom_next.configure(state=self.next.cget("state"))
            self._bottom_previous.configure(state=self.previous.cget("state"))

    def _clear_content(self):
        self._view_key = None
        self._rendered_items = ()
        self._list_widgets = {}
        self._detail_widgets = {}
        self._bottom_frame = self._bottom_next = self._bottom_previous = None
        for child in self.content.winfo_children():
            child.destroy()

    def _state(self, title, message, retry=False):
        self._clear_content()
        StateCard(self.content, title, message, tone="error" if retry else "info").grid(row=0, column=0, sticky="ew", pady=4)
        if retry:
            self._button(self.content, "Retry", self._retry).grid(row=1, column=0, sticky="w", pady=8)

    def _retry(self):
        self._data = None
        self._state("Loading…", "Reading saved scan history.")
        self.refresh()

    def _card(self, row):
        card = ctk.CTkFrame(self.content, fg_color=theme.SURFACE, corner_radius=theme.RADIUS,
                            border_width=1, border_color=theme.BORDER, height=1)
        card.grid(row=row, column=0, sticky="ew", pady=5)
        card.grid_columnconfigure(0, weight=1)
        return card

    def _label(self, parent, text, row, role="body", color=None):
        label = theme.Label(parent, text=text, font=theme.font(role), text_color=color or theme.TEXT,
                            anchor="w", justify="left")
        label.grid(row=row, column=0, sticky="ew", padx=16, pady=5)
        return label

    def _stats(self, session, safe):
        count = session.counters
        skipped = count["skipped_size"] + count["locked_files"] + count["unsupported_files"]
        return (f"Discovered: {count['discovered_files']:,}   ·   Processed: {count['discovered_files']:,}   ·   Successfully scanned: {count['scanned_files']:,}\n"
                f"Safe: {safe:,}   ·   Suspicious: {count['suspicious_detections']:,}   ·   Dangerous: {count['dangerous_detections']:,}\n"
                f"Skipped: {skipped:,}   ·   Errors: {count['errors']:,}   ·   Duration: {duration(session)}")

    def _render_data(self):
        key = (self._session_id, self._page)
        items = tuple(self._data["items"])
        if key == self._view_key:
            if self._session_id and self._rendered_items and items[:len(self._rendered_items)] == self._rendered_items:
                self._update_detail_header()
                self._render_result_rows(items[len(self._rendered_items):], start=len(self._rendered_items) + 1)
                self._bottom_frame.grid_configure(row=len(items) + 1)
                self._rendered_items = items
                return
            if not self._session_id and tuple(item["session"].id for item in items) == tuple(self._list_widgets):
                for item in items:
                    self._update_session_widgets(item)
                return
        self._clear_content()
        if self._session_id:
            self._render_details()
            return
        if not self._data["items"]:
            filtered = any(self._filters.values())
            self._state("No matching scans" if filtered else "No scan history",
                        "Try a different date, type, or status." if filtered else "Run a scan to build your scan history.")
            return
        previous_date = None
        row = 0
        for item in self._data["items"]:
            session = item["session"]
            local = session.started_at.astimezone()
            heading = local.strftime("%A, %d %B %Y")
            if heading != previous_date:
                self._label(self.content, heading, row, "section")
                row += 1
                previous_date = heading
            card = self._card(row)
            self._button(card, f"{scan_label(session)} · {local.strftime('%H:%M:%S')} · View files",
                         lambda selected=session.id: self.open_session(selected), anchor="w").grid(row=0, column=0, padx=12, pady=(12, 4), sticky="ew")
            badge = StatusBadge(card, session.status.value.title(), session.status.value.lower())
            badge.grid(row=1, column=0, padx=16, pady=4, sticky="w")
            stats = self._label(card, self._stats(session, item["safe"]), 2)
            note = self._label(card, "Scan in progress. Totals reflect outcomes saved so far.", 3, "secondary", theme.TEXT_MUTED)
            self._list_widgets[session.id] = (badge, stats, note)
            self._update_session_widgets(item)
            row += 1
        self._bottom_pager(row)
        self._view_key = key

    def _update_session_widgets(self, item):
        session = item["session"]
        badge, stats, note = self._list_widgets[session.id]
        badge.set_status(session.status.value.title(), "partial" if session.status.value == "INCOMPLETE" else session.status.value.lower())
        stats.configure(text=self._stats(session, item["safe"]))
        if session.status.value == "RUNNING":
            note.grid()
        else:
            note.grid_remove()

    def _bottom_pager(self, row):
        pager = self._card(row)
        self._bottom_frame = pager
        pager.grid_columnconfigure(1, weight=1)
        size, total = self._data["page_size"], self._data["total"]
        self._bottom_previous = self._button(pager, "Previous", lambda: self.change_page(-1), width=110,
                     state="normal" if self._page else "disabled")
        self._bottom_previous.grid(row=0, column=0, padx=12, pady=12, sticky="w")
        theme.Label(pager, text=f"Page {self._page + 1}", text_color=theme.TEXT_MUTED).grid(row=0, column=1, sticky="ew")
        self._bottom_next = self._button(pager, "Next", lambda: self.change_page(1), width=100,
                     state="normal" if (self._page + 1) * size < total else "disabled")
        self._bottom_next.grid(row=0, column=2, padx=12, pady=12, sticky="e")

    def _render_details(self):
        data = self._data
        session = data["session"]
        header = self._card(0)
        self._label(header, scan_label(session), 0, "section")
        self._label(header, session.started_at.astimezone().strftime("%A, %d %B %Y · %H:%M:%S"), 1)
        badge = StatusBadge(header, session.status.value.title(), session.status.value.lower())
        badge.grid(row=2, column=0, padx=16, pady=5, sticky="w")
        stats = self._label(header, self._stats(session, data["safe"]), 3)
        note = self._label(header, "", 4, "secondary", theme.TEXT_MUTED)
        error = self._label(header, "", 5, "warning", theme.WARNING)
        self._detail_widgets = {"badge": badge, "stats": stats, "note": note, "error": error}
        self._update_detail_header()
        if not data["items"]:
            StateCard(self.content, "No recorded file results", "The scan has not saved any outcomes yet." if session.status.value == "RUNNING" else
                      "This session contains no saved file outcomes.").grid(row=1, column=0, sticky="ew", pady=8)
            return
        self._render_result_rows(data["items"])
        self._bottom_pager(len(data["items"]) + 1)
        self._view_key = (self._session_id, self._page)
        self._rendered_items = tuple(data["items"])

    def _update_detail_header(self):
        data = self._data
        session = data["session"]
        widgets = self._detail_widgets
        widgets["badge"].set_status(session.status.value.title(), "partial" if session.status.value == "INCOMPLETE" else session.status.value.lower())
        widgets["stats"].configure(text=self._stats(session, data["safe"]))
        note = ("Scan in progress. Totals show saved outcomes; undispatched files are not included. " if session.status.value == "RUNNING" else "")
        note += ("Scan Order is the saved processing sequence for this session." if data["guaranteed_order"] else
                 "Legacy record order: numbered within this session by stored record ID. Original processing order was not guaranteed.")
        widgets["note"].configure(text=note)
        if session.error:
            widgets["error"].configure(text=session.error)
            widgets["error"].grid()
        else:
            widgets["error"].grid_remove()

    def _render_result_rows(self, items, start=1):
        data = self._data
        for index, item in enumerate(items, start=start):
            result = item["result"]
            card = self._card(index)
            filename = result.path.replace("\\", "/").rstrip("/").rsplit("/", 1)[-1]
            prefix = "Scan Order" if data["guaranteed_order"] else "Record Order"
            self._label(card, f"{prefix} #{item['order']} · {filename}", 0, "card")
            if result.result_category is ScanStatus.ERROR:
                status, tone = "Error", "failed"
            elif result.result_category is not ScanStatus.SCANNED:
                status, tone = "Skipped · " + result.result_category.value.replace("SKIPPED_", "").title(), "suspicious"
            else:
                status, tone = {DetectionStatus.NO_DETECTION: ("Safe", "protected"),
                                DetectionStatus.LOW_CONFIDENCE: ("Suspicious", "suspicious"),
                                DetectionStatus.HIGH_CONFIDENCE: ("Dangerous", "dangerous")}[result.detection_status]
            if result.entry_kind != "file":
                status += f" · {result.entry_kind.title()} entry"
            StatusBadge(card, status, tone).grid(row=1, column=0, padx=16, pady=4, sticky="w")
            self._label(card, result.path, 2, "body", theme.TEXT_MUTED)
            reason = result.detection_reason or result.reason
            self._label(card, reason, 3, "secondary", theme.TEXT_MUTED)
            self._label(card, "Recorded: " + result.recorded_at.astimezone().strftime("%Y-%m-%d %H:%M:%S.%f"), 4, "secondary", theme.TEXT_DIM)
