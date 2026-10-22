"""Date-grouped scan history and bounded daily file results."""
from __future__ import annotations

from datetime import date, datetime, time as day_time, timedelta, timezone
import sys
import unicodedata

import customtkinter as ctk
import tkinter.font as tkfont
from tkinter import ttk

from app.models import DetectionStatus, ScanStatus, ScanType
from app.ui import theme
from app.ui.base_page import BasePage
from app.ui.components import StateCard


PAGE_SIZE = 50
DATE_PAGE_SIZE = 30
LOAD_TIMEOUT_MS = 20000
CHANGE_DEBOUNCE_MS = 1000
FILE_TABLE_COLUMNS = (
    ("order", "#", 0.07),
    ("filename", "Filename", 0.38),
    ("scan_type", "Scan Type", 0.17),
    ("result", "Detection Result", 0.16),
    ("time", "Time Scanned", 0.14),
    ("details", "Details", 0.08),
)

SCAN_TYPE_FILTERS = {
    "All scan types": None,
    "Real-time": "real_time",
    "Quick": "quick",
    "Full": "full",
    "Custom": "manual",
    "Startup": "startup",
    "Scheduled": "scheduled",
    "USB": "usb",
}
STATUS_FILTERS = {
    "All Files": "all",
    "Safe": "safe",
    "Suspicious": "suspicious",
    "Dangerous": "dangerous",
    "Skipped / Errors": "skipped_errors",
}


def date_bounds(mode: str, value: str) -> dict:
    """Retain the existing helper used by integrations; bounds are local-day UTC."""
    if mode == "All dates":
        return {}
    selected = date.fromisoformat(value.strip())
    if mode == "Week":
        selected -= timedelta(days=selected.weekday())
    end = selected + timedelta(days=7 if mode == "Week" else 1)
    start_utc = datetime.combine(selected, day_time.min).astimezone().astimezone(timezone.utc)
    end_utc = datetime.combine(end, day_time.min).astimezone().astimezone(timezone.utc)
    return {"start_at": start_utc.isoformat(timespec="microseconds"),
            "end_at": end_utc.isoformat(timespec="microseconds")}


def scan_label(scan_type) -> str:
    kind = scan_type if isinstance(scan_type, ScanType) else ScanType(scan_type)
    return {ScanType.MANUAL: "Custom", ScanType.REAL_TIME: "Real-time"}.get(
        kind, kind.value.replace("_", " ").title()
    )


def _display_date(value: str) -> str:
    selected = date.fromisoformat(value)
    today = datetime.now().astimezone().date()
    if selected == today:
        return f"Today — {selected.strftime('%B %d, %Y')}"
    if selected == today - timedelta(days=1):
        return f"Yesterday — {selected.strftime('%B %d, %Y')}"
    return selected.strftime("%B %d, %Y")


def _result_status(result):
    if result.result_category is ScanStatus.ERROR:
        return "Error", "failed"
    if result.result_category is not ScanStatus.SCANNED:
        return "Skipped", "suspicious"
    return {
        DetectionStatus.NO_DETECTION: ("Safe", "protected"),
        DetectionStatus.LOW_CONFIDENCE: ("Suspicious", "suspicious"),
        DetectionStatus.HIGH_CONFIDENCE: ("Dangerous", "dangerous"),
    }[result.detection_status]


def truncate_filename(filename: str, max_width: int, measure) -> str:
    """Fit a filename to a table cell using rendered pixels, preserving Unicode."""
    if max_width <= 0:
        return "…"
    if measure(filename) <= max_width:
        return filename
    ellipsis = "…"
    if measure(ellipsis) > max_width:
        return ellipsis
    low, high = 0, len(filename)
    while low < high:
        middle = (low + high + 1) // 2
        if measure(filename[:middle] + ellipsis) <= max_width:
            low = middle
        else:
            high = middle - 1
    prefix = filename[:low]
    while prefix and unicodedata.combining(prefix[-1]):
        prefix = prefix[:-1]
    return prefix + ellipsis


def scroll_activity_rows(tree, event, *, platform: str | None = None):
    """Scroll only the Activity Treeview and stop CTk's global wheel handlers."""
    platform = platform or sys.platform
    number = getattr(event, "num", None)
    if number == 4:
        units = -1
    elif number == 5:
        units = 1
    else:
        delta = int(getattr(event, "delta", 0) or 0)
        if delta == 0:
            return "break"
        if platform.startswith("win"):
            units = -int(delta / 120)
        elif platform == "darwin":
            units = -int(delta)
        else:
            units = -int(delta / 120)
        if units == 0:
            units = -1 if delta > 0 else 1
    tree.yview_scroll(units, "units")
    return "break"


class ActivityPage(BasePage):
    title = "Activity"
    subtitle = "Review scan history by date and see the files AutoGuard processed."

    def __init__(self, master, controller, **kwargs):
        super().__init__(master, controller, **kwargs)
        self._selected_date: str | None = None
        self._page = 0
        self._data = None
        self._loading = False
        self._force_render = False
        self._visible = False
        self._request_id = 0
        self._pending_refresh = False
        self._watchdog_id = None
        self._change_job = None
        self._scroll_position = 0.0
        self._dates_scroll_position = 0.0
        self._scroll_restore_pending = False
        self._filters = {"status": "all", "scan_type": None, "search": ""}
        self._render_key = None
        self._rendered_row_keys = ()
        self._activity_tree = None
        self._table_details = {}
        self._table_hover_iid = None
        self._table_full_names = {}
        self._table_filename_font = None
        self._table_widths = None
        self._table_rows = None
        self._summary_label = None
        self._pager_label = self._pager_previous = self._pager_next = None
        self.search_value = ctk.StringVar(value="")
        self.status_filter = ctk.StringVar(value="All Files")
        self.type_filter = ctk.StringVar(value="All scan types")
        self._build_toolbar()
        self.content = ctk.CTkFrame(self.body, fg_color="transparent")
        self.content.grid(row=1, column=0, sticky="nsew", padx=8)
        self.content.grid_columnconfigure(0, weight=1)
        self.content.grid_rowconfigure(3, weight=1)
        self.body.grid_rowconfigure(1, weight=1)
        self.bind("<Configure>", self._fit_activity_table, add="+")
        self._state("Scan history", "Open Activity to load saved scan dates.")

    def _button(self, master, text, command, **kwargs):
        return theme.Button(master, text=text, command=command, fg_color=theme.SURFACE_ALT,
                            hover_color=theme.SURFACE_HOVER, text_color=theme.TEXT, **kwargs)

    def _build_toolbar(self):
        bar = ctk.CTkFrame(self.body, fg_color="transparent")
        bar.grid(row=0, column=0, padx=8, pady=(0, 8), sticky="ew")
        bar.grid_columnconfigure(0, weight=1)
        self.back = self._button(bar, "← Back to dates", self.back_to_dates, width=140)
        self.back.grid(row=0, column=0, sticky="w")
        self.refresh_button = self._button(bar, "Refresh", self.refresh, width=100)
        self.refresh_button.grid(row=0, column=1, sticky="e")
        self.loading_label = theme.Label(bar, text="", anchor="w", text_color=theme.TEXT_MUTED)
        self.loading_label.grid(row=1, column=0, columnspan=2, sticky="ew", pady=(5, 0))
        self._update_toolbar()

    def _update_toolbar(self):
        if self._selected_date:
            self.back.grid()
        else:
            self.back.grid_remove()

    def _cancel_timer(self, name):
        job = getattr(self, name)
        if job is not None:
            try:
                self.after_cancel(job)
            except Exception:
                pass
            setattr(self, name, None)

    def on_show(self):
        self._visible = True
        self.controller.set_activity_view_active(True)
        self.refresh()

    def on_hide(self):
        self._visible = False
        self._request_id += 1
        self._loading = False
        self._pending_refresh = False
        self._cancel_timer("_change_job")
        self._cancel_timer("_watchdog_id")
        self.controller.set_activity_view_active(False)
        self.controller.cancel_activity_view()

    def destroy(self):
        self.on_hide()
        super().destroy()

    def open_date(self, local_date: str):
        self._dates_scroll_position = self.body._parent_canvas.yview()[0]
        self._scroll_position = 0.0
        self._selected_date = date.fromisoformat(local_date).isoformat()
        self._page = 0
        self._update_toolbar()
        self._navigate(reset_scroll=True)

    def back_to_dates(self):
        self._scroll_position = self._dates_scroll_position
        self._selected_date = None
        self._page = 0
        self._update_toolbar()
        self._navigate(reset_scroll=False)

    def change_page(self, delta: int):
        self._page = max(0, self._page + delta)
        self._scroll_position = 0.0
        self._navigate(reset_scroll=True)

    def apply_filters(self):
        self._filters = {
            "status": STATUS_FILTERS[self.status_filter.get()],
            "scan_type": SCAN_TYPE_FILTERS[self.type_filter.get()],
            "search": self.search_value.get().strip(),
        }
        self._page = 0
        self._scroll_position = 0.0
        self._navigate(reset_scroll=True)

    def reset_filters(self):
        self.search_value.set("")
        self.status_filter.set("All Files")
        self.type_filter.set("All scan types")
        self.apply_filters()

    def _navigate(self, *, reset_scroll):
        self._request_id += 1
        self._loading = False
        self._pending_refresh = False
        self._cancel_timer("_watchdog_id")
        self._scroll_position = 0.0 if reset_scroll else self._scroll_position
        self._scroll_restore_pending = True
        self._force_render = True
        self._state("Loading scanned files…" if self._selected_date else "Loading scan dates…",
                    "Reading saved history in the background.")
        self.refresh()

    def refresh(self):
        """Explicit refresh. Overlapping requests collapse to the latest view."""
        if not self._visible:
            return
        if self._loading:
            self._pending_refresh = True
            return
        if self._data is not None and not self._scroll_restore_pending:
            self._scroll_position = self.body._parent_canvas.yview()[0]
        self._cancel_timer("_change_job")
        self._request_id += 1
        self._loading = True
        token = self._request_id
        self.loading_label.configure(text="Loading saved history…")
        self._watchdog_id = self.after(LOAD_TIMEOUT_MS, lambda: self._timeout(token))
        self.controller.request_activity_view(
            token, local_date=self._selected_date, page=self._page,
            page_size=PAGE_SIZE if self._selected_date else DATE_PAGE_SIZE,
            filters=self._filters,
        )

    def refresh_from_state(self, reason=""):
        # Scan-history observer events handle data changes. Relevant lifecycle
        # events remain an explicit fallback for older adapters.
        if reason in {"scan_completed", "scan_batch_completed", "scan_history_changed"}:
            self._schedule_change_refresh()

    def _schedule_change_refresh(self):
        if not self._visible or self._change_job is not None:
            return
        self._change_job = self.after(CHANGE_DEBOUNCE_MS, self._flush_change_refresh)

    def _flush_change_refresh(self):
        self._change_job = None
        if self._visible:
            self.refresh()

    def handle_message(self, message):
        if message.kind == "scan_history_changed":
            if not self._visible:
                return
            changed_date = message.payload.get("local_date")
            changed_dates = message.payload.get("local_dates", (changed_date,))
            if self._selected_date and self._selected_date not in changed_dates:
                return
            self._schedule_change_refresh()
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
            self._force_render = False
            self._state("Unable to load scan history", message.payload.get("error", "Please try again."), retry=True)
        else:
            new_data = message.payload["result"]
            if self._force_render or new_data != self._data:
                previous = self._data
                self._data = new_data
                if not self._force_render and self._can_patch_daily_page(previous, new_data):
                    self._update_daily_summary()
                    self._update_pager_controls()
                else:
                    self._render_data()
                self._force_render = False
                token, target = self._request_id, self._scroll_position
                self.after_idle(lambda: self._restore_scroll(token, target))
        if self._pending_refresh:
            self._pending_refresh = False
            self.refresh()

    def _restore_scroll(self, token, target):
        if token == self._request_id and self._visible:
            self.body._parent_canvas.yview_moveto(target)
            self._scroll_restore_pending = False

    def _timeout(self, token):
        self._watchdog_id = None
        if token == self._request_id and self._loading:
            self._request_id += 1
            self.controller.cancel_activity_view()
            self._loading = False
            self._pending_refresh = False
            self._data = None
            self._force_render = False
            self.loading_label.configure(text="Loading timed out. Please retry.")
            self._state("Unable to load scan history", "The database did not respond in time. Your scan evidence is unchanged.", retry=True)

    def _clear_content(self):
        self._summary_label = None
        self._pager_label = self._pager_previous = self._pager_next = None
        self._rendered_row_keys = ()
        self._activity_tree = None
        self._table_details = {}
        self._table_full_names = {}
        self._table_hover_iid = None
        self._table_widths = None
        for child in self.content.winfo_children():
            child.destroy()

    def _state(self, title, message, retry=False):
        if not hasattr(self, "content"):
            return
        self._clear_content()
        StateCard(self.content, title, message, tone="error" if retry else "info").grid(
            row=0, column=0, sticky="ew", pady=4
        )
        if retry:
            self._button(self.content, "Retry", self.refresh).grid(row=1, column=0, sticky="w", pady=8)

    def _label(self, parent, text, row, column=0, *, role="body", color=None, **kwargs):
        label = theme.Label(parent, text=text, font=theme.font(role), text_color=color or theme.TEXT,
                            anchor="w", justify="left", **kwargs)
        label.grid(row=row, column=column, sticky="ew", padx=10, pady=5)
        return label

    def _render_data(self):
        self._render_key = (self._selected_date, self._page, tuple(sorted(self._filters.items())))
        if self._selected_date:
            self._render_files()
        else:
            self._render_dates()

    def _can_patch_daily_page(self, previous, current):
        if not self._selected_date or previous is None:
            return False
        key = (self._selected_date, self._page, tuple(sorted(self._filters.items())))
        if self._render_key != key or previous.get("local_date") != current.get("local_date"):
            return False
        old_rows = tuple((item["result"].id, item["order"]) for item in previous["items"])
        new_rows = tuple((item["result"].id, item["order"]) for item in current["items"])
        return old_rows == new_rows

    def _update_daily_summary(self):
        if self._summary_label is None or self._data is None:
            return
        summary = self._data["summary"]
        self._summary_label.configure(
            text=f"{summary['total']:,} file scan events  |  {summary['safe']:,} safe  |  "
                 f"{summary['suspicious']:,} suspicious  |  {summary['dangerous']:,} dangerous  |  "
                 f"{summary['skipped']:,} skipped  |  {summary['errors']:,} errors"
        )

    def _update_pager_controls(self):
        if self._pager_label is None or self._data is None:
            return
        data = self._data
        pages = max(1, (data["total"] + data["page_size"] - 1) // data["page_size"])
        self._pager_label.configure(text=f"Page {data['page'] + 1} of {pages}  ·  {data['total']:,} results")
        self._pager_previous.configure(state="normal" if data["page"] > 0 else "disabled")
        self._pager_next.configure(state="normal" if (data["page"] + 1) * data["page_size"] < data["total"] else "disabled")

    def _render_dates(self):
        data = self._data
        self._clear_content()
        if not data["items"]:
            StateCard(self.content, "No scan history", "Run a scan to build your scan history.").grid(
                row=0, column=0, sticky="ew", pady=4
            )
            return
        for row, item in enumerate(data["items"]):
            card = ctk.CTkFrame(self.content, fg_color=theme.SURFACE, corner_radius=theme.RADIUS,
                                border_width=1, border_color=theme.BORDER)
            card.grid(row=row, column=0, sticky="ew", pady=4)
            card.grid_columnconfigure(0, weight=1)
            date_value = item["local_date"]
            self._label(card, _display_date(date_value), 0, role="card")
            summary = (f"{item['total']:,} files  ·  {item['safe']:,} safe  ·  "
                       f"{item['suspicious']:,} suspicious  ·  {item['dangerous']:,} dangerous")
            summary = summary.replace(" files  ", " scan events  ")
            self._label(card, summary, 1, color=theme.TEXT_MUTED)
            self._button(card, "View scanned files →", lambda value=date_value: self.open_date(value),
                         width=180).grid(row=0, column=1, rowspan=2, padx=12, pady=10, sticky="e")
        self._render_pager(data, len(data["items"]))

    def _render_files(self):
        data = self._data
        self._clear_content()
        self._label(self.content, _display_date(data["local_date"]), 0, role="section")
        summary = data["summary"]
        self._summary_label = self._label(
            self.content,
            f"{summary['total']:,} file scan events  |  {summary['safe']:,} safe  |  "
            f"{summary['suspicious']:,} suspicious  |  {summary['dangerous']:,} dangerous  |  "
            f"{summary['skipped']:,} skipped  |  {summary['errors']:,} errors",
            1, color=theme.TEXT_MUTED, wraplength=1100,
        )
        filters = ctk.CTkFrame(self.content, fg_color=theme.SURFACE, corner_radius=theme.RADIUS)
        filters.grid(row=2, column=0, sticky="ew", pady=(8, 6))
        filters.grid_columnconfigure(0, weight=1, minsize=180)
        search = ctk.CTkEntry(filters, textvariable=self.search_value,
                              placeholder_text="Search filename or path", font=theme.font(), height=44,
                              fg_color=theme.SURFACE_ALT, border_color=theme.BORDER,
                              text_color=theme.TEXT, placeholder_text_color=theme.TEXT_DIM,
                              corner_radius=theme.RADIUS_SMALL)
        search.grid(row=0, column=0, padx=8, pady=8, sticky="ew")
        search.bind("<Return>", lambda event: self.apply_filters())
        ctk.CTkOptionMenu(filters, variable=self.status_filter, values=list(STATUS_FILTERS),
                          height=44, font=theme.font(), dropdown_font=theme.font(),
                          fg_color=theme.SURFACE_ALT, button_color=theme.SURFACE_HOVER,
                          button_hover_color=theme.ACCENT_DARK, text_color=theme.TEXT,
                          dropdown_fg_color=theme.SURFACE, dropdown_text_color=theme.TEXT,
                          dropdown_hover_color=theme.SURFACE_HOVER).grid(
                              row=0, column=1, padx=8, pady=8)
        ctk.CTkOptionMenu(filters, variable=self.type_filter, values=list(SCAN_TYPE_FILTERS),
                          height=44, font=theme.font(), dropdown_font=theme.font(),
                          fg_color=theme.SURFACE_ALT, button_color=theme.SURFACE_HOVER,
                          button_hover_color=theme.ACCENT_DARK, text_color=theme.TEXT,
                          dropdown_fg_color=theme.SURFACE, dropdown_text_color=theme.TEXT,
                          dropdown_hover_color=theme.SURFACE_HOVER).grid(
                              row=0, column=2, padx=8, pady=8)
        self._button(filters, "Apply", self.apply_filters, width=80, height=40).grid(row=0, column=3, padx=8, pady=8)
        self._button(filters, "Reset", self.reset_filters, width=80, height=40).grid(row=0, column=4, padx=(0, 8), pady=8)

        table = ctk.CTkFrame(self.content, fg_color=theme.SURFACE, corner_radius=theme.RADIUS,
                             border_width=1, border_color=theme.BORDER)
        table.grid(row=3, column=0, sticky="nsew", pady=(4, 0))
        table.grid_columnconfigure(0, weight=1)
        table.grid_rowconfigure(0, weight=1)
        row_font = (theme.FONT, round(15 * theme.TEXT_SCALES[theme.text_size()]))
        heading_font = (theme.FONT, round(15 * theme.TEXT_SCALES[theme.text_size()]), "bold")
        style = ttk.Style(self)
        style.configure("AutoGuard.Activity.Treeview", background=theme.SURFACE,
                        fieldbackground=theme.SURFACE, foreground=theme.TEXT,
                        rowheight=44, borderwidth=0, font=row_font)
        style.configure("AutoGuard.Activity.Treeview.Heading", background=theme.SURFACE_ALT,
                        foreground=theme.TEXT_MUTED, font=heading_font, padding=(10, 10), relief="flat")
        style.map("AutoGuard.Activity.Treeview", background=[("selected", "#24564E")],
                  foreground=[("selected", theme.TEXT)])
        style.configure("AutoGuard.Activity.Vertical.TScrollbar", background=theme.SURFACE_ALT,
                        troughcolor=theme.BG, bordercolor=theme.BORDER, arrowcolor=theme.TEXT_MUTED)
        style.configure("AutoGuard.Activity.Horizontal.TScrollbar", background=theme.SURFACE_ALT,
                        troughcolor=theme.BG, bordercolor=theme.BORDER, arrowcolor=theme.TEXT_MUTED)
        columns = tuple(column[0] for column in FILE_TABLE_COLUMNS)
        tree = ttk.Treeview(table, columns=columns, show="headings", height=5,
                            selectmode="browse", style="AutoGuard.Activity.Treeview")
        self._activity_tree = tree
        self._table_rows = None
        self._table_filename_font = tkfont.Font(root=self, font=row_font)
        for column, heading, _proportion in FILE_TABLE_COLUMNS:
            tree.heading(column, text=heading, anchor="w" if column == "filename" else "center")
        for column, width, anchor, stretch in (
            ("order", 72, "center", False), ("filename", 390, "w", True),
            ("scan_type", 150, "center", True), ("result", 150, "center", True),
            ("time", 150, "center", True), ("details", 82, "center", False),
        ):
            tree.column(column, width=width, minwidth=70 if column == "filename" else width,
                        anchor=anchor, stretch=stretch)
        tree.tag_configure("odd", background=theme.SURFACE)
        tree.tag_configure("even", background=theme.SURFACE_ALT)
        tree.tag_configure("hover", background=theme.SURFACE_HOVER)
        for tone, (foreground, _background) in theme.STATUS_COLORS.items():
            tree.tag_configure(f"status_{tone}", foreground=foreground)
        tree.grid(row=0, column=0, sticky="nsew")
        vertical = ttk.Scrollbar(table, orient="vertical", command=tree.yview,
                                 style="AutoGuard.Activity.Vertical.TScrollbar")
        horizontal = ttk.Scrollbar(table, orient="horizontal", command=tree.xview,
                                   style="AutoGuard.Activity.Horizontal.TScrollbar")
        tree.configure(yscrollcommand=vertical.set, xscrollcommand=horizontal.set)
        vertical.grid(row=0, column=1, sticky="ns")
        horizontal.grid(row=1, column=0, sticky="ew")
        for widget in (tree, vertical, horizontal):
            widget.bind("<MouseWheel>", lambda event, target=tree: scroll_activity_rows(target, event), add="+")
            widget.bind("<Button-4>", lambda event, target=tree: scroll_activity_rows(target, event), add="+")
            widget.bind("<Button-5>", lambda event, target=tree: scroll_activity_rows(target, event), add="+")
        tree.bind("<Button-1>", self._on_table_click, add="+")
        tree.bind("<Return>", self._open_selected_details, add="+")
        tree.bind("<Motion>", self._on_table_motion, add="+")
        tree.bind("<Leave>", self._clear_table_hover, add="+")
        tree.bind("<Configure>", self._resize_table_columns, add="+")
        table.bind("<Configure>", self._fit_activity_table, add="+")
        self._table_details = {}
        if not data["items"]:
            tree.insert("", "end", values=("", "No matching files", "", "", "", ""), tags=("odd",))
        for index, item in enumerate(data["items"]):
            result = item["result"]
            filename = result.path.replace("\\", "/").rstrip("/").rsplit("/", 1)[-1]
            status, tone = _result_status(result)
            iid = str(result.id)
            tree.insert("", "end", iid=iid,
                        values=(item["order"], truncate_filename(filename, 360, self._table_filename_font.measure),
                                scan_label(item["scan_type"]), status,
                                result.recorded_at.astimezone().strftime("%I:%M:%S %p").lstrip("0"), "View"),
                        tags=("even" if index % 2 else "odd", f"status_{tone}"))
            self._table_details[iid] = item
            self._table_full_names[iid] = filename
        self._rendered_row_keys = tuple((item["result"].id, item["order"]) for item in data["items"])
        self._render_pager(data, len(data["items"]), row=4)

    def _fit_activity_table(self, _event=None):
        tree = self._activity_tree
        if tree is None or not tree.winfo_exists():
            return
        # Leave room for the fixed app/page headers, date summary, filter row,
        # and pager. The Treeview remains bounded and takes the remaining space.
        available = max(0, int(self.winfo_height()) - 500)
        rows = max(4, min(12, available // 44))
        if rows != self._table_rows:
            self._table_rows = rows
            tree.configure(height=rows)

    def _resize_table_columns(self, event):
        tree = self._activity_tree
        if tree is None or event.width < 1:
            return
        proportions = tuple(column[2] for column in FILE_TABLE_COLUMNS)
        minimums = (70, 220, 110, 120, 120, 82)
        available = max(event.width - 18, sum(minimums))
        widths = [max(minimum, round(available * ratio))
                  for minimum, ratio in zip(minimums, proportions)]
        # Keep the total equal to the viewport when minimums are not binding.
        difference = available - sum(widths)
        widths[1] = max(minimums[1], widths[1] + difference)
        if tuple(widths) == self._table_widths:
            return
        self._table_widths = tuple(widths)
        for column, width in zip(("order", "filename", "scan_type", "result", "time", "details"), widths):
            tree.column(column, width=width, minwidth=70 if column == "filename" else width)
        font = self._table_filename_font
        if font is not None:
            max_width = max(70, widths[1] - 28)
            for iid, filename in self._table_full_names.items():
                if tree.exists(iid):
                    values = list(tree.item(iid, "values"))
                    values[1] = truncate_filename(filename, max_width, font.measure)
                    tree.item(iid, values=values)

    def _on_table_click(self, event):
        tree = self._activity_tree
        if tree is not None and tree.identify_column(event.x) == "#6":
            iid = tree.identify_row(event.y)
            if iid in self._table_details:
                tree.selection_set(iid)
                self._show_result_details(self._table_details[iid])
                return "break"

    def _open_selected_details(self, _event=None):
        tree = self._activity_tree
        if tree is not None:
            selected = tree.selection()
            if selected and selected[0] in self._table_details:
                self._show_result_details(self._table_details[selected[0]])
        return "break"

    def _on_table_motion(self, event):
        tree = self._activity_tree
        iid = tree.identify_row(event.y) if tree is not None else None
        if tree is not None:
            pointer = iid in self._table_details and tree.identify_column(event.x) == "#6"
            tree.configure(cursor="hand2" if pointer else "")
        if iid == self._table_hover_iid:
            return
        self._set_table_hover(iid)

    def _clear_table_hover(self, _event=None):
        self._set_table_hover(None)

    def _set_table_hover(self, iid):
        tree = self._activity_tree
        if tree is None:
            return
        for item_id in (self._table_hover_iid, iid):
            if item_id and tree.exists(item_id):
                tags = tuple(tag for tag in tree.item(item_id, "tags") if tag != "hover")
                tree.item(item_id, tags=tags + (("hover",) if item_id == iid else ()))
        self._table_hover_iid = iid

    def _show_result_details(self, item):
        result = item["result"]
        filename = result.path.replace("\\", "/").rstrip("/").rsplit("/", 1)[-1]
        dialog = ctk.CTkToplevel(self)
        dialog.title("Scanned file details")
        dialog.geometry("680x430")
        dialog.minsize(520, 360)
        dialog.configure(fg_color=theme.BG)
        dialog.transient(self.winfo_toplevel())
        dialog.grid_columnconfigure(0, weight=1)
        dialog.grid_rowconfigure(1, weight=1)
        theme.Label(dialog, text="Scanned file details", font=theme.font("section", "bold"),
                    text_color=theme.TEXT).grid(row=0, column=0, sticky="w", padx=20, pady=(18, 10))
        details = ctk.CTkTextbox(dialog, font=theme.font("body"), fg_color=theme.SURFACE,
                                 text_color=theme.TEXT, wrap="word")
        details.grid(row=1, column=0, sticky="nsew", padx=20, pady=8)
        status, _tone = _result_status(result)
        details.insert("1.0", "\n".join((
            f"Filename: {filename}", f"Full path: {result.path}", f"Order for date: #{item['order']}",
            f"Scan type: {scan_label(item['scan_type'])}", f"Source: {item['source'].value}",
            f"Result: {status}",
            f"Recorded: {result.recorded_at.astimezone().strftime('%Y-%m-%d %I:%M:%S %p')}",
            f"Reason: {result.reason or 'No additional details recorded.'}",
            f"Scan session: {result.session_id}",
        )))
        details.configure(state="disabled")
        self._button(dialog, "Close", dialog.destroy, width=100).grid(row=2, column=0, sticky="e", padx=20, pady=(8, 18))
        dialog.grab_set()

    def _render_pager(self, data, shown, row=None):
        if row is None:
            row = shown
        pager = ctk.CTkFrame(self.content, fg_color="transparent")
        pager.grid(row=row, column=0, sticky="ew", pady=10)
        pager.grid_columnconfigure(1, weight=1)
        page = data["page"]
        size = data["page_size"]
        pages = max(1, (data["total"] + size - 1) // size)
        self._pager_previous = self._button(pager, "Previous", lambda: self.change_page(-1), width=100,
                     state="normal" if page > 0 else "disabled")
        self._pager_previous.grid(row=0, column=0, sticky="w")
        self._pager_label = theme.Label(pager, text=f"Page {page + 1} of {pages}  ·  {data['total']:,} results",
                                        text_color=theme.TEXT_MUTED)
        self._pager_label.grid(row=0, column=1, sticky="ew")
        self._pager_next = self._button(pager, "Next", lambda: self.change_page(1), width=100,
                     state="normal" if (page + 1) * size < data["total"] else "disabled")
        self._pager_next.grid(row=0, column=2, sticky="e")
