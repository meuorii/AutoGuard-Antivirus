"""Quarantine selection and confirmed, audited permanent deletion."""
from __future__ import annotations

import customtkinter as ctk

from app.ui import theme
from app.ui.base_page import BasePage
from app.ui.components import ConfirmDialog, StateCard, StatusBadge, SummaryStatCard, compact_text
from app.ui.quarantine_details_page import QuarantineDetailsView


PAGE_SIZE = 50
LOAD_TIMEOUT_MS = 20000


class QuarantinePage(BasePage):
    title = "Quarantine"
    subtitle = "Manage isolated files and review quarantine activity."

    def __init__(self, master, controller, **kwargs):
        super().__init__(master, controller, **kwargs)
        self._detail_ref = None
        self._detail_data = self._list_data = None
        self._notice = None
        self._batch_results = []
        self._loading = False
        self._force_render = False
        self._reload_pending = False
        self._watchdog = None
        self._batch_busy = False
        self._discard_read = False
        self._confirmation = None
        self._selected = set()
        self._filter_text = ""
        self._filter_value = ctk.StringVar(value="")
        self._filter_entry = None
        self._page = 0
        self._selection_widgets = {}
        self._controls = []
        self._pager_buttons = None
        self._selection_label = self._delete_selected_button = self._status_label = None
        self._select_all_button = self._deselect_all_button = None

    def on_show(self):
        selected = self.controller.selected_quarantine_ref
        if selected != self._detail_ref:
            self._loading = False
            self._force_render = True
        self._detail_ref = selected
        if self._batch_busy:
            return
        if not self._list_data and not self._detail_data:
            self._show_loading("Loading quarantine…")
        self._refresh_current()

    def refresh_from_state(self, reason=""):
        self._refresh_current()

    def _cancel_watchdog(self):
        if self._watchdog is not None:
            self.after_cancel(self._watchdog)
            self._watchdog = None

    def destroy(self):
        self._cancel_watchdog()
        self._detach_filter_entry()
        super().destroy()

    def _detach_filter_entry(self):
        if self._filter_entry is not None:
            # CTkEntry 5.2 does not remove its StringVar write trace when
            # detached or destroyed. Remove that residual callback explicitly.
            callback = getattr(self._filter_entry, "_textvariable_callback_name", None)
            if callback and any(name == callback for mode, name in self._filter_value.trace_info()):
                self._filter_value.trace_remove("write", callback)
            self._filter_entry = None

    def clear_body(self):
        self._detach_filter_entry()
        self._selection_widgets = {}
        self._controls = []
        self._pager_buttons = None
        self._selection_label = self._delete_selected_button = self._status_label = None
        self._select_all_button = self._deselect_all_button = None
        super().clear_body()

    def _refresh_current(self):
        if self._batch_busy or self._loading:
            self._reload_pending = True
            return
        self._loading = True
        self._reload_pending = False
        accepted = (self.controller.load_quarantine_details(self._detail_ref) if self._detail_ref
                    else self.controller.load_quarantine())
        if accepted is False:
            self._loading = False
            self._reload_pending = True
        self._cancel_watchdog()
        self._watchdog = self.after(LOAD_TIMEOUT_MS, self._load_timeout)

    def _load_timeout(self):
        self._watchdog = None
        if self._loading or self._reload_pending:
            self._loading = self._reload_pending = False
            self._render_error("Loading took too long. Please retry.")

    def handle_message(self, message):
        kind = message.kind
        if kind == "quarantine_data" and self._detail_ref is None:
            self._cancel_watchdog()
            self._loading = False
            if self._batch_busy or self._discard_read:
                self._discard_read = False
                self._reload_pending = True
                return
            result = dict(message.payload.get("result", {}))
            if self._force_render or result != self._list_data:
                self._list_data = result
                self._render_list(result)
        elif kind == "quarantine_details_requested":
            self._detail_ref = message.payload.get("item_ref")
            self._detail_data = None
            self._loading = False
            self._show_loading("Loading file details…")
            self._refresh_current()
        elif kind == "quarantine_details_data":
            result = message.payload.get("result", {})
            if self._detail_ref and result.get("item_ref") == self._detail_ref:
                self._cancel_watchdog()
                self._loading = False
                if self._batch_busy or self._discard_read:
                    self._discard_read = False
                    self._reload_pending = True
                    return
                if not self._batch_busy and (self._force_render or result != self._detail_data):
                    self._detail_data = result
                    self._render_details(result)
        elif kind == "quarantine_details_closed":
            self._force_render = True
            self._detail_ref = None
            self._detail_data = None
            self._loading = False
            self._refresh_current()
        elif kind == "quarantine_verified":
            self._force_render = True
            result = message.payload.get("result", {})
            self._notice = {"title": result.get("title", "Integrity check finished"),
                            "message": result.get("message", "The integrity check finished."),
                            "tone": "success" if result.get("verified") else "error"}
            self._refresh_current()
        elif kind == "quarantine_batch_deleted":
            self._force_render = True
            result = message.payload.get("result", {})
            self._batch_busy = False
            self._batch_results = list(result.get("items", ()))
            succeeded = {item["item_ref"] for item in self._batch_results if item.get("deleted")}
            self._selected.difference_update(succeeded)
            self._notice = {"title": result.get("title", "Deletion finished"),
                            "message": result.get("message", "Review the per-file deletion results below."),
                            "tone": result.get("tone", "warning")}
            if self._detail_ref in succeeded:
                self.controller.close_quarantine_details()
            else:
                self._refresh_current()
        elif kind == "task_failed":
            task = str(message.payload.get("task", ""))
            if task == "delete-quarantine-batch":
                self._force_render = True
                self._batch_busy = False
                self._notice = {"title": "Operation failed", "message": message.payload.get("error", "Deletion failed. Please retry."), "tone": "error"}
                self._refresh_current()
            elif task.startswith(("load-quarantine", "verify-quarantine:")):
                self._loading = False
                self._cancel_watchdog()
                if self._batch_busy or self._discard_read:
                    self._discard_read = False
                    self._reload_pending = True
                    return
                self._render_error(message.payload.get("error", "AutoGuard could not complete this operation."))
        elif kind == "task_finished" and str(message.payload.get("task", "")).startswith("load-quarantine"):
            if self._reload_pending and not self._loading and not self._batch_busy:
                self._refresh_current()

    def _show_loading(self, title):
        self._force_render = True
        self.clear_body()
        StateCard(self.body, title, "Reading stored quarantine metadata.").grid(row=0, column=0, padx=8, pady=8, sticky="ew")

    def _render_error(self, message):
        self._force_render = True
        self.clear_body()
        StateCard(self.body, "Operation failed", message, tone="danger").grid(row=0, column=0, padx=8, pady=8, sticky="ew")
        self._button(self.body, "Retry", self._refresh_current).grid(row=1, column=0, padx=8, pady=8, sticky="w")

    def _button(self, parent, text, command, **kwargs):
        return theme.Button(parent, text=text, command=command, fg_color=theme.SURFACE_ALT,
                            hover_color=theme.SURFACE_HOVER, text_color=theme.TEXT, **kwargs)

    def _notice_widget(self, row):
        if self._notice:
            StateCard(self.body, self._notice["title"], self._notice["message"],
                      tone=self._notice.get("tone", "info")).grid(row=row, column=0, padx=8, pady=8, sticky="ew")
            row += 1
        if self._batch_results:
            report = ctk.CTkFrame(self.body, fg_color=theme.SURFACE)
            report.grid(row=row, column=0, padx=8, pady=8, sticky="ew")
            report.grid_columnconfigure(0, weight=1)
            theme.Label(report, text="Per-file deletion results", font=theme.font("card", "bold"), text_color=theme.TEXT,
                        anchor="w").grid(row=0, column=0, padx=12, pady=(10, 4), sticky="ew")
            box = ctk.CTkTextbox(report, height=170, font=theme.font("body"), wrap="word", fg_color=theme.SURFACE_ALT, text_color=theme.TEXT)
            box.grid(row=1, column=0, padx=12, pady=(0, 12), sticky="ew")
            lines = [f"{'Deleted' if item.get('deleted') else item.get('status', 'Failed').title()}: {item.get('name', item['item_ref'])} [{item['item_ref']}]\n{item.get('message', '')}" for item in self._batch_results]
            box.insert("1.0", "\n\n".join(lines))
            box.configure(state="disabled")
            row += 1
        return row

    def _filtered_items(self):
        items = (self._list_data or {}).get("items", ())
        query = self._filter_text.casefold()
        return [item for item in items if not query or query in
                " ".join(str(item.get(key, "")) for key in ("name", "original_location", "threat_status")).casefold()]

    def _apply_filter(self):
        if self._batch_busy:
            return
        self._filter_text = self._filter_value.get().strip()
        self._selected.clear()
        self._page = 0
        self._render_list(self._list_data or {})

    def _change_page(self, delta):
        if self._batch_busy:
            return
        self._page = max(0, self._page + delta)
        self._render_list(self._list_data or {})
        self.body._parent_canvas.yview_moveto(0)

    def _select_all(self):
        if not self._batch_busy:
            self._selected = {item["item_ref"] for item in self._filtered_items()}
            self._update_selection()

    def _deselect_all(self):
        if not self._batch_busy:
            self._selected.clear()
            self._update_selection()

    def _toggle_item(self, ref):
        if self._batch_busy:
            return
        if ref in self._selected:
            self._selected.remove(ref)
        else:
            self._selected.add(ref)
        self._update_selection()

    def _update_selection(self):
        for ref, (variable, checkbox, card) in self._selection_widgets.items():
            selected = ref in self._selected
            variable.set(selected)
            checkbox.configure(state="disabled" if self._batch_busy else "normal")
            card.configure(fg_color=theme.ACCENT_DARK if selected else theme.SURFACE,
                           border_width=2 if selected else 1, border_color=theme.ACCENT if selected else theme.BORDER)
        for control in self._controls:
            control.configure(state="disabled" if self._batch_busy else "normal")
        if self._pager_buttons is not None:
            previous, next_button = self._pager_buttons
            previous.configure(state="normal" if self._page and not self._batch_busy else "disabled")
            next_button.configure(state="normal" if (self._page + 1) * PAGE_SIZE < len(self._filtered_items()) and not self._batch_busy else "disabled")
        if self._selection_label:
            count = len(self._selected)
            self._select_all_button.configure(state="normal" if self._filtered_items() and not self._batch_busy else "disabled")
            self._deselect_all_button.configure(state="normal" if count and not self._batch_busy else "disabled")
            self._selection_label.configure(text=f"{count} {'file' if count == 1 else 'files'} selected")
            self._delete_selected_button.configure(text=f"Delete Selected ({count})",
                                                   state="normal" if count and not self._batch_busy else "disabled")
            self._status_label.configure(text="Deleting selected files… Please wait for the batch results." if self._batch_busy else "")

    def _render_list(self, data):
        self._force_render = False
        self._list_data = data
        items = self._filtered_items()
        self._selected.intersection_update(item["item_ref"] for item in items)
        self._page = min(self._page, max(0, (len(items) - 1) // PAGE_SIZE))
        position = self.body._parent_canvas.yview()[0]
        self.clear_body()
        self._selection_widgets = {}
        self._controls = []
        self._pager_buttons = None
        row = self._notice_widget(0)
        count = int(data.get("isolated_count", len(items)))
        summary = ctk.CTkFrame(self.body, fg_color="transparent")
        summary.grid(row=row, column=0, padx=8, pady=(0, 8), sticky="ew")
        summary.grid_columnconfigure((0, 1, 2), weight=1, uniform="quarantine-summary")
        SummaryStatCard(summary, "Total Quarantined", count,
                        "Files currently isolated", tone="info").grid(row=0, column=0, padx=(0, 6), sticky="ew")
        SummaryStatCard(summary, "Integrity Verified", data.get("verified_count", 0),
                        "Stored content checks passed", tone="success").grid(row=0, column=1, padx=6, sticky="ew")
        SummaryStatCard(summary, "Verification Issues", data.get("verification_issues", 0),
                        "Require attention", tone="danger" if data.get("verification_issues", 0) else "neutral").grid(row=0, column=2, padx=(6, 0), sticky="ew")
        row += 1
        toolbar = ctk.CTkFrame(self.body, fg_color="transparent", height=1)
        toolbar.grid(row=row, column=0, padx=8, pady=8, sticky="ew")
        toolbar.grid_columnconfigure(0, weight=1)
        theme.Label(toolbar, text="Quarantined Files", font=theme.font("section", "bold"),
                    text_color=theme.TEXT, anchor="w").grid(row=0, column=0, sticky="ew", pady=(0, 4))
        theme.Label(toolbar, text="Files remain isolated until permanently deleted. Security history is retained.",
                    text_color=theme.TEXT_MUTED, anchor="w", justify="left").grid(row=1, column=0, sticky="ew", pady=4)
        search = ctk.CTkFrame(toolbar, fg_color="transparent", height=1)
        search.grid(row=2, column=0, sticky="ew", pady=6)
        search.grid_columnconfigure(0, weight=1)
        entry = ctk.CTkEntry(search, textvariable=self._filter_value, placeholder_text="Filter by filename, original path, or threat status",
                              font=theme.font(), height=44)
        self._filter_entry = entry
        entry.grid(row=0, column=0, sticky="ew", padx=(0, 8))
        entry.bind("<Return>", lambda event: self._apply_filter())
        apply = self._button(search, "Apply filter", self._apply_filter, width=130)
        apply.grid(row=0, column=1, sticky="e")
        theme.Label(toolbar, text=f"Select All selects all {len(items):,} matching files across every page. Applying a filter clears selection.",
                    font=theme.font("secondary"), text_color=theme.TEXT_MUTED, anchor="w", justify="left").grid(row=3, column=0, sticky="ew", pady=5)
        selections = ctk.CTkFrame(toolbar, fg_color="transparent", height=1)
        selections.grid(row=4, column=0, sticky="ew", pady=6)
        selections.grid_columnconfigure(2, weight=1)
        select = self._button(selections, "Select All", self._select_all, width=110)
        select.grid(row=0, column=0, padx=(0, 8), sticky="w")
        deselect = self._button(selections, "Deselect All", self._deselect_all, width=120)
        deselect.grid(row=0, column=1, sticky="w")
        self._select_all_button, self._deselect_all_button = select, deselect
        self._selection_label = theme.Label(selections, text="", text_color=theme.TEXT, anchor="w")
        self._selection_label.grid(row=1, column=0, columnspan=3, sticky="ew", pady=(10, 4))
        self._delete_selected_button = theme.Button(selections, text="Delete Selected (0)", command=self._delete_selected,
                                                    fg_color=theme.DANGER_DARK, hover_color=theme.DANGER,
                                                    text_color=theme.DANGER)
        self._delete_selected_button.grid(row=2, column=0, columnspan=3, sticky="w", pady=(0, 6))
        self._status_label = theme.Label(toolbar, text="", anchor="w", text_color=theme.WARNING)
        self._status_label.grid(row=5, column=0, sticky="ew")
        pager = ctk.CTkFrame(toolbar, fg_color="transparent", height=1)
        pager.grid(row=6, column=0, sticky="ew", pady=6)
        pager.grid_columnconfigure(1, weight=1)
        previous = self._button(pager, "Previous", lambda: self._change_page(-1), width=110)
        previous.grid(row=0, column=0, sticky="w")
        theme.Label(pager, text=f"Page {self._page + 1} of {max(1, (len(items) + PAGE_SIZE - 1) // PAGE_SIZE)} · {len(items):,} matching files",
                    text_color=theme.TEXT_MUTED).grid(row=0, column=1, sticky="ew", padx=8)
        next_button = self._button(pager, "Next", lambda: self._change_page(1), width=100)
        next_button.grid(row=0, column=2, sticky="e")
        self._controls.extend((entry, apply, select, deselect))
        row += 1
        visible = items[self._page * PAGE_SIZE:(self._page + 1) * PAGE_SIZE]
        if not visible:
            StateCard(self.body, "No matching files" if self._filter_text else "No files are currently isolated",
                      "Try another filter." if self._filter_text else "Quarantine will show files here when AutoGuard isolates them.").grid(row=row, column=0, padx=8, pady=8, sticky="ew")
        for item in visible:
            ref = item["item_ref"]
            card = ctk.CTkFrame(self.body, fg_color=theme.SURFACE, border_width=1, border_color=theme.BORDER, corner_radius=theme.RADIUS, height=1)
            card.grid(row=row, column=0, padx=8, pady=6, sticky="ew")
            card.grid_columnconfigure(1, weight=1)
            variable = ctk.BooleanVar(value=ref in self._selected)
            checkbox = ctk.CTkCheckBox(card, text="", width=32, height=44, variable=variable, command=lambda value=ref: self._toggle_item(value),
                                       fg_color=theme.ACCENT, hover_color=theme.ACCENT_HOVER, border_color=theme.TEXT_MUTED,
                                       checkmark_color=theme.BG)
            checkbox.grid(row=0, column=0, rowspan=3, padx=(16, 8), pady=10, sticky="w")
            checkbox._canvas.configure(takefocus=1)
            checkbox.bind("<space>", lambda event, widget=checkbox: widget.toggle())
            checkbox.bind("<Return>", lambda event, widget=checkbox: widget.toggle())
            checkbox.bind("<FocusIn>", lambda event, widget=checkbox: widget.configure(border_color=theme.TEXT))
            checkbox.bind("<FocusOut>", lambda event, widget=checkbox: widget.configure(border_color=theme.TEXT_MUTED))
            self._selection_widgets[ref] = (variable, checkbox, card)
            theme.Label(card, text=compact_text(item.get("name", "Isolated file"), 72), font=theme.font("card", "bold"), text_color=theme.TEXT,
                        anchor="w", auto_wrap=False).grid(row=0, column=1, padx=(0, 16), pady=(10, 2), sticky="ew")
            theme.Label(card, text=f"Original location: {compact_text(item.get('original_location', 'Unavailable'), 92)}", font=theme.font("secondary"), text_color=theme.TEXT_DIM,
                        anchor="w", auto_wrap=False).grid(row=1, column=1, padx=(0, 16), pady=2, sticky="ew")
            theme.Label(card, text=f"Contained {item.get('contained', 'time unavailable')}", font=theme.font("secondary"), text_color=theme.TEXT_MUTED,
                        anchor="w").grid(row=2, column=1, padx=(0, 16), pady=(2, 10), sticky="ew")
            StatusBadge(card, item.get("threat_status", "Threat recorded"), item.get("threat_status_key", "idle")).grid(row=0, column=2, rowspan=3, padx=8, sticky="e")
            actions = ctk.CTkFrame(card, fg_color="transparent", height=1)
            actions.grid(row=0, column=3, rowspan=3, padx=(8, 14), pady=8, sticky="e")
            view = self._button(actions, text="View", command=lambda value=ref: self.controller.open_quarantine_details(value), width=90)
            view.grid(row=0, column=0, padx=(0, 8))
            delete = theme.Button(actions, text="Delete", command=lambda value=ref: self._confirm_delete((value,)), fg_color=theme.DANGER_DARK,
                                  hover_color=theme.DANGER, text_color=theme.DANGER, width=90)
            delete.grid(row=0, column=1)
            self._controls.extend((view, delete))
            row += 1
        self._pager_buttons = (previous, next_button)
        self._update_selection()
        self.after_idle(lambda: self.body._parent_canvas.yview_moveto(position) if self._detail_ref is None else None)

    def _render_details(self, data):
        self._force_render = False
        self.clear_body()
        row = self._notice_widget(0)
        ref = data.get("item_ref")
        QuarantineDetailsView(self.body, dict(data, busy=self._batch_busy), on_back=self.controller.close_quarantine_details,
                              on_verify=lambda: self.controller.verify_quarantine(ref),
                              on_delete=lambda: self._confirm_delete((ref,))).grid(row=row, column=0, sticky="ew")

    def _delete_selected(self):
        if self._selected:
            self._confirm_delete(tuple(sorted(self._selected)))

    def _confirm_delete(self, refs):
        if self._batch_busy or not refs:
            return
        if self._confirmation is not None and self._confirmation.winfo_exists():
            self._confirmation.lift()
            return
        snapshot = tuple(refs)
        self._confirmation = ConfirmDialog(
            self, "Permanently Delete Quarantined Files?",
            f"You are about to permanently delete {len(snapshot)} quarantined {'file' if len(snapshot) == 1 else 'files'}. "
            "This action cannot be undone. The files will be removed from quarantine storage.\n\n"
            "Original file locations are not deleted. Incident and security history will be retained.",
            confirm_text="Delete Permanently", danger=True,
            on_confirm=lambda: self._start_delete(snapshot),
        )

    def _start_delete(self, refs):
        self._confirmation = None
        if self._batch_busy:
            return
        self._batch_busy = True
        self._discard_read = self._loading
        self._cancel_watchdog()
        if self._detail_ref and self._detail_data:
            self._render_details(self._detail_data)
        elif self._selection_label is not None:
            self._update_selection()
        try:
            accepted = self.controller.delete_quarantine_many(refs)
            if not accepted:
                raise RuntimeError("Another quarantine deletion is already running.")
        except Exception as error:
            self._batch_busy = False
            self._notice = {"title": "Operation failed", "message": str(error), "tone": "error"}
            if self._detail_ref and self._detail_data:
                self._render_details(self._detail_data)
            elif self._list_data:
                self._render_list(self._list_data)
