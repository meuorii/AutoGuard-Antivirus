"""Threats list and selected Threat Details host for UX Refresh Phase 8.

Both list and detail views consume presentation read models from
``AutoGuardUIController`` and never query security tables directly.
"""
from __future__ import annotations

import customtkinter as ctk

from app.ui import theme
from app.ui.base_page import BasePage
from app.ui.components import ConfirmDialog, SectionHeader, StateCard, StatusBadge, SummaryStatCard, compact_text
from app.ui.threat_details_page import ThreatDetailsView


_SECTION_ORDER = ("Needs attention", "Contained", "Resolved")

_STATUS_STYLE = {
    "attention": (theme.WARNING, theme.WARNING_DARK),
    "reviewing": (theme.WARNING, theme.WARNING_DARK),
    "contained": (theme.SUCCESS, theme.SUCCESS_DARK),
    "reappeared": (theme.WARNING, theme.WARNING_DARK),
    "restored": (theme.INFO, theme.INFO_DARK),
    "resolved": (theme.TEXT_MUTED, theme.SURFACE_ALT),
}


class ThreatsPage(BasePage):
    title = "Threats"
    subtitle = "Review, manage, and resolve detected security threats."

    def __init__(self, master, controller, **kwargs):
        super().__init__(master, controller, **kwargs)
        self._loading = False
        self._detail_ref = None
        self._detail_data: dict | None = None
        self._list_data: tuple[dict, ...] | None = None
        self._selected_refs: set[str] = set()
        self._bulk_busy = False
        self._bulk_result = None
        self._render_loading()

    def on_show(self) -> None:
        selected = self.controller.selected_threat_ref
        if selected:
            self._detail_ref = selected
            self._loading = True
            self._render_details_loading()
            self.controller.load_threat_details(selected)
            return
        self._detail_ref = None
        self._loading = True
        self._render_loading()
        self.controller.load_threats()

    def refresh_from_state(self, reason: str = "") -> None:
        if self._detail_ref:
            self.controller.load_threat_details(self._detail_ref)
        else:
            self.controller.load_threats()

    def handle_message(self, message) -> None:
        if message.kind == "threat_details_requested":
            requested_ref = str(message.payload.get("threat_ref") or "").strip()
            if requested_ref:
                self._detail_ref = requested_ref
                self._detail_data = None
                self._loading = True
                self._render_details_loading()
                # Safe if on_show() already requested this read: the controller
                # deduplicates active task names through _submit_once().
                self.controller.load_threat_details(requested_ref)
        elif message.kind == "threat_details_data":
            if self._detail_ref:
                result = dict(message.payload.get("result", {}))
                was_loading = self._loading
                self._loading = False
                if was_loading or result != self._detail_data:
                    self._detail_data = result
                    self._render_details(result)
        elif message.kind == "threat_resolved":
            if self._detail_ref and message.payload.get("result", {}).get("threat_ref") == self._detail_ref:
                self.controller.close_threat_details()
        elif message.kind == "threats_bulk_completed":
            result = message.payload.get("result", {})
            self._bulk_busy = False
            self._selected_refs.difference_update(result.get("processed", ()))
            self._list_data = None
            self.controller.load_threats()
            total = result.get("total_selected", 0)
            processed = len(result.get("processed", ()))
            skipped = result.get("skipped", ())
            failed = result.get("failed", ())
            reasons = "; ".join(f"{item['id'][:8]}: {item['reason']}" for item in (*skipped, *failed))
            self._show_bulk_result(total, processed, len(skipped), len(failed), reasons)
            self._render(self._list_data or ())
        elif message.kind == "task_failed" and message.payload.get("task") == "bulk-threat-action":
            self._bulk_busy = False
            self._show_bulk_result(len(self._selected_refs), 0, 0, 1, str(message.payload.get("error", "Operation failed.")))
            if self._list_data is not None: self._render(self._list_data)
        elif message.kind == "threat_details_closed":
            self._detail_ref = None
            self._detail_data = None
            self._loading = True
            self._render_loading()
            self.controller.load_threats()
        elif message.kind == "threats_data" and not self._detail_ref:
            rows = tuple(message.payload.get("result", ()))
            was_loading = self._loading
            self._loading = False
            if was_loading or self._list_data is None or rows != self._list_data:
                self._list_data = rows
                self._render(rows)
        elif message.kind == "task_failed":
            task = str(message.payload.get("task", ""))
            error = str(message.payload.get("error", "Unable to load threat data."))
            if task == "load-threats" and not self._detail_ref:
                self._loading = False
                self._render_load_error(error, details=False)
            elif task.startswith("load-threat-details:") and self._detail_ref:
                self._loading = False
                self._render_load_error(error, details=True)
        elif message.kind in {"incident_verified", "quarantine_deleted", "recovery_completed"}:
            if self._detail_ref:
                self.controller.load_threat_details(self._detail_ref)
            else:
                self.controller.load_threats()

    def _render_load_error(self, error: str, *, details: bool) -> None:
        self.clear_body()
        self.body.grid_columnconfigure(0, weight=1)
        card = ctk.CTkFrame(
            self.body, fg_color=theme.SURFACE, border_width=1,
            border_color=theme.BORDER, corner_radius=theme.RADIUS,
        )
        card.grid(row=0, column=0, padx=8, pady=8, sticky="ew")
        card.grid_columnconfigure(0, weight=1)
        theme.Label(
            card, text="Threat data could not be loaded",
            font=theme.font("card", "bold", theme.FONT), text_color=theme.TEXT, anchor="w",
        ).grid(row=0, column=0, padx=16, pady=(15, 4), sticky="ew")
        theme.Label(
            card, text="AutoGuard is still protecting your computer. Try loading this view again.",
            font=theme.font("body", "normal", theme.FONT), text_color=theme.TEXT_MUTED, anchor="w",
            justify="left", wraplength=760,
        ).grid(row=1, column=0, padx=16, sticky="ew")
        theme.Label(
            card, text=error, font=theme.font("secondary", "normal", theme.FONT), text_color=theme.TEXT_DIM,
            anchor="w", justify="left", wraplength=760,
        ).grid(row=2, column=0, padx=16, pady=(6, 10), sticky="ew")
        retry = (
            (lambda: self.controller.load_threat_details(self._detail_ref))
            if details else self.controller.load_threats
        )
        theme.Button(
            card, text="Retry", width=90, height=30, command=retry,
            fg_color=theme.ACCENT, hover_color=theme.ACCENT_HOVER,
            text_color=theme.BG,
        ).grid(row=3, column=0, padx=16, pady=(0, 15), sticky="w")

    def _render_details_loading(self) -> None:
        self.clear_body()
        self.body.grid_columnconfigure(0, weight=1)
        StateCard(self.body, "Loading threat details…", "AutoGuard is reading the recorded threat evidence.").grid(
            row=0, column=0, padx=8, pady=8, sticky="ew"
        )

    def _render_details(self, data) -> None:
        self.clear_body()
        self.body.grid_columnconfigure(0, weight=1)
        ThreatDetailsView(
            self.body,
            data or {},
            on_back=self.controller.close_threat_details,
            on_resolve=lambda: self._confirm_resolve(self._detail_ref),
        ).grid(row=0, column=0, sticky="ew")

    def _confirm_resolve(self, threat_ref) -> None:
        if not threat_ref:
            return
        ConfirmDialog(
            self.winfo_toplevel(),
            "Mark threat as resolved?",
            "This closes the incident and moves it to Resolved. Its history is kept. "
            "If the same content is detected again, AutoGuard will open a new incident.",
            confirm_text="Mark as resolved",
            on_confirm=lambda: self.controller.resolve_threat(threat_ref),
        )

    def _render_loading(self) -> None:
        self.clear_body()
        self.body.grid_columnconfigure(0, weight=1)
        StateCard(self.body, "Loading threats…", "AutoGuard is reading recorded threat activity.").grid(
            row=0, column=0, padx=8, pady=8, sticky="ew"
        )

    def _render(self, rows) -> None:
        self.clear_body()
        self.body.grid_columnconfigure(0, weight=1)
        grouped = {name: [] for name in _SECTION_ORDER}
        for row in rows:
            section = row.get("section")
            if section in grouped:
                grouped[section].append(row)

        summary = ctk.CTkFrame(self.body, fg_color="transparent")
        summary.grid(row=0, column=0, padx=8, pady=(0, 8), sticky="ew")
        summary.grid_columnconfigure((0, 1, 2), weight=1, uniform="threat-summary")
        SummaryStatCard(summary, "Active Threats", len(grouped["Needs attention"]),
                        "Require review or action", tone="warning").grid(row=0, column=0, padx=(0, 6), sticky="ew")
        SummaryStatCard(summary, "Contained Threats", len(grouped["Contained"]),
                        "Isolated by AutoGuard", tone="success").grid(row=0, column=1, padx=6, sticky="ew")
        SummaryStatCard(summary, "Resolved Threats", len(grouped["Resolved"]),
                        "Historical incidents retained").grid(row=0, column=2, padx=(6, 0), sticky="ew")

        self._render_bulk_toolbar(rows, row=1)

        if not grouped["Needs attention"]:
            self._empty_attention(2)
            next_row = 3
        else:
            next_row = self._render_section(2, "Needs attention", grouped["Needs attention"])

        for section in ("Contained", "Resolved"):
            items = grouped[section]
            if items:
                next_row = self._render_section(next_row, section, items)

        if not any(grouped.values()):
            self._no_history(next_row)

    def _empty_attention(self, row: int) -> None:
        StateCard(
            self.body,
            "No active threats",
            "Nothing currently needs your review. AutoGuard will continue monitoring supported locations.",
        ).grid(row=row, column=0, padx=8, pady=(4, 12), sticky="ew")

    def _no_history(self, row: int) -> None:
        theme.Label(
            self.body,
            text="No contained or resolved threats have been recorded yet.",
            font=theme.font("body", "normal", theme.FONT),
            text_color=theme.TEXT_DIM,
            anchor="w",
        ).grid(row=row, column=0, padx=12, pady=(0, 18), sticky="w")

    def _render_section(self, row: int, title: str, items) -> int:
        SectionHeader(self.body, title, count=len(items)).grid(
            row=row, column=0, padx=8, pady=(12, 5), sticky="ew"
        )
        row += 1
        for item in items:
            self._threat_card(row, item)
            row += 1
        return row

    def _threat_card(self, row: int, item) -> None:
        card = ctk.CTkFrame(
            self.body,
            fg_color=theme.SURFACE,
            border_width=1,
            border_color=theme.BORDER,
            corner_radius=theme.RADIUS,
        )
        card.grid(row=row, column=0, padx=8, pady=5, sticky="ew")
        card.grid_columnconfigure(1, weight=1)
        threat_ref = item.get("threat_ref")
        selectable = bool(threat_ref)
        if selectable:
            variable = ctk.BooleanVar(value=threat_ref in self._selected_refs)
            ctk.CTkCheckBox(card, text="", width=32, variable=variable,
                            command=lambda ref=threat_ref, value=variable: self._toggle_threat(ref, value.get()),
                            fg_color=theme.ACCENT, hover_color=theme.ACCENT_HOVER,
                            border_color=theme.TEXT_MUTED, checkmark_color=theme.BG).grid(
                                row=0, column=0, rowspan=3, padx=(14, 2), pady=12, sticky="nw")

        top = ctk.CTkFrame(card, fg_color="transparent")
        top.grid(row=0, column=1, padx=16, pady=(14, 3), sticky="ew")
        top.grid_columnconfigure(0, weight=1)
        theme.Label(
            top,
            text=compact_text(item.get("name", "Threat"), 72),
            font=theme.font("card", "bold", theme.FONT),
            text_color=theme.TEXT,
            anchor="w",
        ).grid(row=0, column=0, sticky="ew")
        StatusBadge(
            top,
            item.get("status", "Needs attention"),
            item.get("status_key", "idle"),
        ).grid(row=0, column=1, padx=(10, 0), sticky="e")

        theme.Label(
            card,
            text=compact_text(item.get("location", "Location unavailable"), 92),
            font=theme.font("body", "normal", theme.FONT),
            text_color=theme.TEXT_MUTED,
            anchor="w",
            auto_wrap=False,
        ).grid(row=1, column=1, padx=16, sticky="ew")

        meta_parts = [f"Detected {item.get('detected', 'time unavailable')}"]
        copies = int(item.get("matching_copies", 0) or 0)
        if copies:
            meta_parts.append(f"{copies:,} matching {'copy' if copies == 1 else 'copies'} found")
        theme.Label(
            card,
            text="  •  ".join(meta_parts),
            font=theme.font("body", "normal", theme.FONT),
            text_color=theme.TEXT_DIM,
            anchor="w",
        ).grid(row=2, column=1, padx=16, pady=(6, 14), sticky="w")

        theme.Button(
            card,
            text=item.get("action", "View details"),
            width=98,
            height=30,
            fg_color=theme.SURFACE_ALT,
            hover_color=theme.SURFACE_HOVER,
            text_color=theme.TEXT,
            border_width=1,
            border_color=theme.BORDER,
            command=lambda ref=threat_ref: self.controller.open_threat_details(ref),
        ).grid(row=2, column=1, padx=16, pady=(6, 14), sticky="e")

    def _render_bulk_toolbar(self, rows, *, row=0) -> None:
        refs = {str(row.get("threat_ref")) for row in rows if row.get("threat_ref")}
        selected_count = len(self._selected_refs)
        toolbar = ctk.CTkFrame(self.body, fg_color=theme.SURFACE, border_width=1,
                               border_color=theme.BORDER, corner_radius=theme.RADIUS)
        toolbar.grid(row=row, column=0, padx=8, pady=(0, 8), sticky="ew")
        theme.Label(toolbar, text=f"{selected_count} selected", text_color=theme.TEXT,
                    font=theme.font("body", "bold", theme.FONT)).grid(row=0, column=0, padx=12, pady=9, sticky="w")
        theme.Button(toolbar, text="Select All", width=90, height=28,
                     command=lambda: self._set_selection(refs)).grid(row=0, column=1, padx=4, pady=7)
        theme.Button(toolbar, text="Deselect All", width=95, height=28,
                     command=lambda: self._set_selection(set())).grid(row=0, column=2, padx=4, pady=7)
        if selected_count:
            theme.Button(toolbar, text="Mark as Resolved", width=130, height=28,
                         command=self._confirm_bulk_resolve, fg_color=theme.ACCENT,
                         hover_color=theme.ACCENT_HOVER, text_color=theme.BG).grid(row=0, column=3, padx=4, pady=7)
            theme.Button(toolbar, text="Delete Selected", width=125, height=28,
                         command=self._confirm_bulk_archive, fg_color=theme.DANGER_DARK,
                         hover_color=theme.DANGER, text_color=theme.DANGER).grid(row=0, column=4, padx=(4, 12), pady=7)
        if self._bulk_busy:
            theme.Label(toolbar, text="Processing selected threats…", text_color=theme.TEXT_MUTED).grid(row=1, column=0, columnspan=5, padx=12, pady=(0, 8), sticky="w")
        if self._bulk_result:
            total, processed, skipped, failed, reasons = self._bulk_result
            summary = f"Bulk result: {total} selected · {processed} processed · {skipped} skipped · {failed} failed"
            if reasons: summary += f"\n{reasons}"
            theme.Label(toolbar, text=summary, text_color=theme.WARNING if failed or skipped else theme.SUCCESS,
                        justify="left", anchor="w", wraplength=800).grid(row=2 if self._bulk_busy else 1, column=0, columnspan=5, padx=12, pady=(0, 8), sticky="w")

    def _toggle_threat(self, ref, checked):
        if checked: self._selected_refs.add(ref)
        else: self._selected_refs.discard(ref)
        if self._list_data is not None: self._render(self._list_data)

    def _set_selection(self, refs):
        self._selected_refs = set(refs)
        if self._list_data is not None: self._render(self._list_data)

    def _confirm_bulk_resolve(self):
        refs = tuple(sorted(self._selected_refs))
        if not refs or self._bulk_busy: return
        ConfirmDialog(self.winfo_toplevel(), "Mark selected threats as resolved?",
                      f"Mark {len(refs)} selected threats as resolved? Only incidents that satisfy the existing resolution requirements will be updated.",
                      confirm_text="Mark as resolved", on_confirm=lambda: self._start_bulk(refs, "resolve"))

    def _confirm_bulk_archive(self):
        refs = tuple(sorted(self._selected_refs))
        if not refs or self._bulk_busy: return
        ConfirmDialog(self.winfo_toplevel(), "Remove selected threat entries?",
                      "Remove the selected eligible threat entries from the active list? Historical security records will be retained.",
                      confirm_text="Remove from list", danger=True,
                      on_confirm=lambda: self._start_bulk(refs, "archive"))

    def _start_bulk(self, refs, action):
        if self._bulk_busy: return
        self._bulk_busy = True
        self._render(self._list_data or ())
        if not self.controller.bulk_threat_action(refs, action):
            self._bulk_busy = False

    def _show_bulk_result(self, total, processed, skipped, failed, reasons):
        self._bulk_result = (total, processed, skipped, failed, reasons)
