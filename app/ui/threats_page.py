"""Threats list and selected Threat Details host for UX Refresh Phase 8.

Both list and detail views consume presentation read models from
``AutoGuardUIController`` and never query security tables directly.
"""
from __future__ import annotations

import customtkinter as ctk

from app.ui import theme
from app.ui.base_page import BasePage
from app.ui.components import SectionHeader, StateCard, StatusBadge
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
    subtitle = "Review threats AutoGuard has observed and handled"

    def __init__(self, master, controller, **kwargs):
        super().__init__(master, controller, **kwargs)
        self._loading = False
        self._detail_ref = None
        self._detail_data: dict | None = None
        self._list_data: tuple[dict, ...] | None = None
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
            self._detail_ref = message.payload.get("threat_ref")
            if self._detail_ref:
                self._loading = True
                self._render_details_loading()
        elif message.kind == "threat_details_data":
            if self._detail_ref:
                result = dict(message.payload.get("result", {}))
                was_loading = self._loading
                self._loading = False
                if was_loading or result != self._detail_data:
                    self._detail_data = result
                    self._render_details(result)
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
        ctk.CTkLabel(
            card, text="Threat data could not be loaded",
            font=(theme.FONT, 15, "bold"), text_color=theme.TEXT, anchor="w",
        ).grid(row=0, column=0, padx=16, pady=(15, 4), sticky="ew")
        ctk.CTkLabel(
            card, text="AutoGuard is still protecting your computer. Try loading this view again.",
            font=(theme.FONT, 10), text_color=theme.TEXT_MUTED, anchor="w",
            justify="left", wraplength=760,
        ).grid(row=1, column=0, padx=16, sticky="ew")
        ctk.CTkLabel(
            card, text=error, font=(theme.FONT, 9), text_color=theme.TEXT_DIM,
            anchor="w", justify="left", wraplength=760,
        ).grid(row=2, column=0, padx=16, pady=(6, 10), sticky="ew")
        retry = (
            (lambda: self.controller.load_threat_details(self._detail_ref))
            if details else self.controller.load_threats
        )
        ctk.CTkButton(
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
        ).grid(row=0, column=0, sticky="ew")

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

        if not grouped["Needs attention"]:
            self._empty_attention(0)
            next_row = 1
        else:
            next_row = self._render_section(0, "Needs attention", grouped["Needs attention"])

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
        ctk.CTkLabel(
            self.body,
            text="No contained or resolved threats have been recorded yet.",
            font=(theme.FONT, 10),
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
        card.grid_columnconfigure(0, weight=1)

        top = ctk.CTkFrame(card, fg_color="transparent")
        top.grid(row=0, column=0, columnspan=2, padx=16, pady=(14, 3), sticky="ew")
        top.grid_columnconfigure(0, weight=1)
        ctk.CTkLabel(
            top,
            text=item.get("name", "Threat"),
            font=(theme.FONT, 14, "bold"),
            text_color=theme.TEXT,
            anchor="w",
        ).grid(row=0, column=0, sticky="ew")
        StatusBadge(
            top,
            item.get("status", "Needs attention"),
            item.get("status_key", "idle"),
        ).grid(row=0, column=1, padx=(10, 0), sticky="e")

        ctk.CTkLabel(
            card,
            text=item.get("location", "Location unavailable"),
            font=(theme.FONT, 10),
            text_color=theme.TEXT_MUTED,
            anchor="w",
            justify="left",
            wraplength=760,
        ).grid(row=1, column=0, columnspan=2, padx=16, sticky="ew")

        meta_parts = [f"Detected {item.get('detected', 'time unavailable')}"]
        copies = int(item.get("matching_copies", 0) or 0)
        if copies:
            meta_parts.append(f"{copies:,} matching {'copy' if copies == 1 else 'copies'} found")
        ctk.CTkLabel(
            card,
            text="  •  ".join(meta_parts),
            font=(theme.FONT, 10),
            text_color=theme.TEXT_DIM,
            anchor="w",
        ).grid(row=2, column=0, padx=16, pady=(6, 14), sticky="w")

        threat_ref = item.get("threat_ref")
        ctk.CTkButton(
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