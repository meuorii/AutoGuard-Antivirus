"""Unified human-readable Activity feed for AutoGuard UX Refresh Phase 10."""
from __future__ import annotations

import customtkinter as ctk

from app.ui import theme
from app.ui.base_page import BasePage
from app.ui.components import StateCard


_FILTERS = ("All", "Scans", "Threats", "Protection")
_TONE_COLORS = {
    "success": theme.SUCCESS,
    "warning": theme.WARNING,
    "danger": theme.DANGER,
    "info": theme.INFO,
}


class ActivityPage(BasePage):
    title = "Activity"
    subtitle = "Recent scans, threat handling, and recorded protection activity"

    def __init__(self, master, controller, **kwargs):
        super().__init__(master, controller, **kwargs)
        self._events: list[dict] = []
        self._filter = "All"
        self._loading = True
        self._render()

    def on_show(self) -> None:
        self.refresh()

    def handle_message(self, message) -> None:
        if message.kind == "activity_data":
            events = list(message.payload.get("result", ()))
            was_loading = self._loading
            self._loading = False
            if was_loading or events != self._events:
                self._events = events
                self._render()
        elif message.kind == "task_failed" and message.payload.get("task") == "load-activity":
            self._loading = False
            self._render(error=message.payload.get("error", "Activity could not be loaded."))
        elif message.kind in {
            "scan_result_ready", "scan_stopped", "incident_verified",
            "quarantine_deleted", "recovery_completed",
        }:
            # Persisted evidence changed. Refresh only when this page next becomes
            # visible or when the user chooses Refresh; no expensive polling loop.
            pass

    def refresh(self) -> None:
        self._loading = True
        self._render()
        self.controller.load_activity()

    def refresh_from_state(self, reason: str = "") -> None:
        # Passive/event synchronization keeps the current feed visible while an
        # off-thread read model refreshes; no loading flash on every update.
        self.controller.load_activity()

    def _set_filter(self, value: str) -> None:
        if value not in _FILTERS:
            return
        self._filter = value
        self._render()

    def _filtered_events(self) -> list[dict]:
        if self._filter == "All":
            return list(self._events)
        return [event for event in self._events if event.get("category") == self._filter]

    def _toolbar(self) -> None:
        bar = ctk.CTkFrame(self.body, fg_color="transparent")
        bar.grid(row=0, column=0, padx=8, pady=(2, 14), sticky="ew")
        bar.grid_columnconfigure(0, weight=1)
        segmented = ctk.CTkSegmentedButton(
            bar,
            values=list(_FILTERS),
            command=self._set_filter,
            fg_color=theme.SURFACE,
            selected_color=theme.ACCENT_DARK,
            selected_hover_color=theme.ACCENT_DARK,
            unselected_color=theme.SURFACE,
            unselected_hover_color=theme.SURFACE_HOVER,
            text_color=theme.TEXT,
            border_width=1,
            corner_radius=theme.RADIUS_SMALL,
            font=(theme.FONT, 10, "bold"),
        )
        segmented.grid(row=0, column=0, sticky="w")
        segmented.set(self._filter)
        ctk.CTkButton(
            bar,
            text="Refresh",
            width=84,
            height=30,
            fg_color=theme.SURFACE,
            hover_color=theme.SURFACE_HOVER,
            border_width=1,
            border_color=theme.BORDER,
            text_color=theme.TEXT,
            command=self.refresh,
        ).grid(row=0, column=1, sticky="e")

    def _render(self, *, error: str | None = None) -> None:
        self.clear_body()
        self.body.grid_columnconfigure(0, weight=1)
        self._toolbar()

        if self._loading:
            self._state_card("Loading activity…", "AutoGuard is reading recorded activity in the background.")
            return
        if error:
            self._state_card("Activity could not be loaded", error, tone="danger")
            return

        events = self._filtered_events()
        if not events:
            if self._filter == "Protection":
                self._state_card(
                    "No recorded protection changes",
                    "AutoGuard does not currently have timestamped protection-service state changes to show here.",
                )
            elif self._filter == "Threats":
                self._state_card(
                    "No threat activity recorded",
                    "No suspicious or confirmed threat activity is available in the current history.",
                )
            elif self._filter == "Scans":
                self._state_card(
                    "No scan activity recorded",
                    "Run a scan or let real-time protection monitor supported locations to build activity history.",
                )
            else:
                self._state_card(
                    "No activity has been recorded yet",
                    "AutoGuard will show recorded scans and security activity here as they occur.",
                )
            return

        row_index = 1
        current_group = None
        for event in events:
            group = event.get("date_group", "Earlier")
            if group != current_group:
                current_group = group
                ctk.CTkLabel(
                    self.body,
                    text=group,
                    font=(theme.FONT, 13, "bold"),
                    text_color=theme.TEXT,
                    anchor="w",
                ).grid(row=row_index, column=0, padx=10, pady=(15 if row_index > 1 else 2, 5), sticky="ew")
                row_index += 1
            self._activity_row(row_index, event)
            row_index += 1

    def _state_card(self, title: str, message: str, *, tone: str = "info") -> None:
        StateCard(self.body, title, message, tone=tone).grid(
            row=1, column=0, padx=8, pady=4, sticky="ew"
        )

    def _activity_row(self, row: int, event: dict) -> None:
        card = ctk.CTkFrame(
            self.body,
            fg_color=theme.SURFACE,
            border_width=1,
            border_color=theme.BORDER,
            corner_radius=theme.RADIUS_SMALL,
        )
        card.grid(row=row, column=0, padx=8, pady=4, sticky="ew")
        card.grid_columnconfigure(1, weight=1)

        color = _TONE_COLORS.get(event.get("tone"), theme.INFO)
        ctk.CTkLabel(
            card,
            text="●",
            font=(theme.FONT, 13, "bold"),
            text_color=color,
            width=24,
        ).grid(row=0, column=0, rowspan=2, padx=(14, 6), pady=12, sticky="n")
        ctk.CTkLabel(
            card,
            text=event.get("title", "Activity recorded"),
            font=(theme.FONT, 11, "bold"),
            text_color=theme.TEXT,
            anchor="w",
        ).grid(row=0, column=1, padx=(0, 8), pady=(11, 2), sticky="ew")
        ctk.CTkLabel(
            card,
            text=event.get("time", "Time unavailable"),
            font=(theme.FONT, 9),
            text_color=theme.TEXT_DIM,
            anchor="e",
        ).grid(row=0, column=2, padx=(8, 14), pady=(11, 2), sticky="e")

        detail = event.get("detail", "")
        if detail:
            ctk.CTkLabel(
                card,
                text=detail,
                font=(theme.FONT, 9),
                text_color=theme.TEXT_MUTED,
                anchor="w",
                justify="left",
                wraplength=760,
            ).grid(row=1, column=1, columnspan=2, padx=(0, 14), pady=(0, 11), sticky="ew")
        else:
            ctk.CTkLabel(
                card,
                text=event.get("category", "Activity"),
                font=(theme.FONT, 9),
                text_color=theme.TEXT_DIM,
                anchor="w",
            ).grid(row=1, column=1, columnspan=2, padx=(0, 14), pady=(0, 11), sticky="w")