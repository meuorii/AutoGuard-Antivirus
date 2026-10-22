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

# While a scan is running and the Activity page is visible, reload the feed
# this often (milliseconds). Set to 0 to disable live polling.
LIVE_POLL_MS = 4000
# If a load has not answered after this long, stop showing "Loading" forever
# and let the user retry.
LOAD_TIMEOUT_MS = 20000


class ActivityPage(BasePage):
    title = "Activity"
    subtitle = "Recent scans, threat handling, and recorded protection activity"

    def __init__(self, master, controller, **kwargs):
        super().__init__(master, controller, **kwargs)
        self._events: list[dict] = []
        self._filter = "All"
        self._loading = True
        self._error: str | None = None
        self._reload_pending = False
        self._watchdog_id = None
        self._render()
        if LIVE_POLL_MS > 0:
            self.after(LIVE_POLL_MS, self._poll)

    # ------------------------------------------------------------------ loading
    def on_show(self) -> None:
        # Always load right away. Activity no longer waits for a scan to finish;
        # SQLite runs in WAL mode so reads are safe while a scan is writing.
        self.refresh()

    def _scan_in_progress(self) -> bool:
        """Return whether a UI-launched or automatic scan is currently active."""
        try:
            active_tasks = self.controller.active_tasks()
            if any(
                task == "quick-scan" or task == "full-scan" or task.startswith("scan:")
                for task in active_tasks
            ):
                return True
            return self.controller.automatic_scan_progress() is not None
        except Exception:
            return False

    def _load_in_flight(self) -> bool:
        try:
            return "load-activity" in self.controller.active_tasks()
        except Exception:
            return False

    def _request_reload(self, *, pending_if_busy: bool) -> None:
        """Start a load, or remember to reload once the running one finishes.

        The controller drops load requests while one is running. Without the
        pending flag, a scan-stopped refresh that arrives during an older load
        would be lost and the page would keep stale/empty data.
        """
        if self._load_in_flight():
            if pending_if_busy:
                self._reload_pending = True
            return
        self._arm_watchdog()
        self.controller.load_activity()

    def refresh(self) -> None:
        self._error = None
        # Only show the full "Loading" card when there is nothing to display.
        # Existing events stay visible while the new data loads.
        self._loading = not self._events
        self._render()
        self._request_reload(pending_if_busy=False)

    def refresh_from_state(self, reason: str = "") -> None:
        # Event-driven sync (scan stopped/completed, etc.). No loading flash.
        self._request_reload(pending_if_busy=True)

    def _arm_watchdog(self) -> None:
        self._cancel_watchdog()
        try:
            self._watchdog_id = self.after(LOAD_TIMEOUT_MS, self._on_load_timeout)
        except Exception:
            self._watchdog_id = None

    def _cancel_watchdog(self) -> None:
        if self._watchdog_id is not None:
            try:
                self.after_cancel(self._watchdog_id)
            except Exception:
                pass
            self._watchdog_id = None

    def _on_load_timeout(self) -> None:
        self._watchdog_id = None
        if self._loading:
            self._loading = False
            self._error = "Activity is taking too long to load. Press Refresh to try again."
            self._render()

    def _poll(self) -> None:
        """Keep the feed live while a scan runs and this page is visible."""
        try:
            if (
                self.winfo_ismapped()
                and not self._loading
                and self._scan_in_progress()
            ):
                self._request_reload(pending_if_busy=False)
        except Exception:
            pass
        try:
            self.after(LIVE_POLL_MS, self._poll)
        except Exception:
            pass

    # ----------------------------------------------------------------- messages
    def handle_message(self, message) -> None:
        if message.kind == "activity_data":
            self._cancel_watchdog()
            events = list(message.payload.get("result", ()))
            needs_render = self._loading or self._error is not None or events != self._events
            self._loading = False
            self._error = None
            if needs_render:
                self._events = events
                self._render()
        elif message.kind == "task_failed" and message.payload.get("task") == "load-activity":
            self._cancel_watchdog()
            self._loading = False
            self._error = message.payload.get("error", "Activity could not be loaded.")
            self._render()
        elif message.kind == "task_finished" and message.payload.get("task") == "load-activity":
            # A reload was requested while the previous load was still running.
            if self._reload_pending:
                self._reload_pending = False
                self._request_reload(pending_if_busy=True)
        # Other lifecycle events (scan_stopped, scan_completed, ...) are routed by
        # MainWindow to refresh_from_state() when this page is visible, and
        # on_show() reloads when the page is opened later.

    # ------------------------------------------------------------------- render
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
            font=theme.font("body", "bold", theme.FONT),
            height=44,
        )
        segmented.grid(row=0, column=0, sticky="w")
        segmented.set(self._filter)
        theme.Button(
            bar,
            text="Refresh",
            width=96,
            height=34,
            font=theme.font("body", "normal", theme.FONT),
            fg_color=theme.SURFACE,
            hover_color=theme.SURFACE_HOVER,
            border_width=1,
            border_color=theme.BORDER,
            text_color=theme.TEXT,
            command=self.refresh,
        ).grid(row=0, column=1, sticky="e")

    def _render(self) -> None:
        self.clear_body()
        self.body.grid_columnconfigure(0, weight=1)
        self._toolbar()

        if self._loading and not self._events:
            self._state_card(
                "Loading activity…",
                "AutoGuard is reading recorded activity in the background.",
            )
            return

        events = self._filtered_events()

        if self._error and not self._events:
            self._state_card("Activity could not be loaded", self._error, tone="danger")
            return

        if not events:
            scanning = self._scan_in_progress()
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
                    "A scan is running. Its activity will appear here as it is saved."
                    if scanning
                    else "Run a scan or let real-time protection monitor supported locations to build activity history.",
                )
            else:
                self._state_card(
                    "No activity has been recorded yet",
                    "A scan is running. Its activity will appear here as it is saved."
                    if scanning
                    else "AutoGuard will show recorded scans and security activity here as they occur.",
                )
            return

        row_index = 1
        current_group = None
        for event in events:
            group = event.get("date_group", "Earlier")
            if group != current_group:
                current_group = group
                theme.Label(
                    self.body,
                    text=group,
                    font=theme.font("section", "bold", theme.FONT),
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
        theme.Label(
            card,
            text="●",
            font=theme.font("card", "bold", theme.FONT),
            text_color=color,
            width=28,
        ).grid(row=0, column=0, rowspan=2, padx=(14, 6), pady=12, sticky="n")
        theme.Label(
            card,
            text=event.get("title", "Activity recorded"),
            font=theme.font("card", "bold", theme.FONT),
            text_color=theme.TEXT,
            anchor="w",
        ).grid(row=0, column=1, padx=(0, 8), pady=(11, 2), sticky="ew")
        detection_number = event.get("detection_number")
        if detection_number is not None:
            theme.Label(
                card,
                text=f"DETECTION #{int(detection_number):03d}",
                font=theme.font("body", "bold", theme.FONT),
                text_color=theme.ACCENT,
                fg_color=theme.SURFACE_HOVER,
                corner_radius=theme.RADIUS_SMALL,
            ).grid(row=0, column=2, padx=(4, 6), pady=(9, 2), sticky="e", ipadx=6, ipady=2)

        theme.Label(
            card,
            text=event.get("time", "Time unavailable"),
            font=theme.font("body", "normal", theme.FONT),
            text_color=theme.TEXT_DIM,
            anchor="e",
        ).grid(row=0, column=3, padx=(6, 14), pady=(11, 2), sticky="e")

        detail = event.get("detail", "")
        if detail:
            theme.Label(
                card,
                text=detail,
                font=theme.font("body", "normal", theme.FONT),
                text_color=theme.TEXT_MUTED,
                anchor="w",
                justify="left",
                wraplength=860,
            ).grid(row=1, column=1, columnspan=3, padx=(0, 14), pady=(0, 11), sticky="ew")
        else:
            theme.Label(
                card,
                text=event.get("category", "Activity"),
                font=theme.font("body", "normal", theme.FONT),
                text_color=theme.TEXT_DIM,
                anchor="w",
            ).grid(row=1, column=1, columnspan=3, padx=(0, 14), pady=(0, 11), sticky="w")
