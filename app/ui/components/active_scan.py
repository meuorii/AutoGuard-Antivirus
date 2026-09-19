"""Focused active-scan presentation for AutoGuard UX Refresh Phase 4.

This component is presentation-only. It receives progress already produced by
scanner workers through the UI controller/message bus. It never traverses,
hashes, detects, quarantines, or touches scan-history persistence directly.
"""
from __future__ import annotations

import customtkinter as ctk

from app.ui import theme


_SCAN_NAMES = {
    "manual": "Custom Scan",
    "quick": "Quick Scan",
    "full": "Full Scan",
    "startup": "Startup Scan",
    "startup_quick": "Startup Quick Scan",
    "scheduled": "Scheduled Scan",
    "scheduled_quick": "Scheduled Quick Scan",
    "scheduled_full": "Scheduled Full Scan",
    "usb": "USB Scan",
    "real_time": "Real-Time Scan",
}

_SCAN_MESSAGES = {
    "manual": "Checking the selected file or folder...",
    "quick": "Checking common places where new files appear...",
    "full": "Checking your computer for threats. This may take a while...",
    "startup": "Checking common locations for threats...",
    "startup_quick": "Checking common locations automatically after startup...",
    "scheduled": "Running a scheduled security check...",
    "scheduled_quick": "Running the scheduled Quick Scan...",
    "scheduled_full": "Running the scheduled Full Scan...",
    "usb": "Checking the removable drive for threats...",
    "real_time": "Checking a new or changed file...",
}


class ActiveScanPanel(ctk.CTkFrame):
    """Responsive active-scan view with optional advanced counters."""

    def __init__(self, master, *, on_stop, **kwargs):
        super().__init__(
            master,
            fg_color="transparent",
            corner_radius=0,
            **kwargs,
        )
        self.grid_columnconfigure(0, weight=1)
        self._scan_type = "manual"
        self._details_open = False
        self._discovered = 0
        self._processed = 0
        self._counts = {
            "scanned": 0,
            "skipped": 0,
            "suspicious": 0,
            "dangerous": 0,
            "errors": 0,
        }
        self._on_stop = on_stop

        header = ctk.CTkFrame(self, fg_color="transparent")
        header.grid(row=0, column=0, sticky="ew")
        header.grid_columnconfigure(0, weight=1)
        self.scan_type_label = ctk.CTkLabel(
            header,
            text="Quick Scan",
            text_color=theme.TEXT,
            font=(theme.FONT, 22, "bold"),
            anchor="w",
        )
        self.scan_type_label.grid(row=0, column=0, sticky="w")
        self.state_badge = ctk.CTkLabel(
            header,
            text="SCANNING",
            text_color=theme.ACCENT,
            fg_color=theme.ACCENT_DARK,
            font=(theme.FONT, 9, "bold"),
            corner_radius=theme.RADIUS_SMALL,
            padx=10,
            pady=4,
        )
        self.state_badge.grid(row=0, column=1, padx=(12, 0), sticky="e")

        self.message_label = ctk.CTkLabel(
            self,
            text="Checking your files...",
            text_color=theme.TEXT_MUTED,
            font=(theme.FONT, 11),
            anchor="w",
        )
        self.message_label.grid(row=1, column=0, pady=(4, 18), sticky="ew")

        progress_card = ctk.CTkFrame(
            self,
            fg_color=theme.SURFACE,
            border_width=1,
            border_color=theme.BORDER,
            corner_radius=theme.RADIUS,
        )
        progress_card.grid(row=2, column=0, sticky="ew")
        progress_card.grid_columnconfigure(0, weight=1)

        progress_head = ctk.CTkFrame(progress_card, fg_color="transparent")
        progress_head.grid(row=0, column=0, padx=18, pady=(18, 8), sticky="ew")
        progress_head.grid_columnconfigure(0, weight=1)
        ctk.CTkLabel(
            progress_head,
            text="Scan progress",
            text_color=theme.TEXT,
            font=(theme.FONT, 12, "bold"),
            anchor="w",
        ).grid(row=0, column=0, sticky="w")
        self.percent_label = ctk.CTkLabel(
            progress_head,
            text="Starting...",
            text_color=theme.ACCENT,
            font=(theme.FONT, 11, "bold"),
            anchor="e",
        )
        self.percent_label.grid(row=0, column=1, sticky="e")

        self.progress = ctk.CTkProgressBar(
            progress_card,
            mode="indeterminate",
            progress_color=theme.ACCENT,
            fg_color=theme.SURFACE_ALT,
            height=9,
            corner_radius=5,
        )
        self.progress.grid(row=1, column=0, padx=18, sticky="ew")
        self.progress.set(0)

        metrics = ctk.CTkFrame(progress_card, fg_color="transparent")
        metrics.grid(row=2, column=0, padx=18, pady=(18, 14), sticky="ew")
        metrics.grid_columnconfigure((0, 1), weight=1)
        self.files_checked_value = ctk.CTkLabel(
            metrics,
            text="0",
            text_color=theme.TEXT,
            font=(theme.FONT, 28, "bold"),
            anchor="w",
        )
        self.files_checked_value.grid(row=0, column=0, sticky="w")
        self.threats_value = ctk.CTkLabel(
            metrics,
            text="0",
            text_color=theme.TEXT,
            font=(theme.FONT, 28, "bold"),
            anchor="w",
        )
        self.threats_value.grid(row=0, column=1, sticky="w")
        ctk.CTkLabel(
            metrics,
            text="Files checked",
            text_color=theme.TEXT_MUTED,
            font=(theme.FONT, 10),
            anchor="w",
        ).grid(row=1, column=0, sticky="w")
        ctk.CTkLabel(
            metrics,
            text="Threats found",
            text_color=theme.TEXT_MUTED,
            font=(theme.FONT, 10),
            anchor="w",
        ).grid(row=1, column=1, sticky="w")

        current = ctk.CTkFrame(progress_card, fg_color=theme.SURFACE_ALT, corner_radius=theme.RADIUS_SMALL)
        current.grid(row=3, column=0, padx=18, pady=(0, 16), sticky="ew")
        current.grid_columnconfigure(0, weight=1)
        ctk.CTkLabel(
            current,
            text="Currently checking",
            text_color=theme.TEXT_DIM,
            font=(theme.FONT, 9, "bold"),
            anchor="w",
        ).grid(row=0, column=0, padx=12, pady=(9, 2), sticky="ew")
        self.current_path_label = ctk.CTkLabel(
            current,
            text="Preparing scan...",
            text_color=theme.TEXT_MUTED,
            font=(theme.FONT, 10),
            anchor="w",
            justify="left",
            wraplength=760,
        )
        self.current_path_label.grid(row=1, column=0, padx=12, pady=(0, 10), sticky="ew")

        controls = ctk.CTkFrame(self, fg_color="transparent")
        controls.grid(row=3, column=0, pady=(12, 0), sticky="ew")
        controls.grid_columnconfigure(0, weight=1)
        self.details_button = ctk.CTkButton(
            controls,
            text="More details  ▾",
            command=self._toggle_details,
            width=120,
            height=32,
            fg_color="transparent",
            hover_color=theme.SURFACE_HOVER,
            border_width=1,
            border_color=theme.BORDER,
            text_color=theme.TEXT_MUTED,
            font=(theme.FONT, 10),
            corner_radius=theme.RADIUS_SMALL,
        )
        self.details_button.grid(row=0, column=0, sticky="w")
        self.stop_button = ctk.CTkButton(
            controls,
            text="Stop Scan",
            command=self._request_stop,
            width=110,
            height=32,
            fg_color=theme.DANGER_DARK,
            hover_color=theme.SURFACE_HOVER,
            border_width=1,
            border_color=theme.DANGER,
            text_color=theme.DANGER,
            font=(theme.FONT, 10, "bold"),
            corner_radius=theme.RADIUS_SMALL,
        )
        self.stop_button.grid(row=0, column=1, sticky="e")

        self.details_frame = ctk.CTkFrame(
            self,
            fg_color=theme.SURFACE,
            border_width=1,
            border_color=theme.BORDER,
            corner_radius=theme.RADIUS,
        )
        self.details_frame.grid_columnconfigure((0, 1, 2), weight=1)
        self.detail_values: dict[str, ctk.CTkLabel] = {}
        details = (
            ("discovered", "Discovered"),
            ("processed", "Processed"),
            ("skipped", "Skipped"),
            ("errors", "Errors"),
            ("suspicious", "Suspicious"),
            ("dangerous", "Dangerous"),
        )
        for index, (key, label) in enumerate(details):
            row = (index // 3) * 2
            column = index % 3
            value = ctk.CTkLabel(
                self.details_frame,
                text="0",
                text_color=theme.TEXT,
                font=(theme.FONT, 14, "bold"),
                anchor="w",
            )
            value.grid(row=row, column=column, padx=14, pady=(12, 0), sticky="ew")
            ctk.CTkLabel(
                self.details_frame,
                text=label,
                text_color=theme.TEXT_MUTED,
                font=(theme.FONT, 9),
                anchor="w",
            ).grid(row=row + 1, column=column, padx=14, pady=(0, 12), sticky="ew")
            self.detail_values[key] = value

        self.bind("<Configure>", self._resize_for_width)

    def start(self, scan_type: str, target: str = "", *, stoppable: bool = True) -> None:
        self._scan_type = scan_type or "manual"
        self._discovered = 0
        self._processed = 0
        self._counts = {key: 0 for key in self._counts}
        self.scan_type_label.configure(text=_SCAN_NAMES.get(self._scan_type, self._friendly_type()))
        self.message_label.configure(text=_SCAN_MESSAGES.get(self._scan_type, "Checking your files for threats..."))
        self.state_badge.configure(text="SCANNING")
        self.percent_label.configure(text="Scanning...")
        self.progress.stop()
        self.progress.configure(mode="indeterminate")
        self.progress.start()
        self.files_checked_value.configure(text="0")
        self.threats_value.configure(text="0")
        self.current_path_label.configure(text=target or "Preparing scan...")
        if stoppable:
            self.stop_button.grid()
            self.stop_button.configure(text="Stop Scan", state="normal")
        else:
            self.stop_button.grid_remove()
        self._refresh_details()

    def update_discovery(self, discovered: int, processed: int, current_path: str = "") -> None:
        self._discovered = max(self._discovered, int(discovered), int(processed))
        self._processed = max(self._processed, int(processed))
        if current_path:
            self.current_path_label.configure(text=current_path)
        self._paint_progress()
        self._refresh_details()

    def update_progress(
        self,
        *,
        processed: int,
        discovered: int,
        counts: dict[str, int],
        current_path: str = "",
    ) -> None:
        self._processed = max(0, int(processed))
        self._discovered = max(self._processed, int(discovered))
        self._counts.update({key: int(value) for key, value in counts.items() if key in self._counts})
        self.files_checked_value.configure(text=f"{self._counts['scanned']:,}")
        # LOW_CONFIDENCE is suspicious evidence, not a confirmed threat.
        self.threats_value.configure(text=f"{self._counts['dangerous']:,}")
        if current_path:
            self.current_path_label.configure(text=current_path)
        self._paint_progress()
        self._refresh_details()

    def end(self) -> None:
        self.progress.stop()

    def stopping(self) -> None:
        self.state_badge.configure(text="STOPPING")
        self.message_label.configure(text="Stopping safely after the current file check...")
        self.stop_button.configure(text="Stopping...", state="disabled")

    def finishing(self) -> None:
        self.progress.stop()
        self.state_badge.configure(text="FINISHING")
        self.message_label.configure(text="Preparing your scan results...")
        self.percent_label.configure(text="Finishing...")
        self.stop_button.configure(state="disabled")

    def _paint_progress(self) -> None:
        # Single-pass discovery intentionally does not pre-count the whole tree,
        # so discovered/processed is not a trustworthy total percentage. Keep
        # the primary progress indicator indeterminate and expose those counters
        # only under More details.
        self.percent_label.configure(text="Scanning...")

    def _refresh_details(self) -> None:
        values = {
            "discovered": self._discovered,
            "processed": self._processed,
            "skipped": self._counts["skipped"],
            "errors": self._counts["errors"],
            "suspicious": self._counts["suspicious"],
            "dangerous": self._counts["dangerous"],
        }
        for key, value in values.items():
            self.detail_values[key].configure(text=f"{value:,}")

    def _resize_for_width(self, event) -> None:
        width = max(280, int(getattr(event, "width", 760)) - 80)
        self.current_path_label.configure(wraplength=width)

    def _toggle_details(self) -> None:
        self._details_open = not self._details_open
        if self._details_open:
            self.details_frame.grid(row=4, column=0, pady=(12, 0), sticky="ew")
            self.details_button.configure(text="Hide details  ▴")
        else:
            self.details_frame.grid_remove()
            self.details_button.configure(text="More details  ▾")

    def _request_stop(self) -> None:
        self.stopping()
        self._on_stop()

    def _friendly_type(self) -> str:
        return self._scan_type.replace("_", " ").title()