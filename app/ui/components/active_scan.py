"""Focused active-scan presentation for AutoGuard UX Refresh Phase 4.

This component is presentation-only. It receives progress already produced by
scanner workers through the UI controller/message bus. It never traverses,
hashes, detects, quarantines, or touches scan-history persistence directly.
"""
from __future__ import annotations

import time
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
    "manual": "Checking the selected files and folders...",
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
            "safe": 0,
            "skipped": 0,
            "suspicious": 0,
            "dangerous": 0,
            "errors": 0,
        }
        self._started_at = None
        self._clock_after = None
        self._phase = "discovering"
        self._total = None
        self._eta_seconds = None
        self._bytes_processed = 0
        self._elapsed_snapshot = None
        self._elapsed_snapshot_at = None
        self._on_stop = on_stop

        header = ctk.CTkFrame(self, fg_color="transparent")
        header.grid(row=0, column=0, sticky="ew")
        header.grid_columnconfigure(0, weight=1)
        self.scan_type_label = theme.Label(
            header,
            text="Quick Scan",
            text_color=theme.TEXT,
            font=theme.font("page", "bold", theme.FONT),
            anchor="w",
        )
        self.scan_type_label.grid(row=0, column=0, sticky="w")
        self.state_badge = theme.Label(
            header,
            text="SCANNING",
            text_color=theme.ACCENT,
            fg_color=theme.ACCENT_DARK,
            font=theme.font("secondary", "bold", theme.FONT),
            corner_radius=theme.RADIUS_SMALL,
            padx=10,
            pady=4,
        )
        self.state_badge.grid(row=0, column=1, padx=(12, 0), sticky="e")

        self.message_label = theme.Label(
            self,
            text="Checking your files...",
            text_color=theme.TEXT_MUTED,
            font=theme.font("body", "normal", theme.FONT),
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
        theme.Label(
            progress_head,
            text="Scan progress",
            text_color=theme.TEXT,
            font=theme.font("body", "bold", theme.FONT),
            anchor="w",
        ).grid(row=0, column=0, sticky="w")
        self.percent_label = theme.Label(
            progress_head,
            text="Starting...",
            text_color=theme.ACCENT,
            font=theme.font("body", "bold", theme.FONT),
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
        self.files_checked_value = theme.Label(
            metrics,
            text="0",
            text_color=theme.TEXT,
            font=theme.font("page", "bold", theme.FONT),
            anchor="w",
        )
        self.files_checked_value.grid(row=0, column=0, sticky="w")
        self.threats_value = theme.Label(
            metrics,
            text="0",
            text_color=theme.TEXT,
            font=theme.font("page", "bold", theme.FONT),
            anchor="w",
        )
        self.threats_value.grid(row=0, column=1, sticky="w")
        theme.Label(
            metrics,
            text="Files processed",
            text_color=theme.TEXT_MUTED,
            font=theme.font("body", "normal", theme.FONT),
            anchor="w",
        ).grid(row=1, column=0, sticky="w")
        theme.Label(
            metrics,
            text="Threats found",
            text_color=theme.TEXT_MUTED,
            font=theme.font("body", "normal", theme.FONT),
            anchor="w",
        ).grid(row=1, column=1, sticky="w")

        self.timing_label = theme.Label(
            metrics,
            text="Elapsed: 0s  •  Estimated remaining: Calculating estimate...",
            text_color=theme.TEXT_MUTED,
            font=theme.font("body", "normal", theme.FONT),
            anchor="w",
        )
        self.timing_label.grid(row=2, column=0, columnspan=2, pady=(10, 0), sticky="ew")

        current = ctk.CTkFrame(progress_card, fg_color=theme.SURFACE_ALT, corner_radius=theme.RADIUS_SMALL)
        current.grid(row=3, column=0, padx=18, pady=(0, 16), sticky="ew")
        current.grid_columnconfigure(0, weight=1)
        theme.Label(
            current,
            text="Currently checking",
            text_color=theme.TEXT_DIM,
            font=theme.font("secondary", "bold", theme.FONT),
            anchor="w",
        ).grid(row=0, column=0, padx=12, pady=(9, 2), sticky="ew")
        self.current_path_label = theme.Label(
            current,
            text="Preparing scan...",
            text_color=theme.TEXT_MUTED,
            font=theme.font("body", "normal", theme.FONT),
            anchor="w",
            justify="left",
            wraplength=760,
        )
        self.current_path_label.grid(row=1, column=0, padx=12, pady=(0, 10), sticky="ew")

        controls = ctk.CTkFrame(self, fg_color="transparent")
        controls.grid(row=3, column=0, pady=(12, 0), sticky="ew")
        controls.grid_columnconfigure(0, weight=1)
        self.details_button = theme.Button(
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
            font=theme.font("body", "normal", theme.FONT),
            corner_radius=theme.RADIUS_SMALL,
        )
        self.details_button.grid(row=0, column=0, sticky="w")
        self.stop_button = theme.Button(
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
            font=theme.font("body", "bold", theme.FONT),
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
        self.detail_values: dict[str, theme.Label] = {}
        details = (
            ("discovered", "Discovered"),
            ("processed", "Processed"),
            ("scanned", "Scanned successfully"),
            ("safe", "Safe"),
            ("skipped", "Skipped"),
            ("errors", "Errors"),
            ("suspicious", "Suspicious"),
            ("dangerous", "Dangerous"),
            ("bytes", "Bytes processed"),
        )
        for index, (key, label) in enumerate(details):
            row = (index // 3) * 2
            column = index % 3
            value = theme.Label(
                self.details_frame,
                text="0",
                text_color=theme.TEXT,
                font=theme.font("card", "bold", theme.FONT),
                anchor="w",
            )
            value.grid(row=row, column=column, padx=14, pady=(12, 0), sticky="ew")
            theme.Label(
                self.details_frame,
                text=label,
                text_color=theme.TEXT_MUTED,
                font=theme.font("secondary", "normal", theme.FONT),
                anchor="w",
            ).grid(row=row + 1, column=column, padx=14, pady=(0, 12), sticky="ew")
            self.detail_values[key] = value

        self.bind("<Configure>", self._resize_for_width)

    def start(self, scan_type: str, target: str = "", *, stoppable: bool = True,
              target_count: int | None = None) -> None:
        self._stop_clock()
        self._scan_type = scan_type or "manual"
        self._discovered = 0
        self._processed = 0
        self._counts = {key: 0 for key in self._counts}
        self._bytes_processed = 0
        self.scan_type_label.configure(text=_SCAN_NAMES.get(self._scan_type, self._friendly_type()))
        message = _SCAN_MESSAGES.get(self._scan_type, "Checking your files for threats...")
        if target_count is not None:
            message = f"Scanning {target_count:,} selected files and folders in one custom scan."
        self.message_label.configure(text=message)
        self._started_at = time.monotonic()
        self._phase = "discovering"
        self._total = None
        self._eta_seconds = None
        self._elapsed_snapshot = None
        self._elapsed_snapshot_at = None
        self._clock_tick()
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

    def update_discovery(self, discovered: int, processed: int, current_path: str = "", *,
                         phase: str = "discovering", total: int | None = None,
                         eta_seconds: float | None = None,
                         bytes_processed: int = 0,
                         elapsed_seconds: float | None = None) -> None:
        self._discovered = max(self._discovered, int(discovered), int(processed))
        self._processed = max(self._processed, int(processed))
        self._bytes_processed = max(0, int(bytes_processed))
        self._set_elapsed_snapshot(elapsed_seconds)
        self._set_progress_state(phase, total, eta_seconds)
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
        phase: str = "scanning",
        total: int | None = None,
        eta_seconds: float | None = None,
        bytes_processed: int = 0,
        elapsed_seconds: float | None = None,
    ) -> None:
        self._processed = max(0, int(processed))
        self._discovered = max(self._processed, int(discovered))
        self._counts.update({key: int(value) for key, value in counts.items() if key in self._counts})
        self._bytes_processed = max(0, int(bytes_processed))
        self._set_elapsed_snapshot(elapsed_seconds)
        self._set_progress_state(phase, total, eta_seconds)
        denominator = self._total if self._total is not None else self._discovered
        total_text = f"{denominator:,}" if denominator else "?"
        self.files_checked_value.configure(text=f"{self._processed:,} / {total_text}")
        # LOW_CONFIDENCE is suspicious evidence, not a confirmed threat.
        self.threats_value.configure(text=f"{self._counts['dangerous']:,}")
        if current_path:
            self.current_path_label.configure(text=current_path)
        self._paint_progress()
        self._refresh_details()

    def end(self) -> None:
        self.progress.stop()
        self._stop_clock()

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

    def complete(self) -> None:
        self._stop_clock()
        self.progress.stop()
        self.progress.configure(mode="determinate")
        self.progress.set(1)
        self.percent_label.configure(text="100%")
        self.state_badge.configure(text="COMPLETED")
        self.message_label.configure(text="Scan completed successfully.")
        self._eta_seconds = None
        self._paint_timing()

    def fail(self, message: str) -> None:
        self.end()
        self.state_badge.configure(text="FAILED")
        self.message_label.configure(text=message or "Scan failed. See the diagnostic details.")
        self.percent_label.configure(text="Incomplete")
        self.stop_button.grid_remove()

    def cancelled(self) -> None:
        self.end()
        self.state_badge.configure(text="INCOMPLETE")
        self.message_label.configure(text="Scan stopped. Completed results were saved.")
        self.percent_label.configure(text="Incomplete")
        self.stop_button.grid_remove()

    def _set_progress_state(self, phase: str, total: int | None, eta_seconds: float | None) -> None:
        self._phase = phase
        if total is not None:
            self._total = max(self._processed, int(total))
        self._eta_seconds = eta_seconds
        if phase == "scanning" and self._total:
            self.progress.stop()
            self.progress.configure(mode="determinate")
            fraction = min(0.99, self._processed / self._total)
            self.progress.set(fraction)
            self.percent_label.configure(text=f"{fraction * 100:.0f}%")
            self.message_label.configure(text=f"Scanning files • {self._total:,} processing entries")
        else:
            self.progress.stop()
            self.progress.configure(mode="indeterminate")
            self.progress.start()
            self.percent_label.configure(text="Discovering files..." if phase == "discovering" else "Finalizing...")
            self.message_label.configure(text="Discovering files..." if phase == "discovering" else "Finalizing scan...")
        self._paint_timing()

    def _clock_tick(self) -> None:
        self._clock_after = None
        if self._started_at is None:
            return
        self._paint_timing()
        self._clock_after = self.after(1000, self._clock_tick)

    def _stop_clock(self) -> None:
        if self._clock_after is not None:
            try:
                self.after_cancel(self._clock_after)
            except Exception:
                pass
            self._clock_after = None

    def _paint_timing(self) -> None:
        if self._elapsed_snapshot is not None and self._elapsed_snapshot_at is not None:
            elapsed = max(0, int(self._elapsed_snapshot + time.monotonic() - self._elapsed_snapshot_at))
        else:
            elapsed = max(0, int(time.monotonic() - self._started_at)) if self._started_at is not None else 0
        eta = "Estimated time unavailable"
        if self._eta_seconds is not None:
            eta = f"~{self._format_duration(self._eta_seconds)} remaining"
        elif self._phase == "scanning":
            eta = "Calculating estimate..." if self._total is not None else "Estimated time unavailable"
        self.timing_label.configure(text=f"Elapsed: {self._format_duration(elapsed)}  •  {eta}")

    def _set_elapsed_snapshot(self, elapsed_seconds: float | None) -> None:
        if elapsed_seconds is not None:
            self._elapsed_snapshot = max(0.0, float(elapsed_seconds))
            self._elapsed_snapshot_at = time.monotonic()

    @staticmethod
    def _format_duration(seconds: float) -> str:
        value = max(0, int(seconds))
        hours, remainder = divmod(value, 3600)
        minutes, seconds = divmod(remainder, 60)
        if hours:
            return f"{hours}h {minutes}m"
        if minutes:
            return f"{minutes}m {seconds}s"
        return f"{seconds}s"

    @staticmethod
    def _format_bytes(byte_count: int) -> str:
        amount = float(max(0, byte_count))
        for unit in ("B", "KB", "MB", "GB", "TB"):
            if amount < 1024 or unit == "TB":
                return f"{amount:.0f} {unit}" if unit == "B" else f"{amount:.1f} {unit}"
            amount /= 1024

    def _paint_progress(self) -> None:
        denominator = self._total if self._total is not None else self._discovered
        total_text = f"{denominator:,}" if denominator else "?"
        self.files_checked_value.configure(text=f"{self._processed:,} / {total_text}")
        self._set_progress_state(self._phase, self._total, self._eta_seconds)

    def _refresh_details(self) -> None:
        values = {
            "discovered": self._discovered,
            "processed": self._processed,
            "scanned": self._counts["scanned"],
            "safe": self._counts.get("safe", 0),
            "skipped": self._counts["skipped"],
            "errors": self._counts["errors"],
            "suspicious": self._counts["suspicious"],
            "dangerous": self._counts["dangerous"],
            "bytes": self._bytes_processed,
        }
        for key, value in values.items():
            rendered = self._format_bytes(value) if key == "bytes" else f"{value:,}"
            self.detail_values[key].configure(text=rendered)

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
