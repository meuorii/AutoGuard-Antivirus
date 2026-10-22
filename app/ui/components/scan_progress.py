"""Compact scanner-driven progress panel retained for existing imports."""
from __future__ import annotations

import customtkinter as ctk

from app.ui import theme


class ScanProgressPanel(ctk.CTkFrame):
    def __init__(self, master, **kwargs):
        super().__init__(master, fg_color=theme.SURFACE, border_width=1,
                         border_color=theme.BORDER, corner_radius=theme.RADIUS, **kwargs)
        self.grid_columnconfigure(0, weight=1)
        self._processed = 0
        self._total: int | None = None
        self._phase = "discovering"
        header = ctk.CTkFrame(self, fg_color="transparent")
        header.grid(row=0, column=0, padx=16, pady=(15, 4), sticky="ew")
        header.grid_columnconfigure(0, weight=1)
        self.title = theme.Label(header, text="No scan running", font=theme.font("card", "bold", theme.FONT), text_color=theme.TEXT, anchor="w")
        self.title.grid(row=0, column=0, sticky="w")
        self.mode_badge = theme.Label(header, text="IDLE", font=theme.font("secondary", "bold", theme.FONT), text_color=theme.ACCENT, fg_color=theme.SURFACE_ALT, corner_radius=6, padx=9, pady=3)
        self.mode_badge.grid(row=0, column=1, padx=(8, 10), sticky="e")
        self.percent = theme.Label(header, text="Discovering files...", font=theme.font("card", "bold", theme.FONT), text_color=theme.ACCENT, anchor="e")
        self.percent.grid(row=0, column=2, sticky="e")
        self.detail = theme.Label(self, text="Select a file or folder to scan.", font=theme.font("body", "normal", theme.FONT), text_color=theme.TEXT_MUTED, anchor="w")
        self.detail.grid(row=1, column=0, padx=16, sticky="ew")
        self.progress = ctk.CTkProgressBar(self, mode="indeterminate", progress_color=theme.ACCENT, fg_color=theme.SURFACE_ALT, height=10, corner_radius=5)
        self.progress.grid(row=2, column=0, padx=16, pady=(12, 5), sticky="ew")
        self.progress.start()
        self.work = theme.Label(self, text="0 processed / unknown total", font=theme.font("body", "normal", theme.FONT), text_color=theme.TEXT_MUTED, anchor="e")
        self.work.grid(row=3, column=0, padx=16, sticky="ew")
        footer = ctk.CTkFrame(self, fg_color="transparent")
        footer.grid(row=4, column=0, padx=16, pady=(8, 15), sticky="ew")
        self.labels = {}
        for index, key in enumerate(("scanned", "skipped", "suspicious", "dangerous", "errors")):
            footer.grid_columnconfigure(index, weight=1)
            label = theme.Label(footer, text=f"0\n{key.title()}", font=theme.font("body", "normal", theme.FONT), text_color=theme.TEXT_MUTED)
            label.grid(row=0, column=index, sticky="ew")
            self.labels[key] = label

    def start(self, label: str, scan_type: str = "manual") -> None:
        self._processed, self._total, self._phase = 0, None, "discovering"
        names = {"manual": "Custom Scan", "quick": "Quick Scan", "full": "Full Scan", "startup": "Startup Scan", "scheduled": "Scheduled Scan", "usb": "USB Scan", "real_time": "Real-Time Scan"}
        self.title.configure(text=names.get(scan_type, scan_type.replace("_", " ").title()))
        self.mode_badge.configure(text=scan_type.replace("_", " ").upper())
        self.detail.configure(text=label)
        self._paint()
        for key, counter in self.labels.items():
            counter.configure(text=f"0\n{key.title()}")

    def update_discovery(self, discovered: int, processed: int = 0, current_path: str = "", *, phase: str = "discovering", total: int | None = None) -> None:
        self._processed = max(self._processed, int(processed))
        self._phase = phase
        if total is not None:
            self._total = max(self._processed, int(total))
        self._paint(current_path)

    def update_progress(self, processed: int, discovered: int, counts: dict[str, int], current_path: str = "", *, total: int | None = None, phase: str = "scanning") -> None:
        self._processed = max(0, int(processed))
        self._phase = phase
        if total is not None:
            self._total = max(self._processed, int(total))
        for key, label in self.labels.items():
            label.configure(text=f"{counts.get(key, 0):,}\n{key.title()}")
        self._paint(current_path)

    def _paint(self, current_path: str = "") -> None:
        if self._phase == "scanning" and self._total:
            fraction = min(0.99, self._processed / self._total)
            self.progress.stop()
            self.progress.configure(mode="determinate")
            self.progress.set(fraction)
            self.percent.configure(text=f"{fraction * 100:.0f}%")
            total_text = f"{self._total:,}"
        else:
            self.progress.stop()
            self.progress.configure(mode="indeterminate")
            self.progress.start()
            self.percent.configure(text="Discovering files..." if self._phase == "discovering" else "Finalizing...")
            total_text = "unknown"
        self.work.configure(text=f"{self._processed:,} processed / {total_text} processing entries")
        if current_path:
            self.detail.configure(text=current_path)

    def finish(self, message: str) -> None:
        self.progress.stop()
        self.progress.configure(mode="determinate")
        self.progress.set(1)
        self.percent.configure(text="100%")
        self.mode_badge.configure(text="COMPLETED")
        self.detail.configure(text=message)

    def stop(self, message: str = "Scan incomplete. Completed results were saved.") -> None:
        self.progress.stop()
        self.percent.configure(text="Incomplete")
        self.mode_badge.configure(text="INCOMPLETE")
        self.detail.configure(text=message)
