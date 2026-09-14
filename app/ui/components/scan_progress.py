from __future__ import annotations
import customtkinter as ctk
from app.ui import theme


class ScanProgressPanel(ctk.CTkFrame):
    def __init__(self, master, **kwargs):
        super().__init__(master, fg_color=theme.SURFACE, border_width=1, border_color=theme.BORDER, corner_radius=theme.RADIUS, **kwargs)
        self.grid_columnconfigure(0, weight=1); self._total = self._processed = 0

        header = ctk.CTkFrame(self, fg_color="transparent"); header.grid(row=0, column=0, padx=16, pady=(15, 4), sticky="ew"); header.grid_columnconfigure(0, weight=1)
        self.title = ctk.CTkLabel(header, text="No scan running", font=(theme.FONT, 15, "bold"), text_color=theme.TEXT, anchor="w"); self.title.grid(row=0, column=0, sticky="w")
        self.percent = ctk.CTkLabel(header, text="0%", font=(theme.FONT, 13, "bold"), text_color=theme.ACCENT, anchor="e"); self.percent.grid(row=0, column=1, sticky="e")

        self.detail = ctk.CTkLabel(self, text="Select a file or folder to scan.", font=(theme.FONT, 11), text_color=theme.TEXT_MUTED, anchor="w"); self.detail.grid(row=1, column=0, padx=16, sticky="ew")
        self.progress = ctk.CTkProgressBar(self, mode="determinate", progress_color=theme.ACCENT, fg_color=theme.SURFACE_ALT, height=10, corner_radius=5); self.progress.grid(row=2, column=0, padx=16, pady=(12, 5), sticky="ew"); self.progress.set(0)
        self.work = ctk.CTkLabel(self, text="0 / 0 items", font=(theme.FONT, 10), text_color=theme.TEXT_MUTED, anchor="e"); self.work.grid(row=3, column=0, padx=16, sticky="ew")

        self.counter_frame = ctk.CTkFrame(self, fg_color="transparent"); self.counter_frame.grid(row=4, column=0, padx=16, pady=(8, 15), sticky="ew")
        self.labels = {}
        for idx, key in enumerate(("scanned", "skipped", "suspicious", "dangerous", "errors")):
            self.counter_frame.grid_columnconfigure(idx, weight=1)
            lbl = ctk.CTkLabel(self.counter_frame, text=f"0\n{key.title()}", font=(theme.FONT, 10), text_color=theme.TEXT_MUTED); lbl.grid(row=0, column=idx, sticky="ew")
            self.labels[key] = lbl

    def start(self, label: str) -> None:
        self._total = self._processed = 0
        self.title.configure(text="Preparing scan"); self.detail.configure(text=label); self.percent.configure(text="—"); self.work.configure(text="Counting items…")
        for k, lbl in self.labels.items(): lbl.configure(text=f"0\n{k.title()}")
        self.progress.configure(mode="indeterminate"); self.progress.set(0); self.progress.start()

    def set_total(self, total: int, label: str = "") -> None:
        self.progress.stop(); self.progress.configure(mode="determinate")
        self._total, self._processed = max(0, int(total)), 0
        self.title.configure(text="Scanning")
        if label: self.detail.configure(text=label)
        self.progress.set(0 if self._total else 1); self.percent.configure(text="0%" if self._total else "100%"); self.work.configure(text=f"0 / {self._total:,} items")

    def update_progress(self, processed: int, total: int, counts: dict[str, int], current_path: str = "") -> None:
        self.progress.stop(); self.progress.configure(mode="determinate")
        self._processed, self._total = max(0, int(processed)), max(max(0, int(processed)), int(total))
        ratio = max(0.0, min(1.0, (self._processed / self._total) if self._total else 1.0))
        self.progress.set(ratio); self.percent.configure(text=f"{ratio * 100:.0f}%"); self.work.configure(text=f"{self._processed:,} / {self._total:,} items")
        if current_path: self.detail.configure(text=current_path)
        for k, lbl in self.labels.items(): lbl.configure(text=f"{counts.get(k, 0):,}\n{k.title()}")

    def finish(self, message: str) -> None:
        self.progress.stop(); self.progress.configure(mode="determinate"); self.progress.set(1); self.percent.configure(text="100%")
        if self._total: self.work.configure(text=f"{self._processed:,} / {self._total:,} items")
        self.title.configure(text="Scan finished"); self.detail.configure(text=message)