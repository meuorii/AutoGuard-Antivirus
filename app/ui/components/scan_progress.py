from __future__ import annotations
import customtkinter as ctk
from app.ui import theme

class ScanProgressPanel(ctk.CTkFrame):
    def __init__(self, master, **kwargs):
        super().__init__(master, fg_color=theme.SURFACE, border_width=1, border_color=theme.BORDER, corner_radius=theme.RADIUS, **kwargs)
        self.grid_columnconfigure(0, weight=1); self._discovered = self._processed = 0
        h = ctk.CTkFrame(self, fg_color="transparent"); h.grid(row=0, column=0, padx=16, pady=(15, 4), sticky="ew"); h.grid_columnconfigure(0, weight=1)
        self.title = ctk.CTkLabel(h, text="No scan running", font=(theme.FONT, 15, "bold"), text_color=theme.TEXT, anchor="w"); self.title.grid(row=0, column=0, sticky="w")
        self.percent = ctk.CTkLabel(h, text="0%", font=(theme.FONT, 13, "bold"), text_color=theme.ACCENT, anchor="e"); self.percent.grid(row=0, column=1, sticky="e")
        self.detail = ctk.CTkLabel(self, text="Select a file or folder to scan.", font=(theme.FONT, 11), text_color=theme.TEXT_MUTED, anchor="w"); self.detail.grid(row=1, column=0, padx=16, sticky="ew")
        self.progress = ctk.CTkProgressBar(self, mode="determinate", progress_color=theme.ACCENT, fg_color=theme.SURFACE_ALT, height=10, corner_radius=5); self.progress.grid(row=2, column=0, padx=16, pady=(12, 5), sticky="ew"); self.progress.set(0)
        self.work = ctk.CTkLabel(self, text="0 processed • 0 discovered", font=(theme.FONT, 10), text_color=theme.TEXT_MUTED, anchor="e"); self.work.grid(row=3, column=0, padx=16, sticky="ew")
        f = ctk.CTkFrame(self, fg_color="transparent"); f.grid(row=4, column=0, padx=16, pady=(8, 15), sticky="ew"); self.labels = {}
        for i, key in enumerate(("scanned", "skipped", "suspicious", "dangerous", "errors")):
            f.grid_columnconfigure(i, weight=1)
            lbl = ctk.CTkLabel(f, text=f"0\n{key.title()}", font=(theme.FONT, 10), text_color=theme.TEXT_MUTED); lbl.grid(row=0, column=i, sticky="ew")
            self.labels[key] = lbl

    def start(self, label: str) -> None:
        self._discovered = self._processed = 0; self.title.configure(text="Discovering & scanning"); self.detail.configure(text=label); self.percent.configure(text="0%"); self.work.configure(text="0 processed • 0 discovered"); self.progress.configure(mode="determinate"); self.progress.set(0)
        for k, l in self.labels.items(): l.configure(text=f"0\n{k.title()}")

    def _paint(self, current_path: str = "") -> None:
        raw = (self._processed / self._discovered) if self._discovered else 0.0; shown = min(raw, 0.99) if self._processed or self._discovered else 0.0
        self.progress.set(max(0.0, min(1.0, shown))); self.percent.configure(text=f"~{raw*100:.0f}%" if self._discovered else "0%"); self.work.configure(text=f"{self._processed:,} processed • {self._discovered:,} discovered")
        if current_path: self.detail.configure(text=current_path)

    def update_discovery(self, discovered: int, processed: int = 0, current_path: str = "") -> None:
        self._discovered = max(self._discovered, int(discovered), int(processed)); self._processed = max(self._processed, int(processed)); self._paint(current_path)

    def update_progress(self, processed: int, discovered: int, counts: dict[str, int], current_path: str = "") -> None:
        self._processed = max(0, int(processed)); self._discovered = max(self._processed, int(discovered)); self._paint(current_path)
        for k, l in self.labels.items(): l.configure(text=f"{counts.get(k, 0):,}\n{k.title()}")

    def finish(self, message: str) -> None:
        self.progress.set(1); self.percent.configure(text="100%"); self._discovered = max(self._discovered, self._processed); self.work.configure(text=f"{self._processed:,} processed • {self._discovered:,} discovered"); self.title.configure(text="Scan finished"); self.detail.configure(text=message)