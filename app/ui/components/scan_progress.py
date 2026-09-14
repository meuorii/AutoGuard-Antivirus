from __future__ import annotations
import customtkinter as ctk
from app.ui import theme

class ScanProgressPanel(ctk.CTkFrame):
    def __init__(self, master, **kwargs):
        super().__init__(master, fg_color=theme.SURFACE, border_width=1, border_color=theme.BORDER, corner_radius=theme.RADIUS, **kwargs)
        self.grid_columnconfigure(0, weight=1)
        self.title = ctk.CTkLabel(self, text="No scan running", font=(theme.FONT, 15, "bold"), text_color=theme.TEXT, anchor="w")
        self.title.grid(row=0, column=0, padx=16, pady=(15, 4), sticky="ew")
        self.detail = ctk.CTkLabel(self, text="Select a file or folder to scan.", font=(theme.FONT, 11), text_color=theme.TEXT_MUTED, anchor="w")
        self.detail.grid(row=1, column=0, padx=16, sticky="ew")
        self.progress = ctk.CTkProgressBar(self, mode="indeterminate", progress_color=theme.ACCENT, fg_color=theme.SURFACE_ALT)
        self.progress.grid(row=2, column=0, padx=16, pady=(12, 12), sticky="ew"); self.progress.set(0)
        self.counter_frame = ctk.CTkFrame(self, fg_color="transparent")
        self.counter_frame.grid(row=3, column=0, padx=16, pady=(0, 15), sticky="ew")
        self.labels = {}
        for idx, key in enumerate(("scanned", "skipped", "suspicious", "dangerous", "errors")):
            self.counter_frame.grid_columnconfigure(idx, weight=1)
            label = ctk.CTkLabel(self.counter_frame, text=f"0\n{key.title()}", font=(theme.FONT, 10), text_color=theme.TEXT_MUTED)
            label.grid(row=0, column=idx, sticky="ew"); self.labels[key] = label

    def start(self, label: str) -> None:
        self.title.configure(text="Scanning"); self.detail.configure(text=label)
        for key, lbl in self.labels.items(): lbl.configure(text=f"0\n{key.title()}")
        self.progress.start()

    def update_counts(self, counts: dict[str, int], current_path: str = "") -> None:
        if current_path: self.detail.configure(text=current_path)
        for key, lbl in self.labels.items(): lbl.configure(text=f"{counts.get(key, 0)}\n{key.title()}")

    def finish(self, message: str) -> None:
        self.progress.stop(); self.progress.set(1)
        self.title.configure(text="Scan finished"); self.detail.configure(text=message)