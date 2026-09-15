from __future__ import annotations
import customtkinter as ctk
from tkinter import filedialog
from app.ui.base_page import BasePage
from app.ui import theme
from app.ui.components import ScanProgressPanel
from app.models import ScanStatus

class ScanPage(BasePage):
    title = "Scan"; subtitle = "Run on-demand scans without blocking protection services"
    def __init__(self, master, controller, **kwargs):
        super().__init__(master, controller, **kwargs)
        a = ctk.CTkFrame(self.body, fg_color=theme.SURFACE, border_width=1, border_color=theme.BORDER, corner_radius=theme.RADIUS); a.grid(row=0, column=0, padx=8, pady=6, sticky="ew")
        ctk.CTkLabel(a, text="On-demand scan", font=(theme.FONT, 15, "bold"), text_color=theme.TEXT).pack(anchor="w", padx=16, pady=(14, 3))
        ctk.CTkLabel(a, text="Discovery and scanning run together — no separate pre-count pass.", font=(theme.FONT, 11), text_color=theme.TEXT_MUTED).pack(anchor="w", padx=16)
        r = ctk.CTkFrame(a, fg_color="transparent"); r.pack(fill="x", padx=16, pady=14)
        for text, cmd, primary in (("Scan file", self._file, True), ("Scan folder", self._folder, False), ("Quick scan", controller.start_quick_scan, False), ("Full scan", controller.start_full_scan, False)):
            ctk.CTkButton(r, text=text, height=34, fg_color=theme.ACCENT if primary else theme.SURFACE_ALT, hover_color=theme.ACCENT_HOVER if primary else theme.SURFACE_HOVER, text_color="#07110F" if primary else theme.TEXT, command=cmd).pack(side="left", padx=(0, 8))
        self.progress = ScanProgressPanel(self.body); self.progress.grid(row=1, column=0, padx=8, pady=8, sticky="ew")
        ctk.CTkLabel(self.body, text="Live results", text_color=theme.TEXT, font=(theme.FONT, 14, "bold"), anchor="w").grid(row=2, column=0, padx=8, pady=(15, 6), sticky="ew")
        self.log = ctk.CTkTextbox(self.body, height=280, fg_color=theme.SURFACE, border_width=1, border_color=theme.BORDER, text_color=theme.TEXT_MUTED, font=(theme.FONT, 10), wrap="none"); self.log.grid(row=3, column=0, padx=8, pady=(0, 10), sticky="ew")
        self.counts = {"scanned": 0, "skipped": 0, "suspicious": 0, "dangerous": 0, "errors": 0}

    def _file(self):
        if p := filedialog.askopenfilename(title="Select a file to scan"): self.controller.start_scan(p)
    def _folder(self):
        if p := filedialog.askdirectory(title="Select a folder to scan"): self.controller.start_scan(p)

    def handle_message(self, m):
        if m.kind == "scan_started": self.counts = {k: 0 for k in self.counts}; self.log.delete("1.0", "end"); self.progress.start(m.payload.get("path", "Scan"))
        elif m.kind == "scan_discovered": self.progress.update_discovery(m.payload.get("discovered", 0), m.payload.get("processed", 0), m.payload.get("path", ""))
        elif m.kind == "scan_result":
            status = m.payload["status"]; d = m.payload.get("detection")
            if status == ScanStatus.SCANNED.value: self.counts["scanned"] += 1
            elif status == ScanStatus.ERROR.value: self.counts["errors"] += 1
            else: self.counts["skipped"] += 1
            if d == "LOW_CONFIDENCE": self.counts["suspicious"] += 1
            elif d == "HIGH_CONFIDENCE": self.counts["dangerous"] += 1
            path = m.payload.get("path", ""); self.progress.update_progress(m.payload.get("processed", 0), m.payload.get("discovered", 0), self.counts, path); self.log.insert("end", f"[{status}] {path}\n  {m.payload.get('reason', '')}\n"); self.log.see("end")
        elif m.kind in ("scan_completed", "scan_batch_completed"): self.progress.finish("Scan completed. Review live counters and History for the persisted report.")
        elif m.kind == "task_failed" and "scan" in str(m.payload.get("task", "")): self.progress.finish("Scan ended with an error. Review the notification and persisted history.")