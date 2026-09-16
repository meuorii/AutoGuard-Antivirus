from __future__ import annotations
from tkinter import filedialog
import customtkinter as ctk
from app.models import ScanStatus
from app.ui import theme
from app.ui.base_page import BasePage
from app.ui.components import ScanOptionCard, ScanProgressPanel

class ScanPage(BasePage):
    title = "Scan"; subtitle = "Choose how AutoGuard should check your files"

    def __init__(self, master, controller, **kwargs):
        super().__init__(master, controller, **kwargs); self.body.grid_columnconfigure(0, weight=1); self._scan_running = False
        self.counts = {"scanned": 0, "skipped": 0, "suspicious": 0, "dangerous": 0, "errors": 0}
        self._build_idle_view(); self._build_existing_active_view(); self._show_idle_view()

    def _build_idle_view(self) -> None:
        self.idle_view = ctk.CTkFrame(self.body, fg_color="transparent", corner_radius=0); self.idle_view.grid_columnconfigure(0, weight=1)
        ctk.CTkLabel(self.idle_view, text="Scan your PC", text_color=theme.TEXT, font=(theme.FONT, 22, "bold"), anchor="w").grid(row=0, column=0, padx=8, pady=(4, 3), sticky="ew")
        ctk.CTkLabel(self.idle_view, text="Choose the scan that matches what you want to check.", text_color=theme.TEXT_MUTED, font=(theme.FONT, 11), anchor="w").grid(row=1, column=0, padx=8, pady=(0, 16), sticky="ew")
        ScanOptionCard(self.idle_view, title="Quick Scan", description="Checks common places where new files usually appear.", detail="Downloads  •  Desktop  •  Documents", recommended=True, actions=(("Start Quick Scan", self.controller.start_quick_scan, True),)).grid(row=2, column=0, padx=8, pady=(0, 10), sticky="ew")
        ScanOptionCard(self.idle_view, title="Full Scan", description="Performs a broader scan of your computer. This checks more files and can take significantly longer than a Quick Scan.", actions=(("Start Full Scan", self.controller.start_full_scan, False),)).grid(row=3, column=0, padx=8, pady=(0, 10), sticky="ew")
        ScanOptionCard(self.idle_view, title="Custom Scan", description="Scan one specific file or choose a folder you want AutoGuard to check.", actions=(("Choose File", self._choose_file, True), ("Choose Folder", self._choose_folder, False))).grid(row=4, column=0, padx=8, pady=(0, 10), sticky="ew")

    def _build_existing_active_view(self) -> None:
        self.active_view = ctk.CTkFrame(self.body, fg_color="transparent", corner_radius=0); self.active_view.grid_columnconfigure(0, weight=1)
        self.progress = ScanProgressPanel(self.active_view); self.progress.grid(row=0, column=0, padx=8, pady=8, sticky="ew")
        ctk.CTkLabel(self.active_view, text="Live results", text_color=theme.TEXT, font=(theme.FONT, 14, "bold"), anchor="w").grid(row=1, column=0, padx=8, pady=(15, 6), sticky="ew")
        self.log = ctk.CTkTextbox(self.active_view, height=280, fg_color=theme.SURFACE, border_width=1, border_color=theme.BORDER, text_color=theme.TEXT_MUTED, font=(theme.FONT, 10), wrap="none")
        self.log.grid(row=2, column=0, padx=8, pady=(0, 10), sticky="ew")

    def _choose_file(self) -> None:
        if path := filedialog.askopenfilename(title="Choose a file to scan"): self.controller.start_scan(path)

    def _choose_folder(self) -> None:
        if path := filedialog.askdirectory(title="Choose a folder to scan"): self.controller.start_scan(path)

    def _show_idle_view(self) -> None: self.active_view.grid_remove(); self.idle_view.grid(row=0, column=0, sticky="ew")
    def _show_active_view(self) -> None: self.idle_view.grid_remove(); self.active_view.grid(row=0, column=0, sticky="ew")
    def on_show(self) -> None: self._show_active_view() if self._scan_running else self._show_idle_view()

    def handle_message(self, message) -> None:
        if message.kind == "scan_started":
            self._scan_running = True; self.counts = {key: 0 for key in self.counts}; self.log.delete("1.0", "end")
            self.progress.start(message.payload.get("path", "Scan"), message.payload.get("scan_type", "manual")); self._show_active_view()
        elif message.kind == "scan_discovered":
            self.progress.update_discovery(message.payload.get("discovered", 0), message.payload.get("processed", 0), message.payload.get("path", ""))
        elif message.kind == "scan_result":
            status, detection = message.payload["status"], message.payload.get("detection")
            if status == ScanStatus.SCANNED.value: self.counts["scanned"] += 1
            elif status == ScanStatus.ERROR.value: self.counts["errors"] += 1
            else: self.counts["skipped"] += 1
            if detection == "LOW_CONFIDENCE": self.counts["suspicious"] += 1
            elif detection == "HIGH_CONFIDENCE": self.counts["dangerous"] += 1
            path = message.payload.get("path", "")
            self.progress.update_progress(message.payload.get("processed", 0), message.payload.get("discovered", 0), self.counts, path)
            self.log.insert("end", f"[{status}] {path}\n  {message.payload.get('reason', '')}\n"); self.log.see("end")
        elif message.kind in ("scan_completed", "scan_batch_completed"):
            self._scan_running = False; self.progress.finish("Scan completed. Review Activity for the persisted scan record."); self._show_idle_view()
        elif message.kind == "task_failed" and "scan" in str(message.payload.get("task", "")):
            self._scan_running = False; self.progress.finish("Scan ended with an error. Review Activity for persisted details."); self._show_idle_view()