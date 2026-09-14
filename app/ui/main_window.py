from __future__ import annotations
from pathlib import Path
import customtkinter as ctk

from app.startup import AutoGuardServices
from app.ui import theme
from app.ui.controller import AutoGuardUIController
from app.ui.messages import UIMessageBus
from app.ui.sidebar import Sidebar
from app.ui.dashboard import DashboardPage
from app.ui.scan_page import ScanPage
from app.ui.incidents_page import IncidentsPage
from app.ui.threat_trail_page import ThreatTrailPage
from app.ui.quarantine_page import QuarantinePage
from app.ui.history_page import HistoryPage
from app.ui.settings_page import SettingsPage
from app.ui.components import NotificationCenter

class MainWindow(ctk.CTk):
    """Responsive shell. All blocking service calls are dispatched by controller."""
    def __init__(self, services: AutoGuardServices, *, initial_path: Path | None = None):
        super().__init__(); ctk.set_appearance_mode("dark"); self.title("AutoGuard")
        self.geometry("1320x820"); self.minsize(1080, 680); self.configure(fg_color=theme.BG); self.protocol("WM_DELETE_WINDOW", self._close)
        self.bus = UIMessageBus(); self.controller = AutoGuardUIController(services, self.bus); self.notifications = NotificationCenter(self); self._closing = False
        self.grid_rowconfigure(0, weight=1); self.grid_columnconfigure(1, weight=1)
        self.sidebar = Sidebar(self, self.show_page); self.sidebar.grid(row=0, column=0, sticky="nsw")
        self.container = ctk.CTkFrame(self, fg_color=theme.BG, corner_radius=0); self.container.grid(row=0, column=1, sticky="nsew")
        self.container.grid_rowconfigure(0, weight=1); self.container.grid_columnconfigure(0, weight=1)
        self.pages = {
            "dashboard": DashboardPage(self.container, self.controller), "scan": ScanPage(self.container, self.controller),
            "incidents": IncidentsPage(self.container, self.controller), "threat_trail": ThreatTrailPage(self.container, self.controller),
            "quarantine": QuarantinePage(self.container, self.controller), "history": HistoryPage(self.container, self.controller),
            "settings": SettingsPage(self.container, self.controller),
        }
        for page in self.pages.values(): page.grid(row=0, column=0, sticky="nsew")
        self.current = "dashboard"; self.show_page("dashboard")
        self.after(90, self._drain_messages); self.after(700, self._periodic_dashboard_refresh)
        if initial_path is not None: self.after(450, lambda: self.controller.start_scan(initial_path))

    def show_page(self, name: str) -> None:
        if name not in self.pages: return
        self.current = name; self.sidebar.set_active(name); page = self.pages[name]
        page.tkraise(); page.on_show()

    def _drain_messages(self) -> None:
        if self._closing: return
        for message in self.bus.drain():
            for page in self.pages.values():
                try: page.handle_message(message)
                except Exception: pass
            if message.kind == "task_failed": self.notifications.show("Operation failed", message.payload.get("error", "Unknown error"), "error")
            elif message.kind == "quarantine_verified":
                result = message.payload.get("result"); ok = bool(getattr(result, "verified", False))
                self.notifications.show("Integrity check", "Quarantine object verified." if ok else "Integrity verification failed.", "verified" if ok else "failed")
            elif message.kind == "recovery_completed":
                result = message.payload.get("result"); status = getattr(getattr(result, "status", None), "value", "Recovery completed")
                self.notifications.show("Recovery", status.replace("_", " ").title(), "info" if "RESTORED" in status else "warning")
            elif message.kind == "quarantine_deleted": self.notifications.show("Quarantine", "Isolated object permanently deleted; audit metadata retained.", "warning")
        self.after(90, self._drain_messages)

    def _periodic_dashboard_refresh(self) -> None:
        if self._closing: return
        if self.current == "dashboard": self.controller.refresh_dashboard()
        self.after(2500, self._periodic_dashboard_refresh)

    def _close(self) -> None:
        self._closing = True; self.controller.shutdown(); self.destroy()

def launch_desktop(services: AutoGuardServices, initial_path: Path | None = None) -> None:
    """Create and run the Windows desktop UI on the caller/main thread."""
    MainWindow(services, initial_path=initial_path).mainloop()