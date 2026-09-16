from __future__ import annotations
from pathlib import Path
import customtkinter as ctk
from app.startup import AutoGuardServices
from app.ui import theme
from app.ui.activity_page import ActivityPage
from app.ui.components import NotificationCenter
from app.ui.controller import AutoGuardUIController
from app.ui.dashboard import DashboardPage
from app.ui.messages import UIMessageBus
from app.ui.quarantine_page import QuarantinePage
from app.ui.scan_page import ScanPage
from app.ui.settings_page import SettingsPage
from app.ui.sidebar import NAV_ITEMS, Sidebar
from app.ui.threats_page import ThreatsPage

DEFAULT_PAGE = "home"
PAGE_CLASSES = {"home": DashboardPage, "scan": ScanPage, "threats": ThreatsPage, "quarantine": QuarantinePage, "activity": ActivityPage, "settings": SettingsPage}

if tuple(PAGE_CLASSES) != tuple(key for key, _ in NAV_ITEMS): raise RuntimeError("Sidebar navigation and page registry are out of sync.")

class MainWindow(ctk.CTk):
    def __init__(self, services: AutoGuardServices, *, initial_path: Path | None = None):
        super().__init__(); ctk.set_appearance_mode("dark"); self.title("AutoGuard"); self.geometry("1320x820"); self.minsize(1080, 680); self.configure(fg_color=theme.BG); self.protocol("WM_DELETE_WINDOW", self._close)
        self.bus = UIMessageBus(); self.controller = AutoGuardUIController(services, self.bus); self.notifications = NotificationCenter(self); self._closing = False; self._active_page: str | None = None
        self.grid_rowconfigure(0, weight=1); self.grid_columnconfigure(1, weight=1)
        self.sidebar = Sidebar(self, self.show_page); self.sidebar.grid(row=0, column=0, sticky="nsw")
        self.container = ctk.CTkFrame(self, fg_color=theme.BG, corner_radius=0); self.container.grid(row=0, column=1, sticky="nsew"); self.container.grid_rowconfigure(0, weight=1); self.container.grid_columnconfigure(0, weight=1)
        self.pages = {key: page_class(self.container, self.controller) for key, page_class in PAGE_CLASSES.items()}
        for page in self.pages.values(): page.grid(row=0, column=0, sticky="nsew")
        self.show_page(DEFAULT_PAGE); self.after(90, self._drain_messages); self.after(700, self._periodic_home_refresh)
        if initial_path is not None: self.after(450, lambda: self.controller.start_scan(initial_path))

    @property
    def active_page(self) -> str | None: return self._active_page

    def show_page(self, name: str) -> None:
        page = self.pages.get(name)
        if page is None: return
        self._active_page = name; self.sidebar.set_active(name); page.tkraise(); page.on_show()

    def _drain_messages(self) -> None:
        if self._closing: return
        for message in self.bus.drain():
            if message.kind == "navigate": self.show_page(message.payload.get("page", ""))
            elif message.kind == "dashboard_data":
                state = message.payload.get("result", {}).get("protection_state", {}); key = state.get("key", "issue")
                sidebar_status = {"protected": "protected", "scanning": "running", "attention": "suspicious", "issue": "failed"}.get(key, "stopped")
                self.sidebar.set_protection(state.get("title", "Checking"), sidebar_status)
            for page in self.pages.values():
                try: page.handle_message(message)
                except Exception: pass
            if message.kind == "task_failed": self.notifications.show("Operation failed", message.payload.get("error", "Unknown error"), "error")
            elif message.kind == "quarantine_verified":
                ok = bool(getattr(message.payload.get("result"), "verified", False))
                self.notifications.show("Integrity check", "Quarantine object verified." if ok else "Integrity verification failed.", "verified" if ok else "failed")
            elif message.kind == "recovery_completed":
                status = getattr(getattr(message.payload.get("result"), "status", None), "value", "Recovery completed")
                self.notifications.show("Recovery", status.replace("_", " ").title(), "info" if "RESTORED" in status else "warning")
            elif message.kind == "quarantine_deleted": self.notifications.show("Quarantine", "Isolated object permanently deleted; audit metadata retained.", "warning")
        self.after(90, self._drain_messages)

    def _periodic_home_refresh(self) -> None:
        if self._closing: return
        if self._active_page == "home": self.controller.refresh_dashboard()
        self.after(2500, self._periodic_home_refresh)

    def _close(self) -> None: self._closing = True; self.controller.shutdown(); self.destroy()

def launch_desktop(services: AutoGuardServices, initial_path: Path | None = None) -> None:
    MainWindow(services, initial_path=initial_path).mainloop()