"""AutoGuard CustomTkinter application shell.

UX Refresh Phase 1 changes presentation/navigation only.  Protection services
are supplied once by startup, kept alive for the window lifetime, and are never
created or restarted by page navigation.
"""
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

# One persistent page instance is created for each top-level destination.
# The older Incidents, Threat Trail, and History presentation modules remain in
# the codebase; they are intentionally not top-level navigation in this phase.
PAGE_CLASSES = {
    "home": DashboardPage,
    "scan": ScanPage,
    "threats": ThreatsPage,
    "quarantine": QuarantinePage,
    "activity": ActivityPage,
    "settings": SettingsPage,
}

if tuple(PAGE_CLASSES) != tuple(key for key, _ in NAV_ITEMS):
    raise RuntimeError("Sidebar navigation and page registry are out of sync.")


# Central cross-page synchronization. These are presentation invalidations only;
# they never construct/restart backend services. Hidden pages refresh on next show.
STATE_CHANGE_TARGETS = {
    "scan_started": {"home", "scan"},
    "scan_stopped": {"home", "scan", "activity"},
    "scan_completed": {"home", "scan", "threats", "quarantine", "activity"},
    "scan_batch_completed": {"home", "scan", "threats", "quarantine", "activity"},
    "scan_result_ready": {"home", "scan", "threats", "quarantine", "activity"},
    "incident_verified": {"home", "threats", "activity"},
    "quarantine_verified": {"quarantine"},
    "quarantine_deleted": {"home", "threats", "quarantine", "activity"},
    "recovery_completed": {"home", "threats", "quarantine", "activity"},
    "settings_applied": {"home", "settings"},
}
PASSIVE_REFRESH_PAGES = {"home", "threats", "quarantine", "activity", "settings"}
GLOBAL_STATUS_EVENTS = {
    "scan_started", "scan_stopped", "scan_completed", "scan_batch_completed",
    "scan_result_ready", "incident_verified", "quarantine_deleted",
    "recovery_completed", "settings_applied",
}
PASSIVE_REFRESH_MS = 3000


class MainWindow(ctk.CTk):
    """Responsive shell with one centrally managed active-page state."""

    def __init__(self, services: AutoGuardServices, *, initial_path: Path | None = None):
        super().__init__()
        ctk.set_appearance_mode("dark")
        self.title("AutoGuard")
        self.geometry("1320x820")
        self.minsize(1080, 680)
        self.configure(fg_color=theme.BG)
        self.protocol("WM_DELETE_WINDOW", self._close)

        # Services are created by startup and referenced by one controller.
        # Navigation never reconnects the database or restarts protection.
        self.bus = UIMessageBus()
        self.controller = AutoGuardUIController(services, self.bus)
        self.notifications = NotificationCenter(self)
        self._closing = False
        self._active_page: str | None = None

        self.grid_rowconfigure(0, weight=1)
        self.grid_columnconfigure(1, weight=1)
        self.sidebar = Sidebar(self, self.show_page)
        self.sidebar.grid(row=0, column=0, sticky="nsw")

        self.container = ctk.CTkFrame(self, fg_color=theme.BG, corner_radius=0)
        self.container.grid(row=0, column=1, sticky="nsew")
        self.container.grid_rowconfigure(0, weight=1)
        self.container.grid_columnconfigure(0, weight=1)

        self.pages = {
            key: page_class(self.container, self.controller)
            for key, page_class in PAGE_CLASSES.items()
        }
        for page in self.pages.values():
            page.grid(row=0, column=0, sticky="nsew")

        self.show_page(DEFAULT_PAGE)
        self.after(90, self._drain_messages)
        self.after(700, self._periodic_visible_refresh)
        if initial_path is not None:
            self.after(450, lambda: self.controller.start_scan(initial_path))

    @property
    def active_page(self) -> str | None:
        """The single source of truth for the currently visible page."""
        return self._active_page

    def show_page(self, name: str) -> None:
        """Raise an existing page; never construct or restart services here."""
        page = self.pages.get(name)
        if page is None:
            return
        self._active_page = name
        self.sidebar.set_active(name)
        page.tkraise()
        page.on_show()

    def _drain_messages(self) -> None:
        if self._closing:
            return
        for message in self.bus.drain():
            if message.kind == "navigate":
                self.show_page(message.payload.get("page", ""))
            elif message.kind == "dashboard_data":
                state = message.payload.get("result", {}).get("protection_state", {})
                key = state.get("key", "issue")
                sidebar_status = {
                    "protected": "protected",
                    "scanning": "running",
                    "attention": "suspicious",
                    "issue": "failed",
                }.get(key, "stopped")
                self.sidebar.set_protection(state.get("title", "Checking"), sidebar_status)
            for page in self.pages.values():
                try:
                    page.handle_message(message)
                except Exception:
                    # A single page refresh must not break the UI message pump.
                    pass
            if message.kind == "task_failed":
                self.notifications.show(
                    "Operation failed",
                    message.payload.get("error", "Unknown error"),
                    "error",
                )
            elif message.kind == "quarantine_verified":
                result = message.payload.get("result", {})
                ok = bool(result.get("verified"))
                self.notifications.show(
                    result.get("title", "Integrity check"),
                    result.get("message", "Integrity check finished."),
                    "verified" if ok else "failed",
                )
            elif message.kind == "recovery_completed":
                result = message.payload.get("result", {})
                tone = result.get("tone", "info")
                self.notifications.show(
                    result.get("title", "Restore finished"),
                    result.get("message", "The restore operation finished."),
                    "verified" if tone == "success" else ("failed" if tone == "error" else "warning"),
                )
            elif message.kind == "quarantine_deleted":
                result = message.payload.get("result", {})
                self.notifications.show(
                    result.get("title", "Quarantine"),
                    result.get("message", "The isolated file was permanently deleted."),
                    "warning",
                )
            # Home/sidebar status is global, so keep that lightweight snapshot
            # synchronized even while another page is visible.
            if message.kind in GLOBAL_STATUS_EVENTS:
                self.controller.refresh_dashboard()

            # Refresh only the currently visible affected heavy page. Hidden
            # pages use their normal on_show load when selected.
            targets = STATE_CHANGE_TARGETS.get(message.kind, set())
            if self._active_page in targets:
                self._refresh_visible_page(message.kind)
        self.after(90, self._drain_messages)

    def _refresh_visible_page(self, reason: str = "state-sync") -> None:
        page = self.pages.get(self._active_page or "")
        if page is None:
            return
        try:
            page.refresh_from_state(reason)
        except Exception:
            # A presentation refresh must never interrupt the global message pump.
            pass

    def _periodic_visible_refresh(self) -> None:
        """Keep the visible read-only page current with background monitor data.

        File/USB monitoring can persist evidence without going through the UI bus.
        Only the visible data page is refreshed, and controller read tasks are
        de-duplicated so this never creates parallel service/database readers.
        """
        if self._closing:
            return
        # Background file/USB activity may bypass the UI message bus. Keep the
        # global Home/sidebar health snapshot current regardless of active page.
        self.controller.refresh_dashboard()
        if self._active_page in PASSIVE_REFRESH_PAGES and self._active_page != "home":
            self._refresh_visible_page("background-sync")
        self.after(PASSIVE_REFRESH_MS, self._periodic_visible_refresh)

    def _close(self) -> None:
        self._closing = True
        self.controller.shutdown()
        self.destroy()


def launch_desktop(services: AutoGuardServices, initial_path: Path | None = None) -> None:
    """Create and run the Windows desktop UI on the caller/main thread."""
    MainWindow(services, initial_path=initial_path).mainloop()