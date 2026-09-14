from __future__ import annotations
import customtkinter as ctk
from app.ui.base_page import BasePage
from app.ui import theme
from app.ui.components import StatusCard, ThreatCard

class DashboardPage(BasePage):
    title = "Dashboard"
    subtitle = "Protection status and recent security activity"
    def __init__(self, master, controller, **kwargs):
        super().__init__(master, controller, **kwargs); self.body.grid_columnconfigure((0, 1, 2, 3), weight=1)
        hero = ctk.CTkFrame(self.body, fg_color=theme.SURFACE, border_width=1, border_color=theme.BORDER, corner_radius=theme.RADIUS)
        hero.grid(row=0, column=0, columnspan=4, padx=8, pady=(4, 10), sticky="ew"); hero.grid_columnconfigure(0, weight=1)
        ctk.CTkLabel(hero, text="Protection overview", text_color=theme.TEXT, font=(theme.FONT, 18, "bold"), anchor="w").grid(row=0, column=0, padx=20, pady=(18, 4), sticky="w")
        self.protection = ctk.CTkLabel(hero, text="Checking protection services…", text_color=theme.TEXT_MUTED, font=(theme.FONT, 11), anchor="w")
        self.protection.grid(row=1, column=0, padx=20, pady=(0, 18), sticky="w")
        self.activity = ctk.CTkLabel(hero, text="Idle", text_color=theme.ACCENT, fg_color=theme.ACCENT_DARK, corner_radius=7, padx=10, pady=5, font=(theme.FONT, 10, "bold"))
        self.activity.grid(row=0, column=1, rowspan=2, padx=20, pady=18, sticky="e")
        self.cards = {}; specs = (("file", "File monitor"), ("usb", "USB protection"), ("schedule", "Scheduled scans"), ("quarantine", "Quarantine"))
        for col, (key, label) in enumerate(specs):
            card = StatusCard(self.body, label); card.grid(row=1, column=col, padx=8, pady=8, sticky="nsew"); self.cards[key] = card
        ctk.CTkLabel(self.body, text="Recent detections", text_color=theme.TEXT, font=(theme.FONT, 15, "bold"), anchor="w").grid(row=2, column=0, columnspan=4, padx=8, pady=(18, 7), sticky="ew")
        self.recent = ctk.CTkFrame(self.body, fg_color="transparent"); self.recent.grid(row=3, column=0, columnspan=4, padx=8, pady=(0, 12), sticky="ew"); self.recent.grid_columnconfigure(0, weight=1)

    def on_show(self): self.controller.refresh_dashboard()

    def handle_message(self, message):
        if message.kind == "dashboard_data": self._render(message.payload["result"])
        elif message.kind in ("task_started", "task_finished"):
            tasks = message.payload.get("active_tasks", ())
            self.activity.configure(text=("Working · " + str(len(tasks))) if tasks else "Idle")

    def _render(self, data):
        fm = data.get("file_monitor"); usb = data.get("usb_monitor"); sch = data.get("scheduler")
        fm_status = getattr(getattr(fm, "status", None), "value", "stopped") if fm else "stopped"
        usb_status = getattr(getattr(usb, "status", None), "value", "stopped") if usb else "stopped"
        protected = fm_status.lower() == "running" and (usb is None or usb_status.lower() in ("running", "idle"))
        self.protection.configure(
            text=("Core protection services are active." if protected else "Protection needs attention. Review service status below."),
            text_color=theme.SUCCESS if protected else theme.WARNING
        )
        self.cards["file"].set(fm_status.title(), f"{getattr(fm, 'scans_dispatched', 0)} real-time scans", fm_status)
        self.cards["usb"].set(usb_status.title() if usb else "Disabled", f"{len(getattr(usb, 'present_drives', ()) or ())} removable drives present" if usb else "USB monitor not enabled", usb_status)
        running = "Quick/Full active" if sch and (sch.quick_scan_running or sch.full_scan_running) else "Ready"
        self.cards["schedule"].set(running, f"Quick {self.controller.services.scheduler.settings.quick_interval_hours:g}h · Full {self.controller.services.scheduler.settings.full_interval_days:g}d", "running" if sch and sch.running else "stopped")
        self.cards["quarantine"].set(str(data.get("quarantined_count", 0)), f"{data.get('active_incidents', 0)} active incidents", "contained" if data.get("quarantined_count", 0) else "idle")
        for child in self.recent.winfo_children(): child.destroy()
        rows = data.get("recent_detections", [])
        if not rows: ctk.CTkLabel(self.recent, text="No recent dangerous or suspicious detections.", text_color=theme.TEXT_DIM, font=(theme.FONT, 11)).grid(row=0, column=0, pady=20)
        for i, row in enumerate(rows):
            ThreatCard(self.recent, path=row["path"], status=("dangerous" if row["status"] == "HIGH_CONFIDENCE" else "suspicious"), reason=row["reason"], meta=row["recorded_at"]).grid(row=i, column=0, pady=5, sticky="ew")