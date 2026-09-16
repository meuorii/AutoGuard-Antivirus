from __future__ import annotations
from datetime import datetime
import customtkinter as ctk
from app.ui import theme
from app.ui.base_page import BasePage

_STATE_STYLE = {"protected": (theme.SUCCESS, theme.SUCCESS_DARK, "✓"), "scanning": (theme.ACCENT, theme.ACCENT_DARK, "↻"), "attention": (theme.WARNING, theme.WARNING_DARK, "!"), "issue": (theme.DANGER, theme.DANGER_DARK, "!")}

class _SummaryBlock(ctk.CTkFrame):
    def __init__(self, master, label: str):
        super().__init__(master, fg_color=theme.SURFACE, border_width=1, border_color=theme.BORDER, corner_radius=theme.RADIUS)
        self.grid_columnconfigure(0, weight=1)
        ctk.CTkLabel(self, text=label, text_color=theme.TEXT_DIM, font=(theme.FONT, 10, "bold"), anchor="w").grid(row=0, column=0, padx=16, pady=(14, 5), sticky="ew")
        self.value = ctk.CTkLabel(self, text="Checking…", text_color=theme.TEXT, font=(theme.FONT, 15, "bold"), anchor="w"); self.value.grid(row=1, column=0, padx=16, sticky="ew")
        self.detail = ctk.CTkLabel(self, text="", text_color=theme.TEXT_MUTED, font=(theme.FONT, 10), anchor="w"); self.detail.grid(row=2, column=0, padx=16, pady=(3, 14), sticky="ew")

    def set(self, value: str, detail: str = "") -> None:
        self.value.configure(text=value); self.detail.configure(text=detail)

class _ProtectionRow(ctk.CTkFrame):
    def __init__(self, master, label: str, description: str):
        super().__init__(master, fg_color="transparent", corner_radius=0)
        self.grid_columnconfigure(0, weight=1)
        text = ctk.CTkFrame(self, fg_color="transparent"); text.grid(row=0, column=0, sticky="ew")
        ctk.CTkLabel(text, text=label, text_color=theme.TEXT, font=(theme.FONT, 11, "bold"), anchor="w").pack(anchor="w")
        ctk.CTkLabel(text, text=description, text_color=theme.TEXT_DIM, font=(theme.FONT, 9), anchor="w").pack(anchor="w", pady=(2, 0))
        self.state = ctk.CTkLabel(self, text="Checking", width=64, height=26, corner_radius=7, fg_color=theme.SURFACE_ALT, text_color=theme.TEXT_MUTED, font=(theme.FONT, 9, "bold"))
        self.state.grid(row=0, column=1, padx=(16, 0), sticky="e")

    def set(self, enabled: bool) -> None:
        self.state.configure(text="On" if enabled else "Off", text_color=theme.SUCCESS if enabled else theme.TEXT_MUTED, fg_color=theme.SUCCESS_DARK if enabled else theme.SURFACE_ALT)

class _ActivityRow(ctk.CTkFrame):
    def __init__(self, master, title: str, detail: str, when: datetime | None, tone: str):
        super().__init__(master, fg_color="transparent", corner_radius=0)
        self.grid_columnconfigure(1, weight=1)
        color = {"warning": theme.WARNING, "danger": theme.DANGER, "success": theme.SUCCESS}.get(tone, theme.ACCENT)
        ctk.CTkLabel(self, text="●", width=18, text_color=color, font=(theme.FONT, 9)).grid(row=0, column=0, rowspan=2, padx=(0, 8), sticky="n")
        ctk.CTkLabel(self, text=title, text_color=theme.TEXT, font=(theme.FONT, 10, "bold"), anchor="w").grid(row=0, column=1, sticky="ew")
        ctk.CTkLabel(self, text=detail, text_color=theme.TEXT_MUTED, font=(theme.FONT, 9), anchor="w").grid(row=1, column=1, pady=(2, 0), sticky="ew")
        ctk.CTkLabel(self, text=_format_when(when), text_color=theme.TEXT_DIM, font=(theme.FONT, 9), anchor="e").grid(row=0, column=2, rowspan=2, padx=(16, 0), sticky="e")

def _format_when(value: datetime | None) -> str:
    if value is None: return ""
    local = value.astimezone(); now = datetime.now().astimezone()
    if local.date() == now.date(): return f"Today · {local.strftime('%I:%M %p').lstrip('0')}"
    return local.strftime("%b %d · %I:%M %p").replace(" 0", " ")

class DashboardPage(BasePage):
    title = "Home"; subtitle = "A simple view of your protection"

    def __init__(self, master, controller, **kwargs):
        super().__init__(master, controller, **kwargs)
        self.body.grid_columnconfigure((0, 1, 2), weight=1)
        self.status_panel = ctk.CTkFrame(self.body, fg_color=theme.SURFACE, border_width=1, border_color=theme.BORDER, corner_radius=theme.RADIUS)
        self.status_panel.grid(row=0, column=0, columnspan=3, padx=8, pady=(4, 12), sticky="ew"); self.status_panel.grid_columnconfigure(1, weight=1)
        self.status_icon = ctk.CTkLabel(self.status_panel, text="…", width=52, height=52, corner_radius=12, fg_color=theme.SURFACE_ALT, text_color=theme.TEXT_MUTED, font=(theme.FONT, 24, "bold"))
        self.status_icon.grid(row=0, column=0, rowspan=2, padx=(20, 14), pady=20)
        self.status_title = ctk.CTkLabel(self.status_panel, text="Checking protection", text_color=theme.TEXT, font=(theme.FONT, 20, "bold"), anchor="w")
        self.status_title.grid(row=0, column=1, padx=(0, 16), pady=(20, 2), sticky="sw")
        self.status_message = ctk.CTkLabel(self.status_panel, text="AutoGuard is checking protection services.", text_color=theme.TEXT_MUTED, font=(theme.FONT, 11), anchor="w")
        self.status_message.grid(row=1, column=1, padx=(0, 16), pady=(0, 20), sticky="nw")
        self.quick_scan = ctk.CTkButton(self.status_panel, text="Run Quick Scan", width=142, height=38, corner_radius=theme.RADIUS_SMALL, fg_color=theme.ACCENT, hover_color=theme.ACCENT_HOVER, text_color=theme.BG, font=(theme.FONT, 10, "bold"), command=self.controller.start_quick_scan)
        self.quick_scan.grid(row=0, column=2, rowspan=2, padx=20, pady=20, sticky="e")
        self.summaries = {}
        for col, key in enumerate(("Last Scan", "Threats", "Quarantine")):
            block = _SummaryBlock(self.body, key); block.grid(row=1, column=col, padx=8, pady=(0, 14), sticky="nsew"); self.summaries[key] = block
        protection_header = ctk.CTkLabel(self.body, text="Protection", text_color=theme.TEXT, font=(theme.FONT, 15, "bold"), anchor="w")
        protection_header.grid(row=2, column=0, columnspan=3, padx=8, pady=(10, 7), sticky="ew")
        protection_box = ctk.CTkFrame(self.body, fg_color=theme.SURFACE, border_width=1, border_color=theme.BORDER, corner_radius=theme.RADIUS)
        protection_box.grid(row=3, column=0, columnspan=3, padx=8, sticky="ew"); protection_box.grid_columnconfigure(0, weight=1)
        self.protection_rows = {
            "real_time": _ProtectionRow(protection_box, "Real-time protection", "Watches supported folders for new and changed files."),
            "usb": _ProtectionRow(protection_box, "USB protection", "Checks removable drives when they are connected."),
            "scheduled": _ProtectionRow(protection_box, "Scheduled scanning", "Runs automatic Quick and Full scans on schedule."),
        }
        for row, widget in enumerate(self.protection_rows.values()): widget.grid(row=row, column=0, padx=16, pady=(13 if row == 0 else 9, 13), sticky="ew")
        activity_header = ctk.CTkFrame(self.body, fg_color="transparent")
        activity_header.grid(row=4, column=0, columnspan=3, padx=8, pady=(24, 7), sticky="ew"); activity_header.grid_columnconfigure(0, weight=1)
        ctk.CTkLabel(activity_header, text="Recent Activity", text_color=theme.TEXT, font=(theme.FONT, 15, "bold"), anchor="w").grid(row=0, column=0, sticky="w")
        ctk.CTkButton(activity_header, text="View activity", width=92, height=28, corner_radius=theme.RADIUS_SMALL, fg_color="transparent", hover_color=theme.SURFACE_HOVER, text_color=theme.ACCENT, font=(theme.FONT, 9, "bold"), command=lambda: self.controller.navigate_to("activity")).grid(row=0, column=1, sticky="e")
        self.recent = ctk.CTkFrame(self.body, fg_color=theme.SURFACE, border_width=1, border_color=theme.BORDER, corner_radius=theme.RADIUS)
        self.recent.grid(row=5, column=0, columnspan=3, padx=8, pady=(0, 14), sticky="ew"); self.recent.grid_columnconfigure(0, weight=1)

    def on_show(self) -> None:
        self.controller.refresh_dashboard()

    def handle_message(self, message) -> None:
        if message.kind == "dashboard_data": self._render(message.payload["result"])
        elif message.kind == "scan_started":
            self._set_status("scanning", "Scanning", "AutoGuard is currently checking your files.")
            self.quick_scan.configure(state="disabled")
        elif message.kind in ("scan_completed", "scan_batch_completed"): self.controller.refresh_dashboard()

    def _set_status(self, key: str, title: str, message: str) -> None:
        color, background, icon = _STATE_STYLE.get(key, (theme.TEXT_MUTED, theme.SURFACE_ALT, "…"))
        self.status_icon.configure(text=icon, text_color=color, fg_color=background)
        self.status_title.configure(text=title, text_color=color)
        self.status_message.configure(text=message)

    def _render(self, data) -> None:
        state = data["protection_state"]
        self._set_status(state["key"], state["title"], state["message"])
        self.quick_scan.configure(state="disabled" if data["scan_running"] else "normal")
        last_scan = data["last_scan"]; last_scan_detail = last_scan["detail"]
        if last_scan.get("when") is not None: last_scan_detail = f"{_format_when(last_scan['when'])} · {last_scan_detail}"
        self.summaries["Last Scan"].set(last_scan["value"], last_scan_detail)
        review_count = data["threats_needing_review"]
        self.summaries["Threats"].set("No threats need review" if review_count == 0 else f"{review_count} need review", "Nothing needs your attention" if review_count == 0 else "Open Threats to review")
        quarantine_count = data["quarantined_count"]
        self.summaries["Quarantine"].set(f"{quarantine_count} isolated file{'s' if quarantine_count != 1 else ''}", "Stored safely away from their original locations" if quarantine_count else "No files currently isolated")
        protection = data["protection"]
        for key, row in self.protection_rows.items(): row.set(bool(protection[key]))
        for child in self.recent.winfo_children(): child.destroy()
        activities = data["recent_activity"]
        if not activities:
            ctk.CTkLabel(self.recent, text="No recent activity yet.", text_color=theme.TEXT_DIM, font=(theme.FONT, 10)).grid(row=0, column=0, padx=16, pady=20, sticky="w")
            return
        for index, activity in enumerate(activities):
            row = _ActivityRow(self.recent, activity["title"], activity["detail"], activity["when"], activity["tone"])
            row.grid(row=index, column=0, padx=16, pady=(12, 12), sticky="ew")