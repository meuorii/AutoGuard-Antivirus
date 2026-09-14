from __future__ import annotations
import customtkinter as ctk
from app.ui.base_page import BasePage
from app.ui import theme

class SettingsPage(BasePage):
    title = "Settings"
    subtitle = "Runtime protection paths and scheduling configuration"
    def on_show(self): self._render(self.controller.settings_snapshot())

    def _render(self, data):
        self.clear_body(); self.body.grid_columnconfigure(0, weight=1)
        sections = [
            ("Protection", [("File monitor", "Enabled" if data['file_monitor_enabled'] else "Disabled"), ("USB monitor", "Enabled" if data['usb_monitor_enabled'] else "Disabled"), ("Maximum file size", f"{data['max_file_size_bytes'] / (1024 * 1024):.0f} MiB")]),
            ("Scheduled scans", [("Quick scan", f"Every {data['quick_hours']:g} hours"), ("Full scan", f"Every {data['full_days']:g} days")]),
            ("Storage", [("Database", data['database']), ("Quarantine", data['quarantine'])]),
        ]
        r = 0
        for title, items in sections:
            frame = ctk.CTkFrame(self.body, fg_color=theme.SURFACE, border_width=1, border_color=theme.BORDER, corner_radius=theme.RADIUS)
            frame.grid(row=r, column=0, padx=8, pady=6, sticky="ew"); frame.grid_columnconfigure(1, weight=1); r += 1
            ctk.CTkLabel(frame, text=title, font=(theme.FONT, 14, "bold"), text_color=theme.TEXT).grid(row=0, column=0, columnspan=2, padx=16, pady=(14, 8), sticky="w")
            for i, (k, v) in enumerate(items, 1):
                ctk.CTkLabel(frame, text=k, font=(theme.FONT, 10), text_color=theme.TEXT_MUTED).grid(row=i, column=0, padx=16, pady=5, sticky="w")
                ctk.CTkLabel(frame, text=str(v), font=(theme.FONT, 10), text_color=theme.TEXT, anchor="e", wraplength=650).grid(row=i, column=1, padx=16, pady=5, sticky="e")
            ctk.CTkLabel(frame, text="", height=4).grid(row=len(items) + 1, column=0)
        paths = ctk.CTkFrame(self.body, fg_color=theme.SURFACE, border_width=1, border_color=theme.BORDER, corner_radius=theme.RADIUS)
        paths.grid(row=r, column=0, padx=8, pady=6, sticky="ew")
        ctk.CTkLabel(paths, text="Monitored locations", font=(theme.FONT, 14, "bold"), text_color=theme.TEXT).pack(anchor="w", padx=16, pady=(14, 6))
        for p in data['monitor_paths']: ctk.CTkLabel(paths, text=p, font=(theme.FONT_MONO, 9), text_color=theme.TEXT_MUTED).pack(anchor="w", padx=16, pady=3)
        ctk.CTkLabel(paths, text="Changes to protection paths/schedules are currently applied at startup. Full settings editing can be added after the UI foundation is stable.", wraplength=850, justify="left", font=(theme.FONT, 9), text_color=theme.TEXT_DIM).pack(anchor="w", padx=16, pady=(8, 14))