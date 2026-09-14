from __future__ import annotations
import customtkinter as ctk
from app.ui import theme

NAV_ITEMS = (("dashboard", "Dashboard"), ("scan", "Scan"), ("incidents", "Incidents"), ("threat_trail", "Threat Trail"), ("quarantine", "Quarantine"), ("history", "History"), ("settings", "Settings"))

class Sidebar(ctk.CTkFrame):
    def __init__(self, master, on_navigate, **kwargs):
        super().__init__(master, width=theme.SIDEBAR_WIDTH, fg_color=theme.SIDEBAR, corner_radius=0, **kwargs)
        self.grid_propagate(False); self.grid_rowconfigure(9, weight=1)
        brand = ctk.CTkFrame(self, fg_color="transparent"); brand.grid(row=0, column=0, padx=18, pady=(24, 26), sticky="ew")
        ctk.CTkLabel(brand, text="A", width=34, height=34, corner_radius=10, fg_color=theme.ACCENT_DARK, text_color=theme.ACCENT, font=(theme.FONT, 16, "bold")).pack(side="left")
        block = ctk.CTkFrame(brand, fg_color="transparent"); block.pack(side="left", padx=(10, 0))
        ctk.CTkLabel(block, text="AutoGuard", text_color=theme.TEXT, font=(theme.FONT, 16, "bold")).pack(anchor="w")
        ctk.CTkLabel(block, text="Automatic protection", text_color=theme.TEXT_DIM, font=(theme.FONT, 9)).pack(anchor="w")
        self.buttons = {}
        for idx, (key, label) in enumerate(NAV_ITEMS, start=1):
            button = ctk.CTkButton(self, text=label, anchor="w", height=38, corner_radius=8, fg_color="transparent", hover_color=theme.SURFACE_HOVER, text_color=theme.TEXT_MUTED, font=(theme.FONT, 11, "bold"), command=lambda k=key: on_navigate(k))
            button.grid(row=idx, column=0, padx=12, pady=2, sticky="ew"); self.buttons[key] = button
        footer = ctk.CTkFrame(self, fg_color=theme.SURFACE, border_width=1, border_color=theme.BORDER, corner_radius=10)
        footer.grid(row=10, column=0, padx=12, pady=16, sticky="sew")
        ctk.CTkLabel(footer, text="Protection", text_color=theme.TEXT_DIM, font=(theme.FONT, 9)).pack(anchor="w", padx=12, pady=(10, 0))
        self.protection = ctk.CTkLabel(footer, text="●  Checking", text_color=theme.WARNING, font=(theme.FONT, 10, "bold"))
        self.protection.pack(anchor="w", padx=12, pady=(2, 10)); self.set_active("dashboard")

    def set_active(self, key):
        for name, btn in self.buttons.items():
            btn.configure(fg_color=theme.ACCENT_DARK if name == key else "transparent", text_color=theme.ACCENT if name == key else theme.TEXT_MUTED)

    def set_protection(self, text, status="running"):
        color, _ = theme.STATUS_COLORS.get(status.lower(), (theme.TEXT_MUTED, theme.SURFACE_ALT))
        self.protection.configure(text=f"●  {text}", text_color=color)