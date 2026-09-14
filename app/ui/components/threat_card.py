from __future__ import annotations
import os, customtkinter as ctk; from app.ui import theme

class ThreatCard(ctk.CTkFrame):
    def __init__(self, master, *, path: str, status: str, reason: str, meta: str = "", command=None, **kwargs):
        super().__init__(master, fg_color=theme.SURFACE, border_width=1, border_color=theme.BORDER, corner_radius=theme.RADIUS_SMALL, **kwargs); self.grid_columnconfigure(0, weight=1); name, (color, bg) = os.path.basename(path) or path, theme.STATUS_COLORS.get(status.lower(), (theme.TEXT_MUTED, theme.SURFACE_ALT))
        top = ctk.CTkFrame(self, fg_color="transparent"); top.grid(row=0, column=0, padx=14, pady=(12, 2), sticky="ew"); top.grid_columnconfigure(0, weight=1)
        ctk.CTkLabel(top, text=name, text_color=theme.TEXT, font=(theme.FONT, 13, "bold"), anchor="w").grid(row=0, column=0, sticky="ew")
        ctk.CTkLabel(top, text=status.replace("_", " ").title(), text_color=color, fg_color=bg, corner_radius=6, padx=8, pady=3, font=(theme.FONT, 10, "bold")).grid(row=0, column=1, padx=(8, 0))
        ctk.CTkLabel(self, text=path, text_color=theme.TEXT_DIM, font=(theme.FONT, 10), anchor="w").grid(row=1, column=0, padx=14, sticky="ew")
        ctk.CTkLabel(self, text=reason, text_color=theme.TEXT_MUTED, font=(theme.FONT, 11), anchor="w", justify="left", wraplength=650).grid(row=2, column=0, padx=14, pady=(5, 2), sticky="ew")
        if meta: ctk.CTkLabel(self, text=meta, text_color=theme.TEXT_DIM, font=(theme.FONT, 10), anchor="w").grid(row=3, column=0, padx=14, pady=(1, 10), sticky="ew")
        if command: ctk.CTkButton(self, text="Inspect", width=76, height=28, fg_color=theme.SURFACE_ALT, hover_color=theme.SURFACE_HOVER, text_color=theme.TEXT, command=command).grid(row=0, column=1, rowspan=3, padx=12, pady=12)