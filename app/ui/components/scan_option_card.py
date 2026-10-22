from __future__ import annotations
from collections.abc import Callable
import customtkinter as ctk
from app.ui import theme

class ScanOptionCard(ctk.CTkFrame):

    def __init__(self, master, *, title: str, description: str, detail: str = "", recommended: bool = False, actions: tuple[tuple[str, Callable[[], None], bool], ...] = (), **kwargs):
        super().__init__(master, fg_color=theme.SURFACE, border_width=1, border_color=theme.BORDER, corner_radius=theme.RADIUS, **kwargs)
        self.grid_columnconfigure(0, weight=1)
        header = ctk.CTkFrame(self, fg_color="transparent", corner_radius=0)
        header.grid(row=0, column=0, padx=18, pady=(16, 5), sticky="ew"); header.grid_columnconfigure(0, weight=1)
        theme.Label(header, text=title, text_color=theme.TEXT, font=theme.font("card", "bold", theme.FONT), anchor="w").grid(row=0, column=0, sticky="w")
        if recommended:
            theme.Label(header, text="Recommended", height=24, corner_radius=6, fg_color=theme.ACCENT_DARK, text_color=theme.ACCENT, font=theme.font("secondary", "bold", theme.FONT), padx=9).grid(row=0, column=1, padx=(10, 0), sticky="e")
        theme.Label(self, text=description, text_color=theme.TEXT_MUTED, font=theme.font("body", "normal", theme.FONT), anchor="w", justify="left", wraplength=820).grid(row=1, column=0, padx=18, sticky="ew")
        if detail:
            theme.Label(self, text=detail, text_color=theme.TEXT_DIM, font=theme.font("body", "normal", theme.FONT), anchor="w", justify="left", wraplength=820).grid(row=2, column=0, padx=18, pady=(7, 0), sticky="ew")
        actions_frame = ctk.CTkFrame(self, fg_color="transparent", corner_radius=0)
        actions_frame.grid(row=3, column=0, padx=18, pady=(14, 16), sticky="ew")
        for text, command, primary in actions:
            theme.Button(
                actions_frame, text=text, height=34, corner_radius=theme.RADIUS_SMALL,
                fg_color=theme.ACCENT if primary else theme.SURFACE_ALT,
                hover_color=theme.ACCENT_HOVER if primary else theme.SURFACE_HOVER,
                text_color=theme.BG if primary else theme.TEXT,
                font=theme.font("body", "bold", theme.FONT), command=command
            ).pack(side="left", padx=(0, 8))