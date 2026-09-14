from __future__ import annotations
import customtkinter as ctk
from app.ui import theme

class StatusCard(ctk.CTkFrame):
    def __init__(self, master, title: str, value: str = "—", subtitle: str = "", status: str = "idle", **kwargs):
        super().__init__(master, fg_color=theme.SURFACE, border_width=1, border_color=theme.BORDER, corner_radius=theme.RADIUS, **kwargs)
        self.grid_columnconfigure(0, weight=1)
        self._title = ctk.CTkLabel(self, text=title, text_color=theme.TEXT_MUTED, font=(theme.FONT, 12))
        self._title.grid(row=0, column=0, padx=16, pady=(15, 3), sticky="w")
        self._dot = ctk.CTkLabel(self, text="●", width=16, font=(theme.FONT, 11))
        self._dot.grid(row=0, column=1, padx=(0, 14), pady=(15, 3), sticky="e")
        self._value = ctk.CTkLabel(self, text=value, text_color=theme.TEXT, font=(theme.FONT, 22, "bold"))
        self._value.grid(row=1, column=0, columnspan=2, padx=16, pady=(2, 2), sticky="w")
        self._subtitle = ctk.CTkLabel(self, text=subtitle, text_color=theme.TEXT_DIM, font=(theme.FONT, 11), anchor="w")
        self._subtitle.grid(row=2, column=0, columnspan=2, padx=16, pady=(0, 15), sticky="ew")
        self.set(value, subtitle, status)

    def set(self, value: str, subtitle: str = "", status: str = "idle") -> None:
        fg, _ = theme.STATUS_COLORS.get(status.lower(), (theme.TEXT_MUTED, theme.SURFACE_ALT))
        self._value.configure(text=value); self._subtitle.configure(text=subtitle); self._dot.configure(text_color=fg)