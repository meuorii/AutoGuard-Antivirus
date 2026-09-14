from __future__ import annotations
import customtkinter as ctk
from app.ui import theme

class NotificationCenter:
    def __init__(self, window):
        self.window = window; self._active = []
    def show(self, title: str, message: str, level: str = "info", duration_ms: int = 4200):
        color, _ = theme.STATUS_COLORS.get(level.lower(), (theme.INFO, theme.INFO_DARK))
        box = ctk.CTkFrame(self.window, fg_color=theme.SURFACE_ALT, border_width=1, border_color=theme.BORDER, corner_radius=10)
        box.place(relx=1.0, x=-24, y=24 + len(self._active) * 82, anchor="ne")
        ctk.CTkFrame(box, width=4, fg_color=color, corner_radius=2).pack(side="left", fill="y")
        body = ctk.CTkFrame(box, fg_color="transparent"); body.pack(side="left", padx=12, pady=10)
        ctk.CTkLabel(body, text=title, font=(theme.FONT, 11, "bold"), text_color=theme.TEXT, anchor="w").pack(anchor="w")
        ctk.CTkLabel(body, text=message, font=(theme.FONT, 10), text_color=theme.TEXT_MUTED, wraplength=310, justify="left").pack(anchor="w")
        self._active.append(box)
        def close():
            if box in self._active: self._active.remove(box)
            box.destroy()
            for i, item in enumerate(self._active): item.place_configure(y=24 + i * 82)
        self.window.after(duration_ms, close)