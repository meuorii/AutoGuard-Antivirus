from __future__ import annotations
import customtkinter as ctk
import tkinter as tk
from app.ui import theme

class NotificationCenter:
    def __init__(self, window):
        self.window = window; self._active = []
    def _restack(self, event=None):
        offset = 24
        for item in self._active:
            item.place_configure(y=offset)
            offset += int(item._reverse_widget_scaling(item.winfo_reqheight())) + 12

    def show(self, title: str, message: str, level: str = "info", duration_ms: int = 8000):
        color, _ = theme.STATUS_COLORS.get(level.lower(), (theme.INFO, theme.INFO_DARK))
        box = ctk.CTkFrame(self.window, fg_color=theme.SURFACE_ALT, border_width=1, border_color=theme.BORDER, corner_radius=10)
        box.place(relx=1.0, x=-24, y=24 + len(self._active) * 82, anchor="ne")
        ctk.CTkFrame(box, width=4, fg_color=color, corner_radius=2).pack(side="left", fill="y")
        body = ctk.CTkFrame(box, fg_color="transparent"); body.pack(side="left", padx=12, pady=10)
        theme.Label(body, text=title, font=theme.font("body", "bold", theme.FONT), text_color=theme.TEXT, anchor="w").pack(anchor="w")
        theme.Label(body, text=message, font=theme.font("body", "normal", theme.FONT), text_color=theme.TEXT_MUTED, wraplength=310, justify="left").pack(anchor="w")
        self._active.append(box)
        tk.Frame.bind(box, "<Configure>", self._restack, add="+")
        self.window.after_idle(self._restack)
        def close():
            if box in self._active: self._active.remove(box)
            box.destroy()
            self._restack()
        self.window.after(duration_ms, close)
