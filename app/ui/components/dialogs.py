"""Readable confirmation dialog shared by destructive UI actions."""
from __future__ import annotations

import customtkinter as ctk
from app.ui import theme


class ConfirmDialog(ctk.CTkToplevel):
    def __init__(self, master, title: str, message: str, confirm_text: str = "Confirm", danger: bool = False, on_confirm=None):
        super().__init__(master)
        self._decision_made = False
        self._on_confirm = on_confirm
        self.title(title)
        self.geometry("650x480")
        self.minsize(500, 400)
        self.resizable(True, True)
        self.configure(fg_color=theme.BG)
        self.transient(master.winfo_toplevel())
        self.grab_set()
        self.protocol("WM_DELETE_WINDOW", self.destroy)
        self.bind("<Escape>", lambda event: self.destroy())
        actions = ctk.CTkFrame(self, fg_color="transparent")
        actions.pack(fill="x", padx=24, pady=24, side="bottom")
        content = ctk.CTkScrollableFrame(self, fg_color=theme.BG)
        content.pack(fill="both", expand=True, padx=16, pady=(16, 0))
        theme.Label(content, text=title, font=theme.font("section", "bold"), text_color=theme.TEXT).pack(anchor="w", padx=8, pady=(8, 8))
        theme.Label(content, text=message, justify="left", anchor="w", font=theme.font("warning" if danger else "body"), text_color=theme.TEXT).pack(fill="x", padx=8)
        self.cancel_button = theme.Button(actions, text="Cancel", fg_color=theme.SURFACE_ALT, hover_color=theme.SURFACE_HOVER, command=self.destroy)
        self.cancel_button.pack(side="right")
        self.cancel_button.focus_set()
        self.confirm_button = theme.Button(actions, text=confirm_text, fg_color=theme.DANGER if danger else theme.ACCENT,
                                          hover_color=theme.DANGER_DARK if danger else theme.ACCENT_HOVER,
                                          text_color=theme.BG, command=self.confirm)
        self.confirm_button.pack(side="right", padx=(0, 8))

    def confirm(self):
        if self._decision_made:
            return
        self._decision_made = True
        super().destroy()
        if self._on_confirm:
            self._on_confirm()

    def destroy(self):
        self._decision_made = True
        super().destroy()
