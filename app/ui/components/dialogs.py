from __future__ import annotations
from pathlib import Path
import customtkinter as ctk
from tkinter import filedialog
from app.ui import theme

class ConfirmDialog(ctk.CTkToplevel):
    def __init__(self, master, title: str, message: str, confirm_text: str = "Confirm", danger: bool = False, on_confirm=None):
        super().__init__(master); self.title(title); self.geometry("430x220"); self.resizable(False, False)
        self.configure(fg_color=theme.BG); self.transient(master); self.grab_set()
        ctk.CTkLabel(self, text=title, font=(theme.FONT, 18, "bold"), text_color=theme.TEXT).pack(anchor="w", padx=24, pady=(24, 8))
        ctk.CTkLabel(self, text=message, wraplength=375, justify="left", anchor="w", font=(theme.FONT, 11), text_color=theme.TEXT_MUTED).pack(fill="x", padx=24)
        row = ctk.CTkFrame(self, fg_color="transparent"); row.pack(fill="x", padx=24, pady=24, side="bottom")
        ctk.CTkButton(row, text="Cancel", fg_color=theme.SURFACE_ALT, hover_color=theme.SURFACE_HOVER, command=self.destroy).pack(side="right")
        def go():
            self.destroy()
            if on_confirm: on_confirm()
        ctk.CTkButton(row, text=confirm_text, fg_color=theme.DANGER if danger else theme.ACCENT, hover_color=theme.DANGER_DARK if danger else theme.ACCENT_HOVER, text_color="#07110F" if not danger else theme.TEXT, command=go).pack(side="right", padx=(0, 8))

class RestoreDialog(ctk.CTkToplevel):
    def __init__(self, master, original_path: str, on_restore):
        super().__init__(master); self.title("Restore quarantined file"); self.geometry("560x300")
        self.resizable(False, False); self.configure(fg_color=theme.BG); self.transient(master); self.grab_set()
        ctk.CTkLabel(self, text="Restore file", font=(theme.FONT, 19, "bold"), text_color=theme.TEXT).pack(anchor="w", padx=24, pady=(24, 5))
        ctk.CTkLabel(self, text="AutoGuard will verify the quarantine object and re-evaluate it with current signatures before restoration.", wraplength=505, justify="left", text_color=theme.TEXT_MUTED, font=(theme.FONT, 11)).pack(anchor="w", padx=24)
        self.entry = ctk.CTkEntry(self, fg_color=theme.SURFACE, border_color=theme.BORDER, text_color=theme.TEXT)
        self.entry.pack(fill="x", padx=24, pady=(18, 8)); self.entry.insert(0, original_path)
        def browse():
            initial = Path(self.entry.get())
            chosen = filedialog.asksaveasfilename(initialdir=str(initial.parent), initialfile=initial.name)
            if chosen: self.entry.delete(0, "end"); self.entry.insert(0, chosen)
        ctk.CTkButton(self, text="Choose another destination", fg_color=theme.SURFACE_ALT, hover_color=theme.SURFACE_HOVER, command=browse).pack(anchor="w", padx=24)
        row = ctk.CTkFrame(self, fg_color="transparent"); row.pack(fill="x", padx=24, pady=24, side="bottom")
        ctk.CTkButton(row, text="Cancel", fg_color=theme.SURFACE_ALT, hover_color=theme.SURFACE_HOVER, command=self.destroy).pack(side="right")
        def restore():
            dest = self.entry.get().strip(); self.destroy(); on_restore(dest or None)
        ctk.CTkButton(row, text="Verify & restore", fg_color=theme.ACCENT, hover_color=theme.ACCENT_HOVER, text_color="#07110F", command=restore).pack(side="right", padx=(0, 8))