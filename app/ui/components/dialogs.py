from __future__ import annotations
from pathlib import Path
import customtkinter as ctk
from tkinter import filedialog
from app.ui import theme


class ConfirmDialog(ctk.CTkToplevel):
    def __init__(self, master, title: str, message: str, confirm_text: str = "Confirm", danger: bool = False, on_confirm=None):
        super().__init__(master)
        self.title(title); self.geometry("650x480"); self.minsize(500, 400); self.resizable(True, True)
        self.configure(fg_color=theme.BG); self.transient(master); self.grab_set()
        row=ctk.CTkFrame(self,fg_color="transparent"); row.pack(fill="x",padx=24,pady=24,side="bottom")
        content = ctk.CTkScrollableFrame(self, fg_color=theme.BG)
        content.pack(fill="both", expand=True, padx=16, pady=(16, 0))
        theme.Label(content, text=title, font=theme.font("section", "bold"), text_color=theme.TEXT).pack(anchor="w", padx=8,pady=(8,8))
        theme.Label(content, text=message, justify="left", anchor="w", font=theme.font("warning" if danger else "body"), text_color=theme.TEXT).pack(fill="x", padx=8)
        cancel = theme.Button(row,text="Cancel",fg_color=theme.SURFACE_ALT,hover_color=theme.SURFACE_HOVER,command=self.destroy)
        cancel.pack(side="right")
        cancel.focus_set()
        self.bind("<Escape>", lambda event: self.destroy())
        def go():
            self.destroy()
            if on_confirm: on_confirm()
        theme.Button(row,text=confirm_text,fg_color=theme.DANGER if danger else theme.ACCENT,
                      hover_color=theme.DANGER_DARK if danger else theme.ACCENT_HOVER,
                      text_color="#07110F",command=go).pack(side="right",padx=(0,8))


class RestoreDialog(ctk.CTkToplevel):
    def __init__(self, master, original_path: str, on_restore):
        super().__init__(master); self.title("Restore quarantined file"); self.geometry("700x520")
        self.minsize(560, 460)
        self.resizable(True,True); self.configure(fg_color=theme.BG); self.transient(master); self.grab_set()
        row=ctk.CTkFrame(self,fg_color="transparent"); row.pack(fill="x",padx=24,pady=24,side="bottom")
        content = ctk.CTkScrollableFrame(self, fg_color=theme.BG)
        content.pack(fill="both", expand=True, padx=8, pady=(8, 0))
        theme.Label(content,text="Restore file",font=theme.font("section", "bold", theme.FONT),text_color=theme.TEXT).pack(anchor="w",padx=24,pady=(24,5))
        theme.Label(content,text="AutoGuard will verify the isolated file and re-evaluate it with current signatures before restoration.",justify="left",text_color=theme.TEXT_MUTED,font=theme.font("body", "normal", theme.FONT)).pack(anchor="w",padx=24)
        self.entry=ctk.CTkEntry(content,fg_color=theme.SURFACE,border_color=theme.BORDER,text_color=theme.TEXT, font=theme.font(), height=44)
        self.entry.pack(fill="x",padx=24,pady=(18,8)); self.entry.insert(0,original_path)
        def browse():
            initial=Path(self.entry.get())
            chosen=filedialog.asksaveasfilename(initialdir=str(initial.parent),initialfile=initial.name)
            if chosen: self.entry.delete(0,"end"); self.entry.insert(0,chosen)
        theme.Button(content,text="Choose another destination",fg_color=theme.SURFACE_ALT,hover_color=theme.SURFACE_HOVER,command=browse).pack(anchor="w",padx=24)
        self.bind("<Escape>", lambda event: self.destroy())
        self.entry.focus_set()
        theme.Button(row,text="Cancel",fg_color=theme.SURFACE_ALT,hover_color=theme.SURFACE_HOVER,command=self.destroy).pack(side="right")
        def restore():
            dest=self.entry.get().strip(); self.destroy(); on_restore(dest or None)
        theme.Button(row,text="Verify & restore",fg_color=theme.ACCENT,hover_color=theme.ACCENT_HOVER,text_color="#07110F",command=restore).pack(side="right",padx=(0,8))
