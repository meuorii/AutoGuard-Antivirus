from __future__ import annotations
import customtkinter as ctk
from app.ui import theme

class BasePage(ctk.CTkFrame):
    title = ""; subtitle = ""
    def __init__(self, master, controller, **kwargs):
        super().__init__(master, fg_color=theme.BG, corner_radius=0, **kwargs)
        self.controller = controller
        self.grid_columnconfigure(0, weight=1); self.grid_rowconfigure(1, weight=1)
        header = ctk.CTkFrame(self, fg_color="transparent")
        header.grid(row=0, column=0, padx=28, pady=(24, 14), sticky="ew")
        ctk.CTkLabel(header, text=self.title, text_color=theme.TEXT, font=(theme.FONT, 24, "bold")).pack(anchor="w")
        if self.subtitle: ctk.CTkLabel(header, text=self.subtitle, text_color=theme.TEXT_MUTED, font=(theme.FONT, 11)).pack(anchor="w", pady=(3, 0))
        self.body = ctk.CTkScrollableFrame(self, fg_color=theme.BG, corner_radius=0)
        self.body.grid(row=1, column=0, padx=20, pady=(0, 20), sticky="nsew")
        self.body.grid_columnconfigure(0, weight=1)
    def on_show(self): pass
    def handle_message(self, message): pass
    def clear_body(self):
        for child in self.body.winfo_children(): child.destroy()