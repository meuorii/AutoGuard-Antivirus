from __future__ import annotations
import customtkinter as ctk
from app.ui.base_page import BasePage
from app.ui import theme

class HistoryPage(BasePage):
    title = "History"
    subtitle = "Persisted scan sessions and evidence-based reports"
    def on_show(self): self.controller.load_history()
    def handle_message(self, message):
        if message.kind == "history_data": self._render(message.payload["result"])
        elif message.kind == "scan_report_data": self._show_report(message.payload["result"])

    def _render(self, sessions):
        self.clear_body(); self.body.grid_columnconfigure(0, weight=1)
        for idx, s in enumerate(sessions):
            card = ctk.CTkFrame(self.body, fg_color=theme.SURFACE, border_width=1, border_color=theme.BORDER, corner_radius=10)
            card.grid(row=idx, column=0, padx=8, pady=4, sticky="ew"); card.grid_columnconfigure(0, weight=1)
            ctk.CTkLabel(card, text=f"{s.scan_type.value.title()} scan", font=(theme.FONT, 12, "bold"), text_color=theme.TEXT, anchor="w").grid(row=0, column=0, padx=14, pady=(10, 1), sticky="ew")
            ctk.CTkLabel(card, text=f"{s.started_at.strftime('%Y-%m-%d %H:%M:%S')} · {s.status.value} · {s.source_path}", font=(theme.FONT, 9), text_color=theme.TEXT_DIM, anchor="w").grid(row=1, column=0, padx=14, pady=(0, 10), sticky="ew")
            ctk.CTkButton(card, text="Report", width=72, height=28, fg_color=theme.SURFACE_ALT, hover_color=theme.SURFACE_HOVER, command=lambda sid=s.id: self.controller.load_scan_report(sid)).grid(row=0, column=1, rowspan=2, padx=14, pady=10)

    def _show_report(self, report):
        dialog = ctk.CTkToplevel(self); dialog.title("Scan report"); dialog.geometry("780x620"); dialog.configure(fg_color=theme.BG); dialog.transient(self.winfo_toplevel())
        box = ctk.CTkTextbox(dialog, fg_color=theme.SURFACE, border_width=1, border_color=theme.BORDER, text_color=theme.TEXT, font=(theme.FONT_MONO, 10), wrap="word")
        box.pack(fill="both", expand=True, padx=18, pady=18); box.insert("1.0", report.to_text()); box.configure(state="disabled")