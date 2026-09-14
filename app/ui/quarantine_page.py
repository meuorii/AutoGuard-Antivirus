from __future__ import annotations
import customtkinter as ctk
from app.ui.base_page import BasePage
from app.ui import theme
from app.ui.components import ConfirmDialog, RestoreDialog

class QuarantinePage(BasePage):
    title = "Quarantine"
    subtitle = "Isolated objects and recovery controls"
    def on_show(self): self.controller.load_quarantine()
    def handle_message(self, message):
        if message.kind == "quarantine_data": self._render(message.payload["result"])
        elif message.kind in ("quarantine_verified", "recovery_completed", "quarantine_deleted"): self.controller.load_quarantine()

    def _render(self, items):
        self.clear_body(); self.body.grid_columnconfigure(0, weight=1)
        if not items: ctk.CTkLabel(self.body, text="Quarantine is empty.", text_color=theme.TEXT_DIM).grid(row=0, column=0, pady=30); return
        for idx, item in enumerate(items):
            card = ctk.CTkFrame(self.body, fg_color=theme.SURFACE, border_width=1, border_color=theme.BORDER, corner_radius=theme.RADIUS)
            card.grid(row=idx, column=0, padx=8, pady=6, sticky="ew"); card.grid_columnconfigure(0, weight=1)
            ctk.CTkLabel(card, text=item.original_path.split('\\')[-1].split('/')[-1], text_color=theme.TEXT, font=(theme.FONT, 13, "bold"), anchor="w").grid(row=0, column=0, padx=16, pady=(13, 2), sticky="ew")
            ctk.CTkLabel(card, text=f"{item.state.value} · Integrity {item.integrity_status.value} · {item.sha256[:16]}…", text_color=theme.TEXT_MUTED, font=(theme.FONT, 9), anchor="w").grid(row=1, column=0, padx=16, sticky="ew")
            ctk.CTkLabel(card, text=item.original_path, text_color=theme.TEXT_DIM, font=(theme.FONT, 9), anchor="w").grid(row=2, column=0, padx=16, pady=(2, 10), sticky="ew")
            row = ctk.CTkFrame(card, fg_color="transparent"); row.grid(row=0, column=1, rowspan=3, padx=14, pady=12)
            ctk.CTkButton(row, text="Verify", width=72, height=28, fg_color=theme.SURFACE_ALT, hover_color=theme.SURFACE_HOVER, command=lambda q=item.quarantine_id: self.controller.verify_quarantine(q)).pack(side="left", padx=3)
            ctk.CTkButton(row, text="Restore", width=72, height=28, fg_color=theme.SURFACE_ALT, hover_color=theme.SURFACE_HOVER, command=lambda it=item: self._restore(it)).pack(side="left", padx=3)
            ctk.CTkButton(row, text="Delete", width=68, height=28, fg_color=theme.DANGER_DARK, hover_color=theme.DANGER, text_color=theme.DANGER, command=lambda it=item: self._delete(it)).pack(side="left", padx=3)

    def _restore(self, item): RestoreDialog(self, item.original_path, lambda dest: self.controller.restore_quarantine(item.quarantine_id, dest))
    def _delete(self, item): ConfirmDialog(self, "Permanently delete quarantine object", f"This removes the isolated .agq payload for:\n\n{item.original_path}\n\nAudit metadata is retained, but recovery will no longer be possible.", confirm_text="Delete permanently", danger=True, on_confirm=lambda: self.controller.delete_quarantine(item.quarantine_id))