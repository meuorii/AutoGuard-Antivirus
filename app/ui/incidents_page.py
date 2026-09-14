from __future__ import annotations
import customtkinter as ctk
from app.ui.base_page import BasePage
from app.ui import theme

class IncidentsPage(BasePage):
    title = "Incidents"
    subtitle = "Matching threat observations grouped by exact malicious content"
    def on_show(self): self.controller.load_incidents()
    def handle_message(self, message):
        if message.kind == "incidents_data": self._render(message.payload["result"])
        elif message.kind == "incident_verified": self.controller.load_incidents()

    def _render(self, rows):
        self.clear_body(); self.body.grid_columnconfigure(0, weight=1)
        if not rows: ctk.CTkLabel(self.body, text="No threat incidents recorded.", text_color=theme.TEXT_DIM).grid(row=0, column=0, pady=30); return
        for idx, row in enumerate(rows):
            details = row["details"]; inc = details.incident; verification = row.get("verification")
            card = ctk.CTkFrame(self.body, fg_color=theme.SURFACE, border_width=1, border_color=theme.BORDER, corner_radius=theme.RADIUS)
            card.grid(row=idx, column=0, padx=8, pady=6, sticky="ew"); card.grid_columnconfigure(0, weight=1)
            color, _ = theme.STATUS_COLORS.get(inc.status.value.lower(), (theme.TEXT_MUTED, theme.SURFACE_ALT))
            ctk.CTkLabel(card, text=f"Incident {inc.id[:8]}", font=(theme.FONT, 14, "bold"), text_color=theme.TEXT, anchor="w").grid(row=0, column=0, padx=16, pady=(14, 2), sticky="w")
            ctk.CTkLabel(card, text=inc.status.value, text_color=color, font=(theme.FONT, 10, "bold")).grid(row=0, column=1, padx=16, pady=(14, 2), sticky="e")
            ctk.CTkLabel(card, text=f"SHA-256  {inc.sha256}", font=(theme.FONT_MONO, 9), text_color=theme.TEXT_DIM, anchor="w").grid(row=1, column=0, columnspan=2, padx=16, sticky="ew")
            ctk.CTkLabel(card, text=f"{len(details.files)} observed locations · {inc.detection_count} detections · {inc.reappearance_count} reappearances", font=(theme.FONT, 10), text_color=theme.TEXT_MUTED, anchor="w").grid(row=2, column=0, columnspan=2, padx=16, pady=(6, 2), sticky="ew")
            latest = verification.status.value if verification else "Not verified"
            ctk.CTkLabel(card, text=f"Cleanup verification: {latest}", font=(theme.FONT, 10), text_color=theme.TEXT_MUTED, anchor="w").grid(row=3, column=0, padx=16, pady=(0, 12), sticky="w")
            ctk.CTkButton(card, text="Verify cleanup", width=105, height=28, fg_color=theme.SURFACE_ALT, hover_color=theme.SURFACE_HOVER, text_color=theme.TEXT, command=lambda incident_id=inc.id: self.controller.verify_incident_cleanup(incident_id)).grid(row=3, column=1, padx=16, pady=(0, 12), sticky="e")
            timeline = ctk.CTkFrame(card, fg_color=theme.BG, corner_radius=8)
            timeline.grid(row=4, column=0, columnspan=2, padx=16, pady=(0, 14), sticky="ew")
            for eidx, event in enumerate(details.events[-6:]):
                text = f"{event.occurred_at.strftime('%Y-%m-%d %H:%M')}  ·  {event.event_type.value.replace('_', ' ').title()}"
                if event.path: text += f"  ·  {event.path}"
                ctk.CTkLabel(timeline, text=text, font=(theme.FONT, 9), text_color=theme.TEXT_DIM, anchor="w", justify="left").grid(row=eidx, column=0, padx=10, pady=3, sticky="ew")