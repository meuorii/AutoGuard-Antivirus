from __future__ import annotations
import customtkinter as ctk
from app.ui.base_page import BasePage
from app.ui import theme

class ThreatTrailPage(BasePage):
    title = "Threat Trail"
    subtitle = "Observed locations over time — this timeline does not prove infection origin or direction"
    def on_show(self): self.controller.load_threat_trail()
    def handle_message(self, message):
        if message.kind == "threat_trail_data": self._render(message.payload["result"])

    def _render(self, rows):
        self.clear_body(); self.body.grid_columnconfigure(0, weight=1)
        notice = ctk.CTkFrame(self.body, fg_color=theme.INFO_DARK, border_width=1, border_color=theme.BORDER, corner_radius=10)
        notice.grid(row=0, column=0, padx=8, pady=(4, 12), sticky="ew")
        ctk.CTkLabel(notice, text="Evidence note", font=(theme.FONT, 11, "bold"), text_color=theme.INFO).pack(anchor="w", padx=14, pady=(10, 2))
        ctk.CTkLabel(notice, text="Sequence means ‘observed at this time’, not ‘spread from here’. AutoGuard does not infer causality from path order.", font=(theme.FONT, 10), text_color=theme.TEXT_MUTED, wraplength=850, justify="left").pack(anchor="w", padx=14, pady=(0, 10))
        for idx, row in enumerate(rows):
            line = ctk.CTkFrame(self.body, fg_color=theme.SURFACE if idx % 2 == 0 else theme.SURFACE_ALT, corner_radius=8)
            line.grid(row=idx + 1, column=0, padx=8, pady=3, sticky="ew"); line.grid_columnconfigure(1, weight=1)
            ctk.CTkLabel(line, text="●", text_color=theme.ACCENT, font=(theme.FONT, 10)).grid(row=0, column=0, rowspan=2, padx=(12, 8), pady=10)
            ctk.CTkLabel(line, text=row["path"], text_color=theme.TEXT, font=(theme.FONT, 10, "bold"), anchor="w").grid(row=0, column=1, pady=(8, 1), sticky="ew")
            ctk.CTkLabel(line, text=f"{row['observed_at']} · {row['source']} · SHA {row['sha256'][:12]}…", text_color=theme.TEXT_DIM, font=(theme.FONT, 9), anchor="w").grid(row=1, column=1, pady=(0, 8), sticky="ew")