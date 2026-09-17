from __future__ import annotations
import customtkinter as ctk
from app.ui import theme
from app.ui.base_page import BasePage

_SECTION_ORDER = ("Needs attention", "Contained", "Resolved")
_STATUS_STYLE = {"attention": (theme.WARNING, theme.WARNING_DARK), "reviewing": (theme.WARNING, theme.WARNING_DARK), "contained": (theme.SUCCESS, theme.SUCCESS_DARK), "reappeared": (theme.WARNING, theme.WARNING_DARK), "restored": (theme.INFO, theme.INFO_DARK), "resolved": (theme.TEXT_MUTED, theme.SURFACE_ALT)}

class ThreatsPage(BasePage):
    title = "Threats"
    subtitle = "Review threats AutoGuard has observed and handled"

    def __init__(self, master, controller, **kwargs):
        super().__init__(master, controller, **kwargs); self._loading = False; self._render_loading()

    def on_show(self) -> None:
        self._loading = True; self._render_loading(); self.controller.load_threats()

    def handle_message(self, message) -> None:
        if message.kind == "threats_data": self._loading = False; self._render(message.payload.get("result", ()))
        elif message.kind in {"incident_verified", "quarantine_deleted", "recovery_completed"}: self.controller.load_threats()

    def _render_loading(self) -> None:
        self.clear_body(); self.body.grid_columnconfigure(0, weight=1)
        ctk.CTkLabel(self.body, text="Loading threats…", font=(theme.FONT, 11), text_color=theme.TEXT_MUTED).grid(row=0, column=0, padx=12, pady=28, sticky="w")

    def _render(self, rows) -> None:
        self.clear_body(); self.body.grid_columnconfigure(0, weight=1); grouped = {name: [] for name in _SECTION_ORDER}
        for row in rows:
            section = row.get("section")
            if section in grouped: grouped[section].append(row)
        if not grouped["Needs attention"]: self._empty_attention(0); next_row = 1
        else: next_row = self._render_section(0, "Needs attention", grouped["Needs attention"])
        for section in ("Contained", "Resolved"):
            items = grouped[section]
            if items: next_row = self._render_section(next_row, section, items)
        if not any(grouped.values()): self._no_history(next_row)

    def _empty_attention(self, row: int) -> None:
        frame = ctk.CTkFrame(self.body, fg_color=theme.SURFACE, border_width=1, border_color=theme.BORDER, corner_radius=theme.RADIUS)
        frame.grid(row=row, column=0, padx=8, pady=(4, 12), sticky="ew"); frame.grid_columnconfigure(0, weight=1)
        ctk.CTkLabel(frame, text="No active threats", font=(theme.FONT, 15, "bold"), text_color=theme.TEXT, anchor="w").grid(row=0, column=0, padx=16, pady=(14, 3), sticky="ew")
        ctk.CTkLabel(frame, text="Nothing currently needs your review. AutoGuard will continue monitoring supported locations.", font=(theme.FONT, 10), text_color=theme.TEXT_MUTED, anchor="w", justify="left", wraplength=760).grid(row=1, column=0, padx=16, pady=(0, 14), sticky="ew")

    def _no_history(self, row: int) -> None:
        ctk.CTkLabel(self.body, text="No contained or resolved threats have been recorded yet.", font=(theme.FONT, 10), text_color=theme.TEXT_DIM, anchor="w").grid(row=row, column=0, padx=12, pady=(0, 18), sticky="w")

    def _render_section(self, row: int, title: str, items) -> int:
        header = ctk.CTkFrame(self.body, fg_color="transparent"); header.grid(row=row, column=0, padx=8, pady=(12, 5), sticky="ew"); header.grid_columnconfigure(0, weight=1)
        ctk.CTkLabel(header, text=title, font=(theme.FONT, 14, "bold"), text_color=theme.TEXT, anchor="w").grid(row=0, column=0, sticky="w")
        ctk.CTkLabel(header, text=str(len(items)), font=(theme.FONT, 10, "bold"), text_color=theme.TEXT_MUTED, fg_color=theme.SURFACE_ALT, corner_radius=6, padx=8, pady=2).grid(row=0, column=1, sticky="e")
        row += 1
        for item in items: self._threat_card(row, item); row += 1
        return row

    def _threat_card(self, row: int, item) -> None:
        card = ctk.CTkFrame(self.body, fg_color=theme.SURFACE, border_width=1, border_color=theme.BORDER, corner_radius=theme.RADIUS)
        card.grid(row=row, column=0, padx=8, pady=5, sticky="ew"); card.grid_columnconfigure(0, weight=1)
        top = ctk.CTkFrame(card, fg_color="transparent"); top.grid(row=0, column=0, columnspan=2, padx=16, pady=(14, 3), sticky="ew"); top.grid_columnconfigure(0, weight=1)
        ctk.CTkLabel(top, text=item.get("name", "Threat"), font=(theme.FONT, 14, "bold"), text_color=theme.TEXT, anchor="w").grid(row=0, column=0, sticky="ew")
        color, background = _STATUS_STYLE.get(item.get("status_key"), (theme.TEXT_MUTED, theme.SURFACE_ALT))
        ctk.CTkLabel(top, text=item.get("status", "Needs attention"), font=(theme.FONT, 9, "bold"), text_color=color, fg_color=background, corner_radius=6, padx=8, pady=3).grid(row=0, column=1, padx=(10, 0), sticky="e")
        ctk.CTkLabel(card, text=item.get("location", "Location unavailable"), font=(theme.FONT, 10), text_color=theme.TEXT_MUTED, anchor="w", justify="left", wraplength=760).grid(row=1, column=0, columnspan=2, padx=16, sticky="ew")
        meta_parts = [f"Detected {item.get('detected', 'time unavailable')}"]
        copies = int(item.get("matching_copies", 0) or 0)
        if copies: meta_parts.append(f"{copies:,} matching {'copy' if copies == 1 else 'copies'} found")
        ctk.CTkLabel(card, text="  •  ".join(meta_parts), font=(theme.FONT, 10), text_color=theme.TEXT_DIM, anchor="w").grid(row=2, column=0, padx=16, pady=(6, 14), sticky="w")
        threat_ref = item.get("threat_ref")
        ctk.CTkButton(card, text=item.get("action", "View details"), width=98, height=30, fg_color=theme.SURFACE_ALT, hover_color=theme.SURFACE_HOVER, text_color=theme.TEXT, border_width=1, border_color=theme.BORDER, command=lambda ref=threat_ref: self.controller.open_threat_details(ref)).grid(row=2, column=1, padx=16, pady=(6, 14), sticky="e")