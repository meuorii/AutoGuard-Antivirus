from __future__ import annotations
import customtkinter as ctk
from app.ui import theme

_STATUS_STYLE = {"attention": (theme.WARNING, theme.WARNING_DARK), "reviewing": (theme.WARNING, theme.WARNING_DARK), "contained": (theme.SUCCESS, theme.SUCCESS_DARK), "reappeared": (theme.WARNING, theme.WARNING_DARK), "restored": (theme.INFO, theme.INFO_DARK), "resolved": (theme.TEXT_MUTED, theme.SURFACE_ALT)}

class ThreatDetailsView(ctk.CTkFrame):
    def __init__(self, master, data: dict, *, on_back, **kwargs):
        super().__init__(master, fg_color="transparent", corner_radius=0, **kwargs)
        self._technical_open = False; self._data = data; self.grid_columnconfigure(0, weight=1); self._build(on_back)

    def _build(self, on_back) -> None:
        ctk.CTkButton(self, text="← Back to Threats", width=128, height=30, fg_color="transparent", hover_color=theme.SURFACE_HOVER, text_color=theme.TEXT_MUTED, border_width=0, command=on_back).grid(row=0, column=0, padx=8, pady=(2, 10), sticky="w")
        header = ctk.CTkFrame(self, fg_color=theme.SURFACE, border_width=1, border_color=theme.BORDER, corner_radius=theme.RADIUS)
        header.grid(row=1, column=0, padx=8, pady=(0, 12), sticky="ew"); header.grid_columnconfigure(0, weight=1)
        ctk.CTkLabel(header, text=self._data.get("name", "Threat"), font=(theme.FONT, 21, "bold"), text_color=theme.TEXT, anchor="w").grid(row=0, column=0, padx=(18, 10), pady=(17, 4), sticky="ew")
        color, background = _STATUS_STYLE.get(self._data.get("status_key"), (theme.TEXT_MUTED, theme.SURFACE_ALT))
        ctk.CTkLabel(header, text=self._data.get("status", "Needs attention"), font=(theme.FONT, 10, "bold"), text_color=color, fg_color=background, corner_radius=6, padx=9, pady=4).grid(row=0, column=1, padx=(0, 18), pady=(17, 4), sticky="e")
        ctk.CTkLabel(header, text=f"Last observed {self._data.get('observed', 'time unavailable')}", font=(theme.FONT, 10), text_color=theme.TEXT_MUTED, anchor="w").grid(row=1, column=0, columnspan=2, padx=18, pady=(0, 16), sticky="ew")
        self._build_what_happened(row=2); self._build_technical_details(row=3)

    def _build_what_happened(self, row: int) -> None:
        section = ctk.CTkFrame(self, fg_color=theme.SURFACE, border_width=1, border_color=theme.BORDER, corner_radius=theme.RADIUS)
        section.grid(row=row, column=0, padx=8, pady=6, sticky="ew"); section.grid_columnconfigure(0, weight=1)
        ctk.CTkLabel(section, text="What happened?", font=(theme.FONT, 16, "bold"), text_color=theme.TEXT, anchor="w").grid(row=0, column=0, padx=18, pady=(16, 4), sticky="ew")
        summary = self._data.get("summary")
        if summary: ctk.CTkLabel(section, text=summary, font=(theme.FONT, 10), text_color=theme.TEXT_MUTED, justify="left", anchor="w", wraplength=820).grid(row=1, column=0, padx=18, pady=(0, 12), sticky="ew")
        item_row = 2
        for item in self._data.get("what_happened", ()):
            block = ctk.CTkFrame(section, fg_color="transparent"); block.grid(row=item_row, column=0, padx=18, pady=(3, 8), sticky="ew"); block.grid_columnconfigure(1, weight=1)
            ctk.CTkLabel(block, text=item.get("label", "Evidence"), width=142, font=(theme.FONT, 10, "bold"), text_color=theme.TEXT, anchor="nw").grid(row=0, column=0, padx=(0, 14), sticky="nw")
            ctk.CTkLabel(block, text=item.get("text", "No recorded evidence available."), font=(theme.FONT, 10), text_color=theme.TEXT_MUTED, justify="left", anchor="w", wraplength=690).grid(row=0, column=1, sticky="ew")
            item_row += 1
        ctk.CTkLabel(section, text=self._data.get("caution", "Observed locations do not establish where a threat originated."), font=(theme.FONT, 9), text_color=theme.TEXT_DIM, justify="left", anchor="w", wraplength=820).grid(row=item_row, column=0, padx=18, pady=(6, 16), sticky="ew")

    def _build_technical_details(self, row: int) -> None:
        wrapper = ctk.CTkFrame(self, fg_color=theme.SURFACE, border_width=1, border_color=theme.BORDER, corner_radius=theme.RADIUS)
        wrapper.grid(row=row, column=0, padx=8, pady=(6, 18), sticky="ew"); wrapper.grid_columnconfigure(0, weight=1)
        self._technical_button = ctk.CTkButton(wrapper, text="Technical details  ▾", height=38, fg_color="transparent", hover_color=theme.SURFACE_HOVER, text_color=theme.TEXT, anchor="w", border_width=0, font=(theme.FONT, 11, "bold"), command=self._toggle_technical)
        self._technical_button.grid(row=0, column=0, padx=10, pady=6, sticky="ew")
        self._technical_frame = ctk.CTkFrame(wrapper, fg_color="transparent"); self._technical_frame.grid_columnconfigure(1, weight=1)
        for index, (label, value) in enumerate(self._data.get("technical_details", ())):
            ctk.CTkLabel(self._technical_frame, text=label, width=150, font=(theme.FONT, 9, "bold"), text_color=theme.TEXT_MUTED, anchor="nw").grid(row=index, column=0, padx=(10, 14), pady=5, sticky="nw")
            ctk.CTkLabel(self._technical_frame, text=str(value), font=(theme.FONT_MONO, 9), text_color=theme.TEXT_DIM, justify="left", anchor="w", wraplength=670).grid(row=index, column=1, padx=(0, 10), pady=5, sticky="ew")
        self._technical_frame.grid(row=1, column=0, padx=8, pady=(0, 12), sticky="ew"); self._technical_frame.grid_remove()

    def _toggle_technical(self) -> None:
        self._technical_open = not self._technical_open
        if self._technical_open: self._technical_frame.grid(); self._technical_button.configure(text="Technical details  ▴")
        else: self._technical_frame.grid_remove(); self._technical_button.configure(text="Technical details  ▾")