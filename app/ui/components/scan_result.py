from __future__ import annotations
from collections.abc import Callable
from typing import Any
import customtkinter as ctk
from app.ui import theme

_RESULT_STYLE = {"clean": (theme.SUCCESS, theme.SUCCESS_DARK), "suspicious": (theme.WARNING, theme.WARNING_DARK), "confirmed_threat": (theme.DANGER, theme.DANGER_DARK)}

class ScanResultPanel(ctk.CTkFrame):
    def __init__(self, master, *, on_done: Callable[[], None], on_view_details: Callable[[], None], on_review_files: Callable[[], None], on_view_threat: Callable[[], None], **kwargs) -> None:
        super().__init__(master, fg_color="transparent", corner_radius=0, **kwargs)
        self.grid_columnconfigure(0, weight=1); self._on_done, self._on_view_details, self._on_review_files, self._on_view_threat = on_done, on_view_details, on_review_files, on_view_threat; self._data: dict[str, Any] = {}
        self.hero = ctk.CTkFrame(self, fg_color=theme.SURFACE, border_width=1, border_color=theme.BORDER, corner_radius=theme.RADIUS); self.hero.grid(row=0, column=0, sticky="ew"); self.hero.grid_columnconfigure(1, weight=1)
        self.icon = ctk.CTkLabel(self.hero, text="✓", width=44, height=44, corner_radius=22, fg_color=theme.SUCCESS_DARK, text_color=theme.SUCCESS, font=(theme.FONT, 20, "bold")); self.icon.grid(row=0, column=0, rowspan=2, padx=(18, 14), pady=18, sticky="n")
        self.title_label = ctk.CTkLabel(self.hero, text="Scan complete", text_color=theme.TEXT, font=(theme.FONT, 22, "bold"), anchor="w"); self.title_label.grid(row=0, column=1, padx=(0, 18), pady=(18, 3), sticky="ew")
        self.message_label = ctk.CTkLabel(self.hero, text="No threats detected in the files successfully scanned.", text_color=theme.TEXT_MUTED, font=(theme.FONT, 11), anchor="w", justify="left", wraplength=760); self.message_label.grid(row=1, column=1, padx=(0, 18), pady=(0, 18), sticky="ew")
        self.summary = ctk.CTkFrame(self, fg_color="transparent", corner_radius=0); self.summary.grid(row=1, column=0, pady=(14, 0), sticky="ew"); self.summary.grid_columnconfigure((0, 1), weight=1)
        self.scan_info, self.duration_info = self._info_card(self.summary, "Scan", 0), self._info_card(self.summary, "Duration", 1)
        self.metrics = ctk.CTkFrame(self, fg_color=theme.SURFACE, border_width=1, border_color=theme.BORDER, corner_radius=theme.RADIUS); self.metrics.grid(row=2, column=0, pady=(10, 0), sticky="ew"); self.metrics.grid_columnconfigure((0, 1, 2), weight=1)
        self.metric_values: dict[str, ctk.CTkLabel] = {}
        for column, (key, label) in enumerate((("files_checked", "Files checked"), ("threats_found", "Threats found"), ("skipped_files", "Skipped files"))):
            value = ctk.CTkLabel(self.metrics, text="0", text_color=theme.TEXT, font=(theme.FONT, 22, "bold"), anchor="w"); value.grid(row=0, column=column, padx=16, pady=(15, 0), sticky="ew")
            ctk.CTkLabel(self.metrics, text=label, text_color=theme.TEXT_MUTED, font=(theme.FONT, 9), anchor="w").grid(row=1, column=column, padx=16, pady=(0, 14), sticky="ew"); self.metric_values[key] = value
        self.threat_details = ctk.CTkFrame(self, fg_color=theme.SURFACE, border_width=1, border_color=theme.BORDER, corner_radius=theme.RADIUS); self.threat_details.grid_columnconfigure((0, 1, 2), weight=1)
        self.threat_values: dict[str, ctk.CTkLabel] = {}
        for column, (key, label) in enumerate((("threats_contained", "Threats contained"), ("matching_copies_found", "Matching copies found"), ("cleanup_status", "Cleanup verification"))):
            value = ctk.CTkLabel(self.threat_details, text="0", text_color=theme.TEXT, font=(theme.FONT, 16, "bold"), anchor="w"); value.grid(row=0, column=column, padx=16, pady=(15, 0), sticky="ew")
            ctk.CTkLabel(self.threat_details, text=label, text_color=theme.TEXT_MUTED, font=(theme.FONT, 9), anchor="w").grid(row=1, column=column, padx=16, pady=(0, 14), sticky="ew"); self.threat_values[key] = value
        self.note_label = ctk.CTkLabel(self, text="", text_color=theme.TEXT_MUTED, font=(theme.FONT, 10), anchor="w", justify="left", wraplength=780)
        self.actions = ctk.CTkFrame(self, fg_color="transparent", corner_radius=0); self.actions.grid(row=5, column=0, pady=(16, 0), sticky="ew"); self.actions.grid_columnconfigure(0, weight=1)
        self.secondary_button = ctk.CTkButton(self.actions, text="View scan details", command=self._on_view_details, height=34, fg_color="transparent", hover_color=theme.SURFACE_HOVER, border_width=1, border_color=theme.BORDER, text_color=theme.TEXT, font=(theme.FONT, 10, "bold"), corner_radius=theme.RADIUS_SMALL); self.secondary_button.grid(row=0, column=0, sticky="w")
        self.done_button = ctk.CTkButton(self.actions, text="Done", command=self._on_done, height=34, width=100, fg_color=theme.ACCENT, hover_color=theme.ACCENT_HOVER, text_color=theme.BG, font=(theme.FONT, 10, "bold"), corner_radius=theme.RADIUS_SMALL); self.done_button.grid(row=0, column=1, sticky="e")
        self.bind("<Configure>", self._resize_for_width)

    def _info_card(self, master, label: str, column: int) -> ctk.CTkLabel:
        card = ctk.CTkFrame(master, fg_color=theme.SURFACE, border_width=1, border_color=theme.BORDER, corner_radius=theme.RADIUS); card.grid(row=0, column=column, padx=(0, 5) if column == 0 else (5, 0), sticky="ew"); card.grid_columnconfigure(0, weight=1)
        ctk.CTkLabel(card, text=label, text_color=theme.TEXT_DIM, font=(theme.FONT, 9, "bold"), anchor="w").grid(row=0, column=0, padx=16, pady=(12, 2), sticky="ew")
        value = ctk.CTkLabel(card, text="—", text_color=theme.TEXT, font=(theme.FONT, 12, "bold"), anchor="w"); value.grid(row=1, column=0, padx=16, pady=(0, 12), sticky="ew"); return value

    def show_result(self, data: dict[str, Any]) -> None:
        """Render a controller-prepared result without interpreting backend enums."""
        self._data = dict(data); kind = str(data.get("kind", "clean")); accent, accent_bg = _RESULT_STYLE.get(kind, _RESULT_STYLE["clean"])
        self.icon.configure(text={"clean": "✓", "suspicious": "!", "confirmed_threat": "!"}.get(kind, "✓"), text_color=accent, fg_color=accent_bg)
        self.title_label.configure(text=str(data.get("title", "Scan complete"))); self.message_label.configure(text=str(data.get("message", "")))
        self.scan_info.configure(text=str(data.get("scan_type", "Scan"))); self.duration_info.configure(text=str(data.get("duration", "—")))
        for key in ("files_checked", "threats_found", "skipped_files"): self.metric_values[key].configure(text=f"{int(data.get(key, 0)):,}")
        if kind == "confirmed_threat":
            self.threat_values["threats_contained"].configure(text=f"{int(data.get('threats_contained', 0)):,}"); self.threat_values["matching_copies_found"].configure(text=f"{int(data.get('matching_copies_found', 0)):,}")
            self.threat_values["cleanup_status"].configure(text=str(data.get("cleanup_status", "Not verified"))); self.threat_details.grid(row=3, column=0, pady=(10, 0), sticky="ew")
        else: self.threat_details.grid_remove()
        note = str(data.get("note", "")).strip()
        if note: self.note_label.configure(text=note); self.note_label.grid(row=4, column=0, pady=(10, 0), sticky="ew")
        else: self.note_label.grid_remove()
        if kind == "suspicious": self.secondary_button.configure(text="Review files", command=self._on_review_files)
        elif kind == "confirmed_threat": self.secondary_button.configure(text="View threat", command=self._on_view_threat)
        else: self.secondary_button.configure(text="View scan details", command=self._on_view_details)

    def _resize_for_width(self, event) -> None:
        width = max(300, int(getattr(event, "width", 800)) - 120); self.message_label.configure(wraplength=width); self.note_label.configure(wraplength=width)