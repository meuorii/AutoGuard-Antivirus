"""Shared presentation primitives for the AutoGuard UX Refresh.

These widgets contain no antivirus/business logic. They only standardize common
spacing, status treatment, empty/loading states, and expandable advanced data.
"""
from __future__ import annotations

from collections.abc import Iterable
from typing import Any

import customtkinter as ctk

from app.ui import theme


class StatusBadge(ctk.CTkLabel):
    """Small consistent status badge driven by an already user-facing key."""

    _ALIASES = {
        "attention": "suspicious",
        "reviewing": "investigating",
        "resolved": "stopped",
        "available": "protected",
        "unavailable": "suspicious",
        "pending": "suspicious",
    }

    @classmethod
    def _style(cls, status: str):
        key = cls._ALIASES.get(str(status).lower(), str(status).lower())
        return theme.STATUS_COLORS.get(key, (theme.TEXT_MUTED, theme.SURFACE_ALT))

    def __init__(self, master, text: str, status: str = "idle", **kwargs):
        color, background = self._style(status)
        super().__init__(
            master,
            text=text,
            font=(theme.FONT, 9, "bold"),
            text_color=color,
            fg_color=background,
            corner_radius=6,
            padx=8,
            pady=3,
            **kwargs,
        )

    def set_status(self, text: str, status: str = "idle") -> None:
        color, background = self._style(status)
        self.configure(text=text, text_color=color, fg_color=background)


class StateCard(ctk.CTkFrame):
    """Reusable loading/empty/error/information state card."""

    _TONE = {
        "success": (theme.SUCCESS, theme.SUCCESS_DARK),
        "warning": (theme.WARNING, theme.WARNING_DARK),
        "danger": (theme.DANGER, theme.DANGER_DARK),
        "error": (theme.DANGER, theme.DANGER_DARK),
        "info": (theme.INFO, theme.SURFACE),
        "neutral": (theme.TEXT, theme.SURFACE),
    }

    def __init__(self, master, title: str, message: str = "", *, tone: str = "neutral", **kwargs):
        color, background = self._TONE.get(tone, self._TONE["neutral"])
        super().__init__(
            master,
            fg_color=background,
            border_width=1,
            border_color=color if tone in {"danger", "error", "warning"} else theme.BORDER,
            corner_radius=theme.RADIUS,
            **kwargs,
        )
        self.grid_columnconfigure(0, weight=1)
        ctk.CTkLabel(
            self,
            text=title,
            font=(theme.FONT, 14, "bold"),
            text_color=color,
            anchor="w",
        ).grid(row=0, column=0, padx=16, pady=(14, 3), sticky="ew")
        if message:
            ctk.CTkLabel(
                self,
                text=message,
                font=(theme.FONT, 10),
                text_color=theme.TEXT_MUTED if tone not in {"danger", "error"} else theme.TEXT,
                justify="left",
                anchor="w",
                wraplength=800,
            ).grid(row=1, column=0, padx=16, pady=(0, 14), sticky="ew")


class SectionHeader(ctk.CTkFrame):
    """Consistent section heading with an optional compact count badge."""

    def __init__(self, master, title: str, *, count: int | None = None, **kwargs):
        super().__init__(master, fg_color="transparent", corner_radius=0, **kwargs)
        self.grid_columnconfigure(0, weight=1)
        ctk.CTkLabel(
            self,
            text=title,
            font=(theme.FONT, 14, "bold"),
            text_color=theme.TEXT,
            anchor="w",
        ).grid(row=0, column=0, sticky="w")
        if count is not None:
            StatusBadge(self, str(count), "idle").grid(row=0, column=1, sticky="e")


class ExpandableDetails(ctk.CTkFrame):
    """Collapsed-by-default advanced key/value details."""

    def __init__(
        self,
        master,
        *,
        title: str = "Technical details",
        rows: Iterable[tuple[str, Any]] = (),
        mono_values: bool = True,
        **kwargs,
    ) -> None:
        super().__init__(
            master,
            fg_color=theme.SURFACE,
            border_width=1,
            border_color=theme.BORDER,
            corner_radius=theme.RADIUS,
            **kwargs,
        )
        self.grid_columnconfigure(0, weight=1)
        self._title = title
        self._open = False
        self.button = ctk.CTkButton(
            self,
            text=f"{title}  ▾",
            height=38,
            fg_color="transparent",
            hover_color=theme.SURFACE_HOVER,
            text_color=theme.TEXT,
            anchor="w",
            border_width=0,
            font=(theme.FONT, 11, "bold"),
            command=self.toggle,
        )
        self.button.grid(row=0, column=0, padx=10, pady=6, sticky="ew")
        self.content = ctk.CTkFrame(self, fg_color="transparent")
        self.content.grid_columnconfigure(1, weight=1)
        for index, (label, value) in enumerate(rows):
            ctk.CTkLabel(
                self.content,
                text=label,
                width=160,
                font=(theme.FONT, 9, "bold"),
                text_color=theme.TEXT_MUTED,
                anchor="nw",
            ).grid(row=index, column=0, padx=(10, 14), pady=5, sticky="nw")
            ctk.CTkLabel(
                self.content,
                text=str(value),
                font=(theme.FONT_MONO if mono_values else theme.FONT, 9),
                text_color=theme.TEXT_DIM,
                justify="left",
                anchor="w",
                wraplength=670,
            ).grid(row=index, column=1, padx=(0, 10), pady=5, sticky="ew")
        self.content.grid(row=1, column=0, padx=8, pady=(0, 12), sticky="ew")
        self.content.grid_remove()

    @property
    def expanded(self) -> bool:
        return self._open

    def toggle(self) -> None:
        self._open = not self._open
        if self._open:
            self.content.grid()
            self.button.configure(text=f"{self._title}  ▴")
        else:
            self.content.grid_remove()
            self.button.configure(text=f"{self._title}  ▾")
