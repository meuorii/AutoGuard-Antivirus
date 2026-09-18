"""Reusable top-level navigation for the AutoGuard desktop shell."""
from __future__ import annotations

import customtkinter as ctk
from PIL import Image

from app.resources import autoguard_logo_path
from app.ui import theme


# UX Refresh Phase 1 deliberately exposes only these six user-facing areas.
# Backend services and the older incident/trail/history presentation modules
# remain available elsewhere in the project and are not changed here.
NAV_ITEMS = (
    ("home", "Home"),
    ("scan", "Scan"),
    ("threats", "Threats"),
    ("quarantine", "Quarantine"),
    ("activity", "Activity"),
    ("settings", "Settings"),
)


class Sidebar(ctk.CTkFrame):
    """Presentation-only navigation; it never owns protection services."""

    def __init__(self, master, on_navigate, **kwargs):
        super().__init__(
            master,
            width=theme.SIDEBAR_WIDTH,
            fg_color=theme.SIDEBAR,
            corner_radius=0,
            **kwargs,
        )
        self.grid_propagate(False)

        spacer_row = len(NAV_ITEMS) + 1
        footer_row = spacer_row + 1
        self.grid_rowconfigure(spacer_row, weight=1)

        brand = ctk.CTkFrame(self, fg_color="transparent")
        brand.grid(row=0, column=0, padx=18, pady=(24, 26), sticky="ew")
        logo_image = Image.open(autoguard_logo_path()).convert("RGBA")
        self._brand_logo = ctk.CTkImage(
            light_image=logo_image, dark_image=logo_image, size=(38, 38)
        )
        ctk.CTkLabel(
            brand,
            text="",
            image=self._brand_logo,
            width=40,
            height=40,
            fg_color="transparent",
        ).pack(side="left")
        block = ctk.CTkFrame(brand, fg_color="transparent")
        block.pack(side="left", padx=(10, 0))
        ctk.CTkLabel(
            block,
            text="AutoGuard",
            text_color=theme.TEXT,
            font=(theme.FONT, 16, "bold"),
        ).pack(anchor="w")
        ctk.CTkLabel(
            block,
            text="Automatic protection",
            text_color=theme.TEXT_DIM,
            font=(theme.FONT, 9),
        ).pack(anchor="w")

        self.buttons = {}
        for idx, (key, label) in enumerate(NAV_ITEMS, start=1):
            button = ctk.CTkButton(
                self,
                text=label,
                anchor="w",
                height=38,
                corner_radius=8,
                fg_color="transparent",
                hover_color=theme.SURFACE_HOVER,
                text_color=theme.TEXT_MUTED,
                font=(theme.FONT, 11, "bold"),
                command=lambda k=key: on_navigate(k),
            )
            button.grid(row=idx, column=0, padx=12, pady=2, sticky="ew")
            self.buttons[key] = button

        footer = ctk.CTkFrame(
            self,
            fg_color=theme.SURFACE,
            border_width=1,
            border_color=theme.BORDER,
            corner_radius=10,
        )
        footer.grid(row=footer_row, column=0, padx=12, pady=16, sticky="sew")
        ctk.CTkLabel(
            footer,
            text="Protection",
            text_color=theme.TEXT_DIM,
            font=(theme.FONT, 9),
        ).pack(anchor="w", padx=12, pady=(10, 0))
        self.protection = ctk.CTkLabel(
            footer,
            text="●  Checking",
            text_color=theme.WARNING,
            font=(theme.FONT, 10, "bold"),
        )
        self.protection.pack(anchor="w", padx=12, pady=(2, 10))

        self.set_active("home")

    def set_active(self, key: str) -> None:
        for name, button in self.buttons.items():
            button.configure(
                fg_color=theme.ACCENT_DARK if name == key else "transparent",
                text_color=theme.ACCENT if name == key else theme.TEXT_MUTED,
            )

    def set_protection(self, text: str, status: str = "running") -> None:
        color, _ = theme.STATUS_COLORS.get(
            status.lower(), (theme.TEXT_MUTED, theme.SURFACE_ALT)
        )
        self.protection.configure(text=f"●  {text}", text_color=color)