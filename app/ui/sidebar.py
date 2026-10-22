"""Reusable top-level navigation for the AutoGuard desktop shell."""
from __future__ import annotations

import customtkinter as ctk
import math
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
        title_font = theme.font("brand_title", "bold")
        subtitle_font = theme.font("brand_subtitle")
        # Reserve enough logical width for the largest supported text setting.
        # CTkFont measures logical pixels; CTk applies Windows DPI separately.
        largest_scale = max(theme.TEXT_SCALES.values())
        text_width = max(
            math.ceil(title_font.measure("AutoGuard") *
                      round(theme.TYPE_SIZES["brand_title"] * largest_scale) / title_font.cget("size")),
            math.ceil(subtitle_font.measure("Automatic Protection") *
                      round(theme.TYPE_SIZES["brand_subtitle"] * largest_scale) / subtitle_font.cget("size")),
        ) + 8
        sidebar_width = max(theme.SIDEBAR_WIDTH, 36 + 40 + 12 + text_width)
        super().__init__(
            master,
            width=sidebar_width,
            fg_color=theme.SIDEBAR,
            corner_radius=0,
            **kwargs,
        )
        self.grid_propagate(False)
        self.grid_columnconfigure(0, weight=1, minsize=sidebar_width)

        spacer_row = len(NAV_ITEMS) + 1
        footer_row = spacer_row + 1
        self.grid_rowconfigure(spacer_row, weight=1)

        brand = ctk.CTkFrame(self, fg_color="transparent", height=1)
        brand.grid(row=0, column=0, padx=18, pady=(24, 22), sticky="ew")
        brand.grid_columnconfigure(0, weight=0, minsize=40)
        brand.grid_columnconfigure(1, weight=1, minsize=text_width + 12)
        self.brand = brand
        logo_image = Image.open(autoguard_logo_path()).convert("RGBA")
        self._brand_logo = ctk.CTkImage(
            light_image=logo_image, dark_image=logo_image, size=(38, 38)
        )
        self.logo = theme.Label(
            brand,
            text="",
            image=self._brand_logo,
            width=40,
            height=40,
            fg_color="transparent",
            auto_wrap=False,
        )
        self.logo.grid(row=0, column=0, sticky="w")
        block = ctk.CTkFrame(brand, fg_color="transparent", height=1)
        block.grid(row=0, column=1, padx=(12, 0), sticky="ew")
        block.grid_columnconfigure(0, weight=1, minsize=text_width)
        self.brand_title = theme.Label(
            block,
            text="AutoGuard",
            text_color=theme.TEXT,
            font=title_font,
            anchor="w",
            auto_wrap=False,
        )
        self.brand_title.grid(row=0, column=0, sticky="ew")
        self.brand_subtitle = theme.Label(
            block,
            text="Automatic Protection",
            text_color=theme.TEXT_DIM,
            font=subtitle_font,
            anchor="w",
            auto_wrap=False,
        )
        self.brand_subtitle.grid(row=1, column=0, pady=(2, 0), sticky="ew")

        self.buttons = {}
        for idx, (key, label) in enumerate(NAV_ITEMS, start=1):
            button = theme.Button(
                self,
                text=label,
                anchor="w",
                height=38,
                corner_radius=8,
                fg_color="transparent",
                hover_color=theme.SURFACE_HOVER,
                text_color=theme.TEXT_MUTED,
                font=theme.font("body", "bold", theme.FONT),
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
            height=1,
        )
        footer.grid(row=footer_row, column=0, padx=12, pady=16, sticky="sew")
        footer.grid_columnconfigure(1, weight=1)
        self.footer = footer
        theme.Label(
            footer,
            text="Protection",
            text_color=theme.TEXT_DIM,
            font=theme.font("secondary", "normal", theme.FONT),
            anchor="w",
            auto_wrap=False,
        ).grid(row=0, column=0, columnspan=2, padx=12, pady=(10, 0), sticky="ew")
        self.protection_icon = theme.Label(
            footer, text="●", width=18, text_color=theme.WARNING,
            font=theme.font("body", "bold"), auto_wrap=False,
        )
        self.protection_icon.grid(row=1, column=0, padx=(12, 4), pady=(2, 10), sticky="nw")
        self.protection = theme.Label(
            footer,
            text="Checking",
            text_color=theme.WARNING,
            font=theme.font("body", "bold", theme.FONT),
            anchor="w",
            justify="left",
        )
        self.protection.grid(row=1, column=1, padx=(0, 12), pady=(2, 10), sticky="ew")

        self.set_active("home")

    def set_active(self, key: str) -> None:
        for name, button in self.buttons.items():
            button.configure(
                fg_color=theme.ACCENT_DARK if name == key else "transparent",
                text_color=theme.ACCENT if name == key else theme.TEXT_MUTED,
                border_width=2 if name == key else 0,
                border_color=theme.ACCENT if name == key else theme.BORDER,
            )

    def set_protection(self, text: str, status: str = "running") -> None:
        color, _ = theme.STATUS_COLORS.get(
            status.lower(), (theme.TEXT_MUTED, theme.SURFACE_ALT)
        )
        self.protection.configure(text=text, text_color=color)
        self.protection_icon.configure(text_color=color)
