"""Dedicated quarantine detail view for AutoGuard UX Refresh Phase 9.

The view renders a sanitized read model from AutoGuardUIController. It does not
read quarantine storage, hash files, restore files, or delete content itself.
"""
from __future__ import annotations

import customtkinter as ctk

from app.ui import theme


_INTEGRITY_STYLE = {
    "verified": (theme.SUCCESS, theme.SUCCESS_DARK),
    "failed": (theme.DANGER, theme.DANGER_DARK),
    "pending": (theme.WARNING, theme.WARNING_DARK),
}


class QuarantineDetailsView(ctk.CTkFrame):
    """Reusable advanced detail view for one isolated file."""

    def __init__(
        self,
        master,
        data: dict,
        *,
        on_back,
        on_verify,
        on_restore,
        on_delete,
        **kwargs,
    ):
        super().__init__(master, fg_color="transparent", corner_radius=0, **kwargs)
        self._data = data
        self.grid_columnconfigure(0, weight=1)
        self._build(on_back, on_verify, on_restore, on_delete)

    def _card(self, row: int) -> ctk.CTkFrame:
        card = ctk.CTkFrame(
            self,
            fg_color=theme.SURFACE,
            border_width=1,
            border_color=theme.BORDER,
            corner_radius=theme.RADIUS,
        )
        card.grid(row=row, column=0, padx=8, pady=6, sticky="ew")
        card.grid_columnconfigure(0, weight=1)
        return card

    def _build(self, on_back, on_verify, on_restore, on_delete) -> None:
        ctk.CTkButton(
            self,
            text="← Back to Quarantine",
            width=150,
            height=30,
            fg_color="transparent",
            hover_color=theme.SURFACE_HOVER,
            text_color=theme.TEXT_MUTED,
            border_width=0,
            command=on_back,
        ).grid(row=0, column=0, padx=8, pady=(2, 10), sticky="w")

        header = self._card(1)
        ctk.CTkLabel(
            header,
            text=self._data.get("name", "Isolated file"),
            font=(theme.FONT, 21, "bold"),
            text_color=theme.TEXT,
            anchor="w",
        ).grid(row=0, column=0, padx=18, pady=(17, 3), sticky="ew")
        ctk.CTkLabel(
            header,
            text=f"Contained {self._data.get('contained', 'time unavailable')}",
            font=(theme.FONT, 10),
            text_color=theme.TEXT_MUTED,
            anchor="w",
        ).grid(row=1, column=0, padx=18, pady=(0, 3), sticky="ew")
        ctk.CTkLabel(
            header,
            text=self._data.get("original_location", "Original location unavailable"),
            font=(theme.FONT, 9),
            text_color=theme.TEXT_DIM,
            anchor="w",
            justify="left",
            wraplength=820,
        ).grid(row=2, column=0, padx=18, pady=(0, 16), sticky="ew")

        integrity = self._card(2)
        ctk.CTkLabel(
            integrity,
            text="Integrity",
            font=(theme.FONT, 16, "bold"),
            text_color=theme.TEXT,
            anchor="w",
        ).grid(row=0, column=0, padx=18, pady=(16, 8), sticky="ew")
        color, background = _INTEGRITY_STYLE.get(
            self._data.get("integrity_key"), (theme.TEXT_MUTED, theme.SURFACE_ALT)
        )
        verification = ctk.CTkFrame(integrity, fg_color="transparent")
        verification.grid(row=1, column=0, padx=18, pady=(0, 8), sticky="ew")
        verification.grid_columnconfigure(1, weight=1)
        ctk.CTkLabel(
            verification,
            text="Hash verification",
            width=150,
            font=(theme.FONT, 10, "bold"),
            text_color=theme.TEXT,
            anchor="w",
        ).grid(row=0, column=0, sticky="w")
        ctk.CTkLabel(
            verification,
            text=self._data.get("hash_verification", "Not verified yet"),
            font=(theme.FONT, 9, "bold"),
            text_color=color,
            fg_color=background,
            corner_radius=6,
            padx=8,
            pady=3,
        ).grid(row=0, column=1, sticky="w")
        self._detail_row(
            integrity,
            2,
            "Quarantine integrity",
            self._data.get("quarantine_integrity", "No integrity information available."),
        )
        self._detail_row(
            integrity,
            3,
            "Last verified",
            self._data.get("last_verified", "Not verified yet"),
        )
        ctk.CTkButton(
            integrity,
            text="Verify integrity",
            width=118,
            height=30,
            fg_color=theme.SURFACE_ALT,
            hover_color=theme.SURFACE_HOVER,
            command=on_verify,
        ).grid(row=4, column=0, padx=18, pady=(4, 16), sticky="w")

        details = self._card(3)
        ctk.CTkLabel(
            details,
            text="File details",
            font=(theme.FONT, 16, "bold"),
            text_color=theme.TEXT,
            anchor="w",
        ).grid(row=0, column=0, padx=18, pady=(16, 8), sticky="ew")
        rows = (
            ("Associated threat", f"{self._data.get('threat_name', 'Threat')} · {self._data.get('threat_status', 'Recorded')}") ,
            ("Original path", self._data.get("original_location", "Unavailable")),
            ("Quarantine timestamp", self._data.get("contained", "Time unavailable")),
            ("Original size", self._data.get("original_size", "Size unavailable")),
            ("Original removed", self._data.get("original_removed", "Unknown")),
            ("SHA-256", self._data.get("sha256", "Not recorded")),
            ("Internal quarantine ID", self._data.get("quarantine_id", "Not recorded")),
            ("Associated incident ID", self._data.get("incident_id", "Not recorded")),
        )
        for index, (label, value) in enumerate(rows, start=1):
            self._detail_row(details, index, label, value, technical=label in {
                "SHA-256", "Internal quarantine ID", "Associated incident ID"
            })

        latest = self._data.get("latest_recovery")
        final_row = len(rows) + 1
        if latest:
            self._detail_row(
                details,
                final_row,
                "Latest restore attempt",
                f"{latest.get('status', 'Finished')} · {latest.get('when', 'Time unavailable')}",
            )
            final_row += 1

        actions = ctk.CTkFrame(details, fg_color="transparent")
        actions.grid(row=final_row, column=0, padx=18, pady=(10, 16), sticky="ew")
        ctk.CTkButton(
            actions,
            text="Restore",
            width=90,
            height=32,
            fg_color=theme.ACCENT,
            hover_color=theme.ACCENT_HOVER,
            text_color="#07110F",
            state="normal" if self._data.get("can_restore") else "disabled",
            command=on_restore,
        ).pack(side="left")
        ctk.CTkButton(
            actions,
            text="Delete",
            width=84,
            height=32,
            fg_color=theme.DANGER_DARK,
            hover_color=theme.DANGER,
            text_color=theme.DANGER,
            state="normal" if self._data.get("can_delete") else "disabled",
            command=on_delete,
        ).pack(side="left", padx=(8, 0))

    def _detail_row(
        self,
        parent,
        row: int,
        label: str,
        value: str,
        *,
        technical: bool = False,
    ) -> None:
        block = ctk.CTkFrame(parent, fg_color="transparent")
        block.grid(row=row, column=0, padx=18, pady=(2, 6), sticky="ew")
        block.grid_columnconfigure(1, weight=1)
        ctk.CTkLabel(
            block,
            text=label,
            width=170,
            font=(theme.FONT, 10, "bold"),
            text_color=theme.TEXT,
            anchor="nw",
        ).grid(row=0, column=0, padx=(0, 14), sticky="nw")
        ctk.CTkLabel(
            block,
            text=value,
            font=(theme.FONT_MONO if technical else theme.FONT, 9),
            text_color=theme.TEXT_MUTED,
            anchor="w",
            justify="left",
            wraplength=650,
        ).grid(row=0, column=1, sticky="ew")