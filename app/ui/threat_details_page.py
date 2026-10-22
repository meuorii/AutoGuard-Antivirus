"""Evidence-based Threat Details view for AutoGuard UX Refresh Phase 8.

This view is presentation-only. It receives a sanitized read model from the UI
controller and never queries Threat Trail, incident, quarantine, cleanup, or
recovery storage directly.
"""
from __future__ import annotations

import customtkinter as ctk

from app.ui import theme
from app.ui.components import StatusBadge


_STATUS_STYLE = {
    "attention": (theme.WARNING, theme.WARNING_DARK),
    "reviewing": (theme.WARNING, theme.WARNING_DARK),
    "contained": (theme.SUCCESS, theme.SUCCESS_DARK),
    "reappeared": (theme.WARNING, theme.WARNING_DARK),
    "restored": (theme.INFO, theme.INFO_DARK),
    "resolved": (theme.TEXT_MUTED, theme.SURFACE_ALT),
}

_LOCATION_STYLE = {
    "available": (theme.SUCCESS, theme.SUCCESS_DARK),
    "contained": (theme.INFO, theme.INFO_DARK),
    "unavailable": (theme.WARNING, theme.WARNING_DARK),
}


class ThreatDetailsView(ctk.CTkFrame):
    """Reusable Threat Details presentation with Locations and Timeline."""

    _TIMELINE_INITIAL = 8
    # Hard caps: one huge Tk widget (a tall card or a very long label) can exceed the
    # Windows bitmap limit and fail with "Tk_GetPixmap: Error from CreateDIBSection".
    _TIMELINE_MAX = 100
    _LOCATIONS_MAX = 25
    _RAW_LOG_MAX_LINES = 200

    def __init__(self, master, data: dict, *, on_back, on_resolve=None, **kwargs):
        super().__init__(master, fg_color="transparent", corner_radius=0, **kwargs)
        self._technical_open = False
        self._data = data
        self._on_resolve = on_resolve
        self._timeline_more = None
        self.grid_columnconfigure(0, weight=1)
        self._build(on_back)

    def _build(self, on_back) -> None:
        ctk.CTkButton(
            self,
            text="← Back to Threats",
            width=128,
            height=30,
            fg_color="transparent",
            hover_color=theme.SURFACE_HOVER,
            text_color=theme.TEXT_MUTED,
            border_width=0,
            command=on_back,
        ).grid(row=0, column=0, padx=8, pady=(2, 10), sticky="w")

        header = ctk.CTkFrame(
            self,
            fg_color=theme.SURFACE,
            border_width=1,
            border_color=theme.BORDER,
            corner_radius=theme.RADIUS,
        )
        header.grid(row=1, column=0, padx=8, pady=(0, 12), sticky="ew")
        header.grid_columnconfigure(0, weight=1)

        ctk.CTkLabel(
            header,
            text=self._data.get("name", "Threat"),
            font=(theme.FONT, 21, "bold"),
            text_color=theme.TEXT,
            anchor="w",
        ).grid(row=0, column=0, padx=(18, 10), pady=(17, 4), sticky="ew")

        StatusBadge(
            header,
            self._data.get("status", "Needs attention"),
            self._data.get("status_key", "attention"),
        ).grid(row=0, column=1, padx=(0, 18), pady=(17, 4), sticky="e")

        can_resolve = bool(self._data.get("can_resolve")) and self._on_resolve is not None
        ctk.CTkLabel(
            header,
            text=f"Last observed {self._data.get('observed', 'time unavailable')}",
            font=(theme.FONT, 10),
            text_color=theme.TEXT_MUTED,
            anchor="w",
        ).grid(row=1, column=0, columnspan=1 if can_resolve else 2, padx=18, pady=(0, 16), sticky="ew")
        if can_resolve:
            ctk.CTkButton(
                header,
                text="Mark as resolved",
                width=130,
                height=30,
                fg_color=theme.SURFACE_ALT,
                hover_color=theme.SURFACE_HOVER,
                text_color=theme.TEXT,
                border_width=1,
                border_color=theme.BORDER,
                command=self._on_resolve,
            ).grid(row=1, column=1, padx=(0, 18), pady=(0, 16), sticky="e")

        self._build_what_happened(row=2)
        self._build_locations(row=3)
        self._build_timeline(row=4)
        self._build_technical_details(row=5)

    def _card(self, row: int) -> ctk.CTkFrame:
        section = ctk.CTkFrame(
            self,
            fg_color=theme.SURFACE,
            border_width=1,
            border_color=theme.BORDER,
            corner_radius=theme.RADIUS,
        )
        section.grid(row=row, column=0, padx=8, pady=6, sticky="ew")
        section.grid_columnconfigure(0, weight=1)
        return section

    def _build_what_happened(self, row: int) -> None:
        section = self._card(row)
        ctk.CTkLabel(
            section,
            text="What happened?",
            font=(theme.FONT, 16, "bold"),
            text_color=theme.TEXT,
            anchor="w",
        ).grid(row=0, column=0, padx=18, pady=(16, 4), sticky="ew")

        summary = self._data.get("summary")
        if summary:
            ctk.CTkLabel(
                section,
                text=summary,
                font=(theme.FONT, 10),
                text_color=theme.TEXT_MUTED,
                justify="left",
                anchor="w",
                wraplength=820,
            ).grid(row=1, column=0, padx=18, pady=(0, 12), sticky="ew")

        item_row = 2
        for item in self._data.get("what_happened", ()):
            block = ctk.CTkFrame(section, fg_color="transparent")
            block.grid(row=item_row, column=0, padx=18, pady=(3, 8), sticky="ew")
            block.grid_columnconfigure(1, weight=1)
            ctk.CTkLabel(
                block,
                text=item.get("label", "Evidence"),
                width=142,
                font=(theme.FONT, 10, "bold"),
                text_color=theme.TEXT,
                anchor="nw",
            ).grid(row=0, column=0, padx=(0, 14), sticky="nw")
            ctk.CTkLabel(
                block,
                text=item.get("text", "No recorded evidence available."),
                font=(theme.FONT, 10),
                text_color=theme.TEXT_MUTED,
                justify="left",
                anchor="w",
                wraplength=690,
            ).grid(row=0, column=1, sticky="ew")
            item_row += 1

        ctk.CTkLabel(
            section,
            text=self._data.get(
                "caution",
                "Observed locations do not establish where a threat originated.",
            ),
            font=(theme.FONT, 9),
            text_color=theme.TEXT_DIM,
            justify="left",
            anchor="w",
            wraplength=820,
        ).grid(row=item_row, column=0, padx=18, pady=(6, 16), sticky="ew")

    def _build_locations(self, row: int) -> None:
        section = self._card(row)
        ctk.CTkLabel(
            section,
            text="Locations",
            font=(theme.FONT, 16, "bold"),
            text_color=theme.TEXT,
            anchor="w",
        ).grid(row=0, column=0, padx=18, pady=(16, 3), sticky="ew")
        ctk.CTkLabel(
            section,
            text="AutoGuard observed identical file content in these locations.",
            font=(theme.FONT, 10),
            text_color=theme.TEXT_MUTED,
            anchor="w",
            justify="left",
            wraplength=820,
        ).grid(row=1, column=0, padx=18, pady=(0, 4), sticky="ew")
        ctk.CTkLabel(
            section,
            text=(
                "The first observed location is only the first place AutoGuard recorded this content. "
                "Multiple identical SHA-256 observations do not prove an infection source or direction of spread."
            ),
            font=(theme.FONT, 9),
            text_color=theme.TEXT_DIM,
            anchor="w",
            justify="left",
            wraplength=820,
        ).grid(row=2, column=0, padx=18, pady=(0, 12), sticky="ew")

        locations = tuple(self._data.get("locations", ()))
        if not locations:
            ctk.CTkLabel(
                section,
                text="No recorded locations are available for this threat.",
                font=(theme.FONT, 10),
                text_color=theme.TEXT_MUTED,
                anchor="w",
            ).grid(row=3, column=0, padx=18, pady=(4, 16), sticky="ew")
            return

        hidden_locations = max(0, len(locations) - self._LOCATIONS_MAX)
        locations = locations[: self._LOCATIONS_MAX]
        for index, item in enumerate(locations, start=3):
            card = ctk.CTkFrame(section, fg_color=theme.SURFACE_ALT, corner_radius=theme.RADIUS_SMALL)
            card.grid(row=index, column=0, padx=18, pady=(0, 8), sticky="ew")
            card.grid_columnconfigure(0, weight=1)

            top = ctk.CTkFrame(card, fg_color="transparent")
            top.grid(row=0, column=0, padx=12, pady=(10, 2), sticky="ew")
            top.grid_columnconfigure(0, weight=1)
            ctk.CTkLabel(
                top,
                text=item.get("path", "Location unavailable"),
                font=(theme.FONT_MONO, 9),
                text_color=theme.TEXT,
                anchor="w",
                justify="left",
                wraplength=650,
            ).grid(row=0, column=0, sticky="ew")

            badge_column = 1
            if item.get("first_observed"):
                ctk.CTkLabel(
                    top,
                    text="First observed location",
                    font=(theme.FONT, 8, "bold"),
                    text_color=theme.INFO,
                    fg_color=theme.INFO_DARK,
                    corner_radius=6,
                    padx=7,
                    pady=2,
                ).grid(row=0, column=badge_column, padx=(8, 0), sticky="e")
                badge_column += 1

            location_color, location_bg = _LOCATION_STYLE.get(
                item.get("availability_key"), (theme.TEXT_MUTED, theme.SURFACE)
            )
            ctk.CTkLabel(
                top,
                text=item.get("availability", "Recorded location"),
                font=(theme.FONT, 8, "bold"),
                text_color=location_color,
                fg_color=location_bg,
                corner_radius=6,
                padx=7,
                pady=2,
            ).grid(row=0, column=badge_column, padx=(8, 0), sticky="e")

            ctk.CTkLabel(
                card,
                text=f"Last recorded observation: {item.get('observed', 'Time unavailable')}",
                font=(theme.FONT, 9),
                text_color=theme.TEXT_MUTED,
                anchor="w",
            ).grid(row=1, column=0, padx=12, pady=(2, 0), sticky="ew")
            ctk.CTkLabel(
                card,
                text=item.get("availability_detail", ""),
                font=(theme.FONT, 9),
                text_color=theme.TEXT_DIM,
                anchor="w",
                justify="left",
                wraplength=790,
            ).grid(row=2, column=0, padx=12, pady=(2, 10), sticky="ew")

        next_row = 3 + len(locations)
        if hidden_locations:
            self._locations_more_note(section, next_row, hidden_locations)
            next_row += 1
        ctk.CTkFrame(section, fg_color="transparent", height=4).grid(
            row=next_row, column=0, pady=(0, 4)
        )

    def _locations_more_note(self, section, row: int, hidden: int) -> None:
        ctk.CTkLabel(
            section,
            text=f"+ {hidden:,} more matching locations not shown. See the Quarantine page for all isolated files.",
            font=(theme.FONT, 9),
            text_color=theme.TEXT_DIM,
            anchor="w",
        ).grid(row=row, column=0, padx=18, pady=(0, 14), sticky="ew")

    def _build_timeline(self, row: int) -> None:
        section = self._card(row)
        ctk.CTkLabel(
            section,
            text="Timeline",
            font=(theme.FONT, 16, "bold"),
            text_color=theme.TEXT,
            anchor="w",
        ).grid(row=0, column=0, padx=18, pady=(16, 3), sticky="ew")
        ctk.CTkLabel(
            section,
            text="Recorded threat activity, shown in chronological order.",
            font=(theme.FONT, 10),
            text_color=theme.TEXT_MUTED,
            anchor="w",
        ).grid(row=1, column=0, padx=18, pady=(0, 12), sticky="ew")

        timeline = tuple(self._data.get("timeline", ()))
        total_events = len(timeline)
        if total_events > self._TIMELINE_MAX:
            timeline = timeline[-self._TIMELINE_MAX:]
        if not timeline:
            ctk.CTkLabel(
                section,
                text="No incident timeline events have been recorded.",
                font=(theme.FONT, 10),
                text_color=theme.TEXT_MUTED,
                anchor="w",
            ).grid(row=2, column=0, padx=18, pady=(2, 16), sticky="ew")
            return

        # Building every timeline row with CustomTkinter widgets is the slowest part of
        # this page (about 0.02 s per event), so show the newest events first and let
        # the user expand the rest on demand.
        hidden = max(0, len(timeline) - self._TIMELINE_INITIAL)
        visible = timeline[-self._TIMELINE_INITIAL:] if hidden else timeline
        first_row = 2
        if hidden:
            self._timeline_more = ctk.CTkButton(
                section,
                text=f"Show {hidden:,} earlier {'event' if hidden == 1 else 'events'}",
                width=170,
                height=28,
                fg_color=theme.SURFACE_ALT,
                hover_color=theme.SURFACE_HOVER,
                text_color=theme.TEXT,
                border_width=1,
                border_color=theme.BORDER,
                command=lambda: self._expand_timeline(section, timeline),
            )
            self._timeline_more.grid(row=2, column=0, padx=18, pady=(0, 12), sticky="w")
            first_row = 3
        for index, item in enumerate(visible, start=first_row):
            self._timeline_line(section, index, item)
        self._timeline_total = total_events

    def _expand_timeline(self, section, timeline) -> None:
        """Render the remaining (older) events in small batches so the UI stays responsive."""
        if self._timeline_more is not None:
            self._timeline_more.configure(text="Loading earlier events…", state="disabled")
        older = timeline[:-self._TIMELINE_INITIAL]
        shown = timeline[-self._TIMELINE_INITIAL:]
        # Re-grid the already-visible rows after the older ones by shifting their rows.
        base = 3
        children = [w for w in section.winfo_children() if int(w.grid_info().get("row", 0)) >= base]
        for widget in children:
            info = widget.grid_info()
            widget.grid_configure(row=int(info["row"]) + len(older))

        def render(start: int = 0) -> None:
            if not section.winfo_exists():
                return
            for offset, item in enumerate(older[start:start + 8], start=start):
                self._timeline_line(section, base + offset, item)
            if start + 8 < len(older):
                self.after(10, lambda: render(start + 8))
            else:
                if self._timeline_more is not None:
                    self._timeline_more.destroy()
                    self._timeline_more = None
                total = getattr(self, "_timeline_total", len(timeline))
                if total > len(timeline):
                    ctk.CTkLabel(
                        section,
                        text=f"Showing the latest {len(timeline):,} of {total:,} recorded events.",
                        font=(theme.FONT, 9),
                        text_color=theme.TEXT_DIM,
                        anchor="w",
                    ).grid(row=2, column=0, padx=18, pady=(0, 10), sticky="w")

        render()

    def _timeline_line(self, section, row: int, item: dict) -> None:
        line = ctk.CTkFrame(section, fg_color="transparent")
        line.grid(row=row, column=0, padx=18, pady=(0, 12), sticky="ew")
        line.grid_columnconfigure(1, weight=1)
        ctk.CTkLabel(
            line,
            text="●",
            width=18,
            font=(theme.FONT, 10),
            text_color=theme.ACCENT,
            anchor="n",
        ).grid(row=0, column=0, padx=(0, 8), sticky="n")

        body = ctk.CTkFrame(line, fg_color="transparent")
        body.grid(row=0, column=1, sticky="ew")
        body.grid_columnconfigure(0, weight=1)
        ctk.CTkLabel(
            body,
            text=("Threat resolved" if item.get("label") == "Incident resolved" else item.get("label", "Threat activity recorded")),
            font=(theme.FONT, 10, "bold"),
            text_color=theme.TEXT,
            anchor="w",
        ).grid(row=0, column=0, sticky="ew")
        ctk.CTkLabel(
            body,
            text=item.get("time", "Time unavailable"),
            font=(theme.FONT, 9),
            text_color=theme.TEXT_DIM,
            anchor="e",
        ).grid(row=0, column=1, padx=(12, 0), sticky="e")
        ctk.CTkLabel(
            body,
            text=item.get("explanation", ""),
            font=(theme.FONT, 9),
            text_color=theme.TEXT_MUTED,
            anchor="w",
            justify="left",
            wraplength=730,
        ).grid(row=1, column=0, columnspan=2, pady=(2, 0), sticky="ew")
        if item.get("path"):
            ctk.CTkLabel(
                body,
                text=item["path"],
                font=(theme.FONT_MONO, 8),
                text_color=theme.TEXT_DIM,
                anchor="w",
                justify="left",
                wraplength=730,
            ).grid(row=2, column=0, columnspan=2, pady=(3, 0), sticky="ew")

    def _build_technical_details(self, row: int) -> None:
        wrapper = ctk.CTkFrame(
            self,
            fg_color=theme.SURFACE,
            border_width=1,
            border_color=theme.BORDER,
            corner_radius=theme.RADIUS,
        )
        wrapper.grid(row=row, column=0, padx=8, pady=(6, 18), sticky="ew")
        wrapper.grid_columnconfigure(0, weight=1)

        self._technical_button = ctk.CTkButton(
            wrapper,
            text="Technical details  ▾",
            height=38,
            fg_color="transparent",
            hover_color=theme.SURFACE_HOVER,
            text_color=theme.TEXT,
            anchor="w",
            border_width=0,
            font=(theme.FONT, 11, "bold"),
            command=self._toggle_technical,
        )
        self._technical_button.grid(row=0, column=0, padx=10, pady=6, sticky="ew")

        self._technical_frame = ctk.CTkFrame(wrapper, fg_color="transparent")
        self._technical_frame.grid_columnconfigure(1, weight=1)
        for index, (label, value) in enumerate(self._data.get("technical_details", ())):
            if label == "Incident events":
                lines = str(value).split("\n")
                if len(lines) > self._RAW_LOG_MAX_LINES:
                    value = (
                        f"Showing the latest {self._RAW_LOG_MAX_LINES} of {len(lines):,} recorded events\n"
                        + "\n".join(lines[-self._RAW_LOG_MAX_LINES:])
                    )
            ctk.CTkLabel(
                self._technical_frame,
                text=label,
                width=150,
                font=(theme.FONT, 9, "bold"),
                text_color=theme.TEXT_MUTED,
                anchor="nw",
            ).grid(row=index, column=0, padx=(10, 14), pady=5, sticky="nw")
            ctk.CTkLabel(
                self._technical_frame,
                text=str(value),
                font=(theme.FONT_MONO, 9),
                text_color=theme.TEXT_DIM,
                justify="left",
                anchor="w",
                wraplength=670,
            ).grid(row=index, column=1, padx=(0, 10), pady=5, sticky="ew")
        self._technical_frame.grid(
            row=1, column=0, padx=8, pady=(0, 12), sticky="ew"
        )
        self._technical_frame.grid_remove()

    def _toggle_technical(self) -> None:
        self._technical_open = not self._technical_open
        if self._technical_open:
            self._technical_frame.grid()
            self._technical_button.configure(text="Technical details  ▴")
        else:
            self._technical_frame.grid_remove()
            self._technical_button.configure(text="Technical details  ▾")