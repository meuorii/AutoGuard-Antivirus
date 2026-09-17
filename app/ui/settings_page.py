"""User-facing AutoGuard settings for UX Refresh Phase 11.

Only controls backed by an existing runtime service are interactive. Startup-only
configuration is presented as read-only information rather than duplicated as
UI-only state.
"""
from __future__ import annotations

import customtkinter as ctk

from app.ui import theme
from app.ui.base_page import BasePage


class SettingsPage(BasePage):
    title = "Settings"
    subtitle = "Protection, scanning, quarantine, and application configuration"

    def __init__(self, master, controller, **kwargs):
        super().__init__(master, controller, **kwargs)
        self._data: dict | None = None
        self._loading = True
        self._error: str | None = None
        self._feedback: tuple[str, str] | None = None
        self._advanced_open = False
        self._busy_service: str | None = None
        self._render()

    def on_show(self) -> None:
        self.refresh()

    def handle_message(self, message) -> None:
        if message.kind == "settings_data":
            self._data = dict(message.payload.get("result", {}))
            self._loading = False
            self._error = None
            self._render()
        elif message.kind == "settings_applied":
            result = message.payload.get("result", {})
            self._feedback = (
                result.get("title", "Setting updated"),
                result.get("message", "The setting was applied."),
            )
            self._busy_service = None
            self.refresh(preserve_feedback=True)
        elif message.kind == "task_failed":
            task = str(message.payload.get("task", ""))
            if task == "load-settings" or task.startswith("settings-service:"):
                self._loading = False
                self._busy_service = None
                self._error = message.payload.get("error", "The setting could not be applied.")
                self._render()

    def refresh(self, *, preserve_feedback: bool = False) -> None:
        self._loading = True
        self._error = None
        if not preserve_feedback:
            self._feedback = None
        self._render()
        self.controller.load_settings()

    def _render(self) -> None:
        self.clear_body()
        self.body.grid_columnconfigure(0, weight=1)

        if self._loading and self._data is None:
            self._state_card(
                "Loading settings…",
                "AutoGuard is reading the current runtime and startup configuration.",
            )
            return
        if self._error and self._data is None:
            self._state_card("Settings could not be loaded", self._error, tone="danger")
            return
        if not self._data:
            self._state_card("Settings unavailable", "No configuration data is available for this launch.")
            return

        row = 0
        if self._feedback:
            title, message = self._feedback
            row = self._feedback_card(row, title, message, tone="success")
        if self._error:
            row = self._feedback_card(row, "Setting could not be applied", self._error, tone="danger")

        row = self._protection_section(row)
        row = self._schedule_section(row)
        row = self._scan_preferences_section(row)
        row = self._quarantine_section(row)
        row = self._application_section(row)
        self._advanced_section(row)

    def _section(self, row: int, title: str, description: str = "") -> ctk.CTkFrame:
        frame = ctk.CTkFrame(
            self.body,
            fg_color=theme.SURFACE,
            border_width=1,
            border_color=theme.BORDER,
            corner_radius=theme.RADIUS,
        )
        frame.grid(row=row, column=0, padx=8, pady=6, sticky="ew")
        frame.grid_columnconfigure(0, weight=1)
        ctk.CTkLabel(
            frame,
            text=title,
            font=(theme.FONT, 14, "bold"),
            text_color=theme.TEXT,
            anchor="w",
        ).grid(row=0, column=0, padx=16, pady=(14, 2), sticky="ew")
        if description:
            ctk.CTkLabel(
                frame,
                text=description,
                font=(theme.FONT, 9),
                text_color=theme.TEXT_MUTED,
                justify="left",
                anchor="w",
                wraplength=820,
            ).grid(row=1, column=0, padx=16, pady=(0, 8), sticky="ew")
        return frame

    def _service_row(
        self,
        parent: ctk.CTkFrame,
        row: int,
        *,
        name: str,
        description: str,
        service_key: str,
        state: dict,
    ) -> None:
        wrap = ctk.CTkFrame(parent, fg_color="transparent")
        wrap.grid(row=row, column=0, padx=16, pady=5, sticky="ew")
        wrap.grid_columnconfigure(0, weight=1)
        text = ctk.CTkFrame(wrap, fg_color="transparent")
        text.grid(row=0, column=0, sticky="ew")
        ctk.CTkLabel(
            text, text=name, font=(theme.FONT, 10, "bold"), text_color=theme.TEXT, anchor="w"
        ).pack(anchor="w")
        ctk.CTkLabel(
            text,
            text=description,
            font=(theme.FONT, 9),
            text_color=theme.TEXT_MUTED,
            anchor="w",
            justify="left",
            wraplength=620,
        ).pack(anchor="w", pady=(2, 0))

        status = state.get("status", "Unavailable")
        status_color = (
            theme.SUCCESS if state.get("running") else
            (theme.WARNING if state.get("available") else theme.TEXT_DIM)
        )
        ctk.CTkLabel(
            wrap,
            text=status,
            font=(theme.FONT, 9, "bold"),
            text_color=status_color,
            width=112,
            anchor="e",
        ).grid(row=0, column=1, padx=(12, 10), sticky="e")

        available = bool(state.get("available"))
        running = bool(state.get("running"))
        busy = self._busy_service == service_key
        button = ctk.CTkButton(
            wrap,
            text="Applying…" if busy else ("Turn off" if running else "Turn on"),
            width=88,
            height=30,
            fg_color=theme.SURFACE_ALT if running else theme.ACCENT_DARK,
            hover_color=theme.SURFACE_HOVER if running else theme.ACCENT_DARK,
            border_width=1,
            border_color=theme.BORDER,
            text_color=theme.TEXT if available else theme.TEXT_DIM,
            state="disabled" if (not available or busy) else "normal",
            command=lambda: self._set_service(service_key, not running),
        )
        button.grid(row=0, column=2, sticky="e")

    def _info_row(
        self,
        parent: ctk.CTkFrame,
        row: int,
        label: str,
        value: str,
        *,
        detail: str = "",
        mono: bool = False,
    ) -> None:
        wrap = ctk.CTkFrame(parent, fg_color="transparent")
        wrap.grid(row=row, column=0, padx=16, pady=5, sticky="ew")
        wrap.grid_columnconfigure(0, weight=1)
        ctk.CTkLabel(
            wrap, text=label, font=(theme.FONT, 10), text_color=theme.TEXT_MUTED, anchor="w"
        ).grid(row=0, column=0, sticky="w")
        ctk.CTkLabel(
            wrap,
            text=value,
            font=(theme.FONT_MONO if mono else theme.FONT, 9 if mono else 10),
            text_color=theme.TEXT,
            anchor="e",
            justify="right",
            wraplength=650,
        ).grid(row=0, column=1, padx=(12, 0), sticky="e")
        if detail:
            ctk.CTkLabel(
                wrap,
                text=detail,
                font=(theme.FONT, 9),
                text_color=theme.TEXT_DIM,
                anchor="w",
                justify="left",
                wraplength=820,
            ).grid(row=1, column=0, columnspan=2, pady=(2, 0), sticky="ew")

    def _protection_section(self, row: int) -> int:
        protection = self._data["protection"]
        card = self._section(
            row,
            "Protection",
            "Runtime switches use the existing protection services. No duplicate monitor or worker is created.",
        )
        offset = 2
        self._service_row(
            card, offset,
            name="Real-time protection",
            description="Monitors configured folders for new or changed files.",
            service_key="real_time",
            state=protection["real_time"],
        )
        self._service_row(
            card, offset + 1,
            name="USB protection",
            description="Detects supported removable drives and dispatches USB scans.",
            service_key="usb",
            state=protection["usb"],
        )
        startup = protection["startup_scan"]
        self._info_row(
            card,
            offset + 2,
            "Startup Quick Scan",
            startup["status"],
            detail=startup["detail"] + " This startup-only choice is not editable in the current in-app configuration layer.",
        )
        ctk.CTkLabel(card, text="", height=6).grid(row=offset + 3, column=0)
        return row + 1

    def _schedule_section(self, row: int) -> int:
        schedule = self._data["schedule"]
        protection = self._data["protection"]
        card = self._section(
            row,
            "Scheduled Scanning",
            "Turn recurring scanning on or off for this session. Existing scan intervals remain startup-configured.",
        )
        self._service_row(
            card, 2,
            name="Scheduled scanning",
            description="Uses AutoGuard's existing scheduler and overlap-prevention gate.",
            service_key="scheduled",
            state=protection["scheduled"],
        )
        self._info_row(card, 3, "Quick Scan", f"Every {schedule['quick_hours']:g} hours")
        self._info_row(card, 4, "Full Scan", f"Every {schedule['full_days']:g} days")
        self._info_row(
            card,
            5,
            "Schedule editing",
            "Configured at launch",
            detail="AutoGuard does not currently expose a persisted in-app reschedule API, so Phase 11 does not create a fake frequency editor.",
        )
        ctk.CTkLabel(card, text="", height=6).grid(row=6, column=0)
        return row + 1

    def _scan_preferences_section(self, row: int) -> int:
        prefs = self._data["scan_preferences"]
        card = self._section(
            row,
            "Scan Preferences",
            "Current protected scope and scanner limits. Values shown here come from the active scanner/services.",
        )
        mib = prefs["max_file_size_bytes"] / (1024 * 1024)
        self._info_row(
            card,
            2,
            "Maximum file size",
            f"{mib:g} MiB",
            detail="The current scanner limit is startup-configured in this build.",
        )
        ctk.CTkLabel(
            card,
            text="Protected locations",
            font=(theme.FONT, 10, "bold"),
            text_color=theme.TEXT,
            anchor="w",
        ).grid(row=3, column=0, padx=16, pady=(8, 3), sticky="ew")
        paths = prefs.get("monitor_paths", ())
        if paths:
            for index, path in enumerate(paths, start=4):
                ctk.CTkLabel(
                    card,
                    text=str(path),
                    font=(theme.FONT_MONO, 9),
                    text_color=theme.TEXT_MUTED,
                    justify="left",
                    anchor="w",
                    wraplength=820,
                ).grid(row=index, column=0, padx=16, pady=2, sticky="ew")
            end_row = 4 + len(paths)
        else:
            ctk.CTkLabel(
                card,
                text="No protected locations are available for this launch.",
                font=(theme.FONT, 9),
                text_color=theme.TEXT_DIM,
                anchor="w",
            ).grid(row=4, column=0, padx=16, pady=2, sticky="ew")
            end_row = 5
        ctk.CTkLabel(
            card,
            text="Custom exclusions are not exposed because AutoGuard does not currently have a user-configurable exclusion service.",
            font=(theme.FONT, 9),
            text_color=theme.TEXT_DIM,
            justify="left",
            anchor="w",
            wraplength=820,
        ).grid(row=end_row, column=0, padx=16, pady=(7, 14), sticky="ew")
        return row + 1

    def _quarantine_section(self, row: int) -> int:
        data = self._data["quarantine"]
        card = self._section(
            row,
            "Quarantine",
            "Only behavior already implemented by the existing quarantine service is shown.",
        )
        self._info_row(card, 2, "Retention", data["retention"], detail=data["detail"])
        ctk.CTkLabel(card, text="", height=8).grid(row=3, column=0)
        return row + 1

    def _application_section(self, row: int) -> int:
        data = self._data["application"]
        card = self._section(
            row,
            "Application",
            "Application-level locations and configuration behavior supported by the current build.",
        )
        self._info_row(card, 2, "Logs", "Enabled", detail=f"Stored in {data['logs_dir']}")
        self._info_row(card, 3, "AutoGuard data", data["data_dir"], mono=True)
        self._info_row(card, 4, "Configuration", "Startup + runtime services", detail=data["configuration_note"])
        ctk.CTkLabel(card, text="", height=8).grid(row=5, column=0)
        return row + 1

    def _advanced_section(self, row: int) -> None:
        card = self._section(
            row,
            "Advanced",
            "Developer-oriented runtime paths and timing information are hidden by default.",
        )
        ctk.CTkButton(
            card,
            text="Hide advanced details" if self._advanced_open else "Show advanced details",
            width=154,
            height=30,
            fg_color=theme.SURFACE_ALT,
            hover_color=theme.SURFACE_HOVER,
            border_width=1,
            border_color=theme.BORDER,
            text_color=theme.TEXT,
            command=self._toggle_advanced,
        ).grid(row=2, column=0, padx=16, pady=(4, 12), sticky="w")
        if not self._advanced_open:
            return
        advanced = self._data["advanced"]
        detail_row = 3
        entries = [
            ("Database", advanced["database"], True),
            ("Quarantine storage", advanced["quarantine_storage"], True),
            ("File monitor debounce", self._seconds(advanced.get("debounce_seconds")), False),
            ("File stability window", self._seconds(advanced.get("stability_seconds")), False),
            ("USB polling interval", self._seconds(advanced.get("usb_poll_seconds")), False),
        ]
        for label, value, mono in entries:
            self._info_row(card, detail_row, label, value, mono=mono)
            detail_row += 1
        self._path_group(card, detail_row, "Quick Scan targets", advanced.get("quick_paths", ()))
        detail_row += 1
        self._path_group(card, detail_row, "Full Scan targets", advanced.get("full_paths", ()))
        ctk.CTkLabel(card, text="", height=8).grid(row=detail_row + 1, column=0)

    def _path_group(self, parent: ctk.CTkFrame, row: int, label: str, paths) -> None:
        value = " • ".join(str(path) for path in paths) if paths else "None"
        self._info_row(parent, row, label, value, mono=True)

    @staticmethod
    def _seconds(value) -> str:
        if value is None:
            return "Unavailable"
        return f"{float(value):g} seconds"

    def _toggle_advanced(self) -> None:
        self._advanced_open = not self._advanced_open
        self._render()

    def _set_service(self, service_key: str, enabled: bool) -> None:
        self._busy_service = service_key
        self._feedback = None
        self._error = None
        self._render()
        self.controller.set_protection_service(service_key, enabled)

    def _state_card(self, title: str, message: str, *, tone: str = "info") -> None:
        self._feedback_card(0, title, message, tone=tone)

    def _feedback_card(self, row: int, title: str, message: str, *, tone: str) -> int:
        colors = {
            "success": theme.SUCCESS,
            "danger": theme.DANGER,
            "warning": theme.WARNING,
            "info": theme.INFO,
        }
        card = ctk.CTkFrame(
            self.body,
            fg_color=theme.SURFACE,
            border_width=1,
            border_color=theme.BORDER,
            corner_radius=theme.RADIUS,
        )
        card.grid(row=row, column=0, padx=8, pady=(4, 8), sticky="ew")
        card.grid_columnconfigure(0, weight=1)
        ctk.CTkLabel(
            card,
            text=title,
            font=(theme.FONT, 11, "bold"),
            text_color=colors.get(tone, theme.TEXT),
            anchor="w",
        ).grid(row=0, column=0, padx=16, pady=(11, 2), sticky="ew")
        ctk.CTkLabel(
            card,
            text=message,
            font=(theme.FONT, 9),
            text_color=theme.TEXT_MUTED,
            justify="left",
            anchor="w",
            wraplength=820,
        ).grid(row=1, column=0, padx=16, pady=(0, 11), sticky="ew")
        return row + 1