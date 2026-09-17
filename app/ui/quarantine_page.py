"""Simplified Quarantine experience for AutoGuard UX Refresh Phase 9."""
from __future__ import annotations

import customtkinter as ctk

from app.ui import theme
from app.ui.base_page import BasePage
from app.ui.components import ConfirmDialog, RestoreDialog, StateCard, StatusBadge
from app.ui.quarantine_details_page import QuarantineDetailsView


_STATUS_STYLE = {
    "attention": (theme.WARNING, theme.WARNING_DARK),
    "reviewing": (theme.WARNING, theme.WARNING_DARK),
    "contained": (theme.SUCCESS, theme.SUCCESS_DARK),
    "reappeared": (theme.WARNING, theme.WARNING_DARK),
    "restored": (theme.INFO, theme.INFO_DARK),
    "resolved": (theme.TEXT_MUTED, theme.SURFACE_ALT),
}


class QuarantinePage(BasePage):
    title = "Quarantine"
    subtitle = "Files AutoGuard has isolated from their original locations"

    def __init__(self, master, controller, **kwargs):
        super().__init__(master, controller, **kwargs)
        self._detail_ref: str | None = None
        self._detail_data: dict | None = None
        self._list_data: dict | None = None
        self._notice: dict | None = None

    def on_show(self):
        if self.controller.selected_quarantine_ref:
            self._detail_ref = self.controller.selected_quarantine_ref
            self._show_loading("Loading file details…")
            self.controller.load_quarantine_details(self._detail_ref)
        else:
            self._detail_ref = None
            self._show_loading("Loading quarantine…")
            self.controller.load_quarantine()

    def refresh_from_state(self, reason: str = "") -> None:
        self._refresh_current()

    def handle_message(self, message):
        kind = message.kind
        if kind == "quarantine_data" and self._detail_ref is None:
            result = dict(message.payload.get("result", {}))
            if result != self._list_data:
                self._list_data = result
                self._render_list(result)
        elif kind == "quarantine_details_requested":
            self._detail_ref = message.payload.get("item_ref")
            self._detail_data = None
            self._show_loading("Loading file details…")
            self.controller.load_quarantine_details(self._detail_ref)
        elif kind == "quarantine_details_data":
            result = message.payload.get("result", {})
            if self._detail_ref and result.get("item_ref") == self._detail_ref:
                if result != self._detail_data:
                    self._detail_data = result
                    self._render_details(result)
        elif kind == "quarantine_details_closed":
            self._detail_ref = None
            self._detail_data = None
            self._show_loading("Loading quarantine…")
            self.controller.load_quarantine()
        elif kind == "quarantine_verified":
            result = message.payload.get("result", {})
            self._notice = {
                "title": result.get("title", "Integrity check finished"),
                "message": result.get("message", "The integrity check finished."),
                "tone": "success" if result.get("verified") else "error",
            }
            self._refresh_current()
        elif kind == "recovery_completed":
            result = message.payload.get("result", {})
            self._notice = {
                "title": result.get("title", "Restore finished"),
                "message": result.get("message", "The restore operation finished."),
                "tone": result.get("tone", "info"),
            }
            self._refresh_current()
        elif kind == "quarantine_deleted":
            result = message.payload.get("result", {})
            self._notice = {
                "title": result.get("title", "Removed from quarantine"),
                "message": result.get("message", "The isolated file was removed."),
                "tone": "warning",
            }
            if self._detail_ref == result.get("item_ref"):
                self._detail_ref = None
                self._detail_data = None
                self.controller.close_quarantine_details()
            else:
                self.controller.load_quarantine()
        elif kind == "task_started":
            task = str(message.payload.get("task", ""))
            if task.startswith("verify-quarantine:"):
                self._notice = {"title": "Verifying integrity", "message": "AutoGuard is checking the isolated file…", "tone": "info"}
                if self._detail_data:
                    self._render_details(self._detail_data)
            elif task.startswith("restore:"):
                self._notice = {"title": "Restoring file", "message": "AutoGuard is verifying and re-evaluating the file before restoration…", "tone": "info"}
                if self._detail_data:
                    self._render_details(self._detail_data)
            elif task.startswith("delete-quarantine:"):
                self._notice = {"title": "Deleting file", "message": "AutoGuard is permanently removing the isolated file…", "tone": "info"}
                if self._detail_data:
                    self._render_details(self._detail_data)
        elif kind == "task_failed":
            task = str(message.payload.get("task", ""))
            if task.startswith(("load-quarantine", "verify-quarantine:", "restore:", "delete-quarantine:")):
                self._notice = {
                    "title": "Operation failed",
                    "message": message.payload.get("error", "AutoGuard could not complete this operation."),
                    "tone": "error",
                }
                if self._detail_data:
                    self._render_details(self._detail_data)
                elif self._detail_ref is None:
                    self._render_error(self._notice["message"])

    def _refresh_current(self):
        if self._detail_ref:
            self.controller.load_quarantine_details(self._detail_ref)
        else:
            self.controller.load_quarantine()

    def _show_loading(self, text: str):
        self.clear_body()
        self.body.grid_columnconfigure(0, weight=1)
        StateCard(self.body, text, "This may take a moment.").grid(
            row=0, column=0, padx=8, pady=8, sticky="ew"
        )

    def _render_error(self, message: str):
        self.clear_body()
        self.body.grid_columnconfigure(0, weight=1)
        StateCard(self.body, "Could not load quarantine", message, tone="danger").grid(
            row=0, column=0, padx=8, pady=8, sticky="ew"
        )

    def _notice_widget(self, parent, row: int):
        if not self._notice:
            return row
        tone = self._notice.get("tone", "info")
        style = {
            "success": (theme.SUCCESS, theme.SUCCESS_DARK),
            "warning": (theme.WARNING, theme.WARNING_DARK),
            "error": (theme.DANGER, theme.DANGER_DARK),
            "info": (theme.INFO, theme.INFO_DARK),
        }
        color, background = style.get(tone, style["info"])
        box = ctk.CTkFrame(parent, fg_color=background, border_width=1, border_color=color, corner_radius=theme.RADIUS_SMALL)
        box.grid(row=row, column=0, padx=8, pady=(2, 10), sticky="ew")
        box.grid_columnconfigure(0, weight=1)
        ctk.CTkLabel(box, text=self._notice.get("title", "Update"), font=(theme.FONT, 11, "bold"), text_color=color, anchor="w").grid(row=0, column=0, padx=14, pady=(10, 2), sticky="ew")
        ctk.CTkLabel(box, text=self._notice.get("message", ""), font=(theme.FONT, 9), text_color=theme.TEXT, anchor="w", justify="left", wraplength=800).grid(row=1, column=0, padx=14, pady=(0, 10), sticky="ew")
        return row + 1

    def _render_list(self, data: dict):
        self.clear_body()
        self.body.grid_columnconfigure(0, weight=1)
        row = self._notice_widget(self.body, 0)
        count = int(data.get("isolated_count", 0))
        summary = ctk.CTkFrame(self.body, fg_color="transparent")
        summary.grid(row=row, column=0, padx=8, pady=(2, 12), sticky="ew")
        summary.grid_columnconfigure(0, weight=1)
        ctk.CTkLabel(
            summary,
            text=f"{count:,} {'file' if count == 1 else 'files'} safely isolated",
            font=(theme.FONT, 18, "bold"),
            text_color=theme.TEXT,
            anchor="w",
        ).grid(row=0, column=0, sticky="w")
        ctk.CTkLabel(
            summary,
            text="Isolated files are kept separate from their original locations until you restore or delete them.",
            font=(theme.FONT, 10),
            text_color=theme.TEXT_MUTED,
            anchor="w",
            justify="left",
            wraplength=820,
        ).grid(row=1, column=0, pady=(3, 0), sticky="ew")
        row += 1

        items = tuple(data.get("items", ()))
        if not items:
            empty = ctk.CTkFrame(self.body, fg_color=theme.SURFACE, border_width=1, border_color=theme.BORDER, corner_radius=theme.RADIUS)
            empty.grid(row=row, column=0, padx=8, pady=6, sticky="ew")
            ctk.CTkLabel(empty, text="No files are currently isolated", font=(theme.FONT, 14, "bold"), text_color=theme.TEXT, anchor="w").grid(row=0, column=0, padx=18, pady=(18, 4), sticky="w")
            ctk.CTkLabel(empty, text="Quarantine will show files here when AutoGuard successfully isolates them.", font=(theme.FONT, 10), text_color=theme.TEXT_MUTED, anchor="w").grid(row=1, column=0, padx=18, pady=(0, 18), sticky="w")
            return

        for item in items:
            card = ctk.CTkFrame(self.body, fg_color=theme.SURFACE, border_width=1, border_color=theme.BORDER, corner_radius=theme.RADIUS)
            card.grid(row=row, column=0, padx=8, pady=6, sticky="ew")
            card.grid_columnconfigure(0, weight=1)
            ctk.CTkLabel(card, text=item.get("name", "Isolated file"), font=(theme.FONT, 13, "bold"), text_color=theme.TEXT, anchor="w").grid(row=0, column=0, padx=16, pady=(14, 2), sticky="ew")
            ctk.CTkLabel(card, text=f"Contained {item.get('contained', 'time unavailable')}", font=(theme.FONT, 9), text_color=theme.TEXT_MUTED, anchor="w").grid(row=1, column=0, padx=16, sticky="ew")
            ctk.CTkLabel(card, text=f"Original location: {item.get('original_location', 'Unavailable')}", font=(theme.FONT, 9), text_color=theme.TEXT_DIM, anchor="w", justify="left", wraplength=650).grid(row=2, column=0, padx=16, pady=(2, 12), sticky="ew")

            StatusBadge(
                card, item.get("threat_status", "Threat recorded"), item.get("threat_status_key", "idle")
            ).grid(row=0, column=1, padx=(8, 16), pady=(14, 2), sticky="e")
            actions = ctk.CTkFrame(card, fg_color="transparent")
            actions.grid(row=1, column=1, rowspan=2, padx=13, pady=(4, 12), sticky="e")
            ref = item.get("item_ref")
            ctk.CTkButton(actions, text="View", width=70, height=28, fg_color=theme.SURFACE_ALT, hover_color=theme.SURFACE_HOVER, command=lambda q=ref: self.controller.open_quarantine_details(q)).pack(side="left", padx=3)
            ctk.CTkButton(actions, text="Restore", width=76, height=28, fg_color=theme.SURFACE_ALT, hover_color=theme.SURFACE_HOVER, command=lambda q=ref, path=item.get("original_location", ""): self._restore(q, path)).pack(side="left", padx=3)
            ctk.CTkButton(actions, text="Delete", width=70, height=28, fg_color=theme.DANGER_DARK, hover_color=theme.DANGER, text_color=theme.DANGER, command=lambda q=ref, name=item.get("name", "this file"): self._delete(q, name)).pack(side="left", padx=3)
            row += 1

    def _render_details(self, data: dict):
        self.clear_body()
        self.body.grid_columnconfigure(0, weight=1)
        row = self._notice_widget(self.body, 0)
        ref = data.get("item_ref")
        details = QuarantineDetailsView(
            self.body,
            data,
            on_back=self.controller.close_quarantine_details,
            on_verify=lambda q=ref: self.controller.verify_quarantine(q),
            on_restore=lambda q=ref, path=data.get("original_location", ""): self._restore(q, path),
            on_delete=lambda q=ref, name=data.get("name", "this file"): self._delete(q, name),
        )
        details.grid(row=row, column=0, sticky="ew")

    def _restore(self, item_ref: str, original_path: str):
        RestoreDialog(
            self,
            original_path,
            lambda destination: self.controller.restore_quarantine(item_ref, destination),
        )

    def _delete(self, item_ref: str, name: str):
        ConfirmDialog(
            self,
            "Permanently delete isolated file",
            (
                f"Delete {name} from AutoGuard quarantine?\n\n"
                "This permanently removes the isolated file. Audit history is retained, "
                "but the file can no longer be restored from quarantine."
            ),
            confirm_text="Delete permanently",
            danger=True,
            on_confirm=lambda: self.controller.delete_quarantine(item_ref),
        )