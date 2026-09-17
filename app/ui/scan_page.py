"""Scan chooser, active scan, and completed-result presentation.

Phase 3 owns the idle Quick/Full/Custom chooser. Phase 4 owns the focused
active-scan view. Phase 5 adds the completed result experience. All scanner,
hashing, detection, containment, and persistence work remains in the controller
and backend services.
"""
from __future__ import annotations

from tkinter import filedialog

import customtkinter as ctk

from app.models import ScanStatus
from app.ui import theme
from app.ui.base_page import BasePage
from app.ui.components import ActiveScanPanel, ScanOptionCard, ScanResultPanel


class ScanPage(BasePage):
    title = "Scan"
    subtitle = "Choose how AutoGuard should check your files"

    def __init__(self, master, controller, **kwargs):
        super().__init__(master, controller, **kwargs)
        self.body.grid_columnconfigure(0, weight=1)
        self._scan_running = False
        self._result_pending = False
        self._result_visible = False
        self._last_result: dict = {}
        self.counts = {
            "scanned": 0,
            "skipped": 0,
            "suspicious": 0,
            "dangerous": 0,
            "errors": 0,
        }
        self._build_idle_view()
        self._build_active_view()
        self._build_result_view()
        self._show_idle_view()

    def _build_idle_view(self) -> None:
        self.idle_view = ctk.CTkFrame(self.body, fg_color="transparent", corner_radius=0)
        self.idle_view.grid_columnconfigure(0, weight=1)

        ctk.CTkLabel(
            self.idle_view,
            text="Scan your PC",
            text_color=theme.TEXT,
            font=(theme.FONT, 22, "bold"),
            anchor="w",
        ).grid(row=0, column=0, padx=8, pady=(4, 3), sticky="ew")
        ctk.CTkLabel(
            self.idle_view,
            text="Choose the scan that matches what you want to check.",
            text_color=theme.TEXT_MUTED,
            font=(theme.FONT, 11),
            anchor="w",
        ).grid(row=1, column=0, padx=8, pady=(0, 16), sticky="ew")

        quick = ScanOptionCard(
            self.idle_view,
            title="Quick Scan",
            description="Checks common places where new files usually appear.",
            detail="Downloads  •  Desktop  •  Documents",
            recommended=True,
            actions=(("Start Quick Scan", self.controller.start_quick_scan, True),),
        )
        quick.grid(row=2, column=0, padx=8, pady=(0, 10), sticky="ew")

        full = ScanOptionCard(
            self.idle_view,
            title="Full Scan",
            description=(
                "Performs a broader scan of your computer. This checks more files "
                "and can take significantly longer than a Quick Scan."
            ),
            actions=(("Start Full Scan", self.controller.start_full_scan, False),),
        )
        full.grid(row=3, column=0, padx=8, pady=(0, 10), sticky="ew")

        custom = ScanOptionCard(
            self.idle_view,
            title="Custom Scan",
            description="Scan one specific file or choose a folder you want AutoGuard to check.",
            actions=(
                ("Choose File", self._choose_file, True),
                ("Choose Folder", self._choose_folder, False),
            ),
        )
        custom.grid(row=4, column=0, padx=8, pady=(0, 10), sticky="ew")

    def _build_active_view(self) -> None:
        self.active_view = ctk.CTkFrame(self.body, fg_color="transparent", corner_radius=0)
        self.active_view.grid_columnconfigure(0, weight=1)
        self.active_scan = ActiveScanPanel(
            self.active_view,
            on_stop=self.controller.stop_scan,
        )
        self.active_scan.grid(row=0, column=0, padx=8, pady=8, sticky="ew")

    def _build_result_view(self) -> None:
        self.result_view = ctk.CTkFrame(self.body, fg_color="transparent", corner_radius=0)
        self.result_view.grid_columnconfigure(0, weight=1)
        self.scan_result = ScanResultPanel(
            self.result_view,
            on_done=self._done_with_result,
            on_view_details=lambda: self.controller.navigate_to("activity"),
            on_review_files=lambda: self.controller.navigate_to("threats"),
            on_view_threat=self._view_result_threat,
        )
        self.scan_result.grid(row=0, column=0, padx=8, pady=8, sticky="ew")

    def _view_result_threat(self) -> None:
        threat_ref = self._last_result.get("primary_threat_ref")
        if threat_ref:
            self.controller.open_threat_details(threat_ref)
        else:
            self.controller.navigate_to("threats")

    def refresh_from_state(self, reason: str = "") -> None:
        # Scan state is synchronized continuously through scan_* bus messages,
        # including while this page is hidden. No service/database reload needed.
        return

    def _choose_file(self) -> None:
        path = filedialog.askopenfilename(title="Choose a file to scan")
        if path:
            self.controller.start_scan(path)

    def _choose_folder(self) -> None:
        path = filedialog.askdirectory(title="Choose a folder to scan")
        if path:
            self.controller.start_scan(path)

    def _hide_views(self) -> None:
        self.idle_view.grid_remove()
        self.active_view.grid_remove()
        self.result_view.grid_remove()

    def _show_idle_view(self) -> None:
        self._hide_views()
        self.idle_view.grid(row=0, column=0, sticky="ew")

    def _show_active_view(self) -> None:
        self._hide_views()
        self.active_view.grid(row=0, column=0, sticky="ew")

    def _show_result_view(self) -> None:
        self._hide_views()
        self.result_view.grid(row=0, column=0, sticky="ew")

    def _done_with_result(self) -> None:
        self._result_visible = False
        self._result_pending = False
        self._show_idle_view()

    def on_show(self) -> None:
        if self._result_visible:
            self._show_result_view()
        elif self._scan_running or self._result_pending:
            self._show_active_view()
        else:
            self._show_idle_view()

    def handle_message(self, message) -> None:
        if message.kind == "scan_started":
            self._scan_running = True
            self._result_pending = False
            self._result_visible = False
            self.counts = {key: 0 for key in self.counts}
            self.active_scan.start(
                message.payload.get("scan_type", "manual"),
                message.payload.get("path", ""),
            )
            self._show_active_view()

        elif message.kind == "scan_discovered":
            self.active_scan.update_discovery(
                message.payload.get("discovered", 0),
                message.payload.get("processed", 0),
                message.payload.get("path", ""),
            )

        elif message.kind == "scan_result":
            cumulative = message.payload.get("counts")
            if cumulative is not None:
                # Performance hotfix: the controller may coalesce many per-file
                # callbacks into one UI paint. Cumulative counters keep the UI exact.
                self.counts = {
                    key: int(cumulative.get(key, 0)) for key in self.counts
                }
            else:
                # Backward-compatible path for older controller messages/tests.
                status = message.payload["status"]
                detection = message.payload.get("detection")
                if status == ScanStatus.SCANNED.value:
                    self.counts["scanned"] += 1
                elif status == ScanStatus.ERROR.value:
                    self.counts["errors"] += 1
                else:
                    self.counts["skipped"] += 1
                if detection == "LOW_CONFIDENCE":
                    self.counts["suspicious"] += 1
                elif detection == "HIGH_CONFIDENCE":
                    self.counts["dangerous"] += 1

            self.active_scan.update_progress(
                processed=message.payload.get("processed", 0),
                discovered=message.payload.get("discovered", 0),
                counts=self.counts,
                current_path=message.payload.get("path", ""),
            )

        elif message.kind == "scan_stop_requested":
            self.active_scan.stopping()

        elif message.kind == "scan_stopped":
            self._scan_running = False
            self._result_pending = False
            self._result_visible = False
            self.active_scan.end()
            self._show_idle_view()

        elif message.kind in ("scan_completed", "scan_batch_completed"):
            self._scan_running = False
            self._result_pending = True
            self._result_visible = False
            self.active_scan.finishing()
            self._show_active_view()
            self.controller.prepare_scan_result(message.payload.get("result"))

        elif message.kind == "scan_result_ready":
            self._result_pending = False
            self._result_visible = True
            self.active_scan.end()
            self._last_result = dict(message.payload.get("result", {}))
            self.scan_result.show_result(self._last_result)
            self._show_result_view()

        elif message.kind == "scan_rejected":
            return

        elif message.kind == "task_failed" and "scan" in str(message.payload.get("task", "")):
            self._scan_running = False
            self._result_pending = False
            self._result_visible = False
            self.active_scan.end()
            self._show_idle_view()