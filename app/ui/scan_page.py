"""Scan chooser, active scan, and completed-result presentation.

Phase 3 owns the idle Quick/Full/Custom chooser. Phase 4 owns the focused
active-scan view. Phase 5 adds the completed result experience. All scanner,
hashing, detection, containment, and persistence work remains in the controller
and backend services.
"""
from __future__ import annotations

import tkinter as tk
from pathlib import Path
from tkinter import filedialog

import customtkinter as ctk

from app.models import ScanStatus
from app.hashing import normalize_path
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
        self._automatic_scan_running = False
        self._automatic_scan_key: tuple[str, object] | None = None
        self._result_pending = False
        self._result_visible = False
        self._last_result: dict = {}
        self._selected_targets: list[tuple[Path, str]] = []
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
        self.after(350, self._poll_automatic_scan)

    def _build_idle_view(self) -> None:
        self.idle_view = ctk.CTkFrame(self.body, fg_color="transparent", corner_radius=0)
        self.idle_view.grid_columnconfigure(0, weight=1)

        theme.Label(
            self.idle_view,
            text="Scan your PC",
            text_color=theme.TEXT,
            font=theme.font("page", "bold", theme.FONT),
            anchor="w",
        ).grid(row=0, column=0, padx=8, pady=(4, 3), sticky="ew")
        theme.Label(
            self.idle_view,
            text="Choose the scan that matches what you want to check.",
            text_color=theme.TEXT_MUTED,
            font=theme.font("body", "normal", theme.FONT),
            anchor="w",
        ).grid(row=1, column=0, padx=8, pady=(0, 16), sticky="ew")

        self.background_scan_status = theme.Label(
            self.idle_view,
            text="Checking real-time protection status...",
            text_color=theme.TEXT_MUTED,
            font=theme.font("secondary"),
            anchor="w",
        )
        self.background_scan_status.grid(row=2, column=0, padx=8, pady=(0, 12), sticky="ew")

        quick = ScanOptionCard(
            self.idle_view,
            title="Quick Scan",
            description="Checks common places where new files usually appear.",
            detail="Downloads  •  Desktop  •  Documents",
            recommended=True,
            actions=(("Start Quick Scan", self.controller.start_quick_scan, True),),
        )
        quick.grid(row=3, column=0, padx=8, pady=(0, 10), sticky="ew")

        full = ScanOptionCard(
            self.idle_view,
            title="Full Scan",
            description=(
                "Performs a broader scan of your computer. This checks more files "
                "and can take significantly longer than a Quick Scan."
            ),
            actions=(("Start Full Scan", self.controller.start_full_scan, False),),
        )
        full.grid(row=4, column=0, padx=8, pady=(0, 10), sticky="ew")

        custom = ctk.CTkFrame(self.idle_view, fg_color=theme.SURFACE, border_width=1,
                              border_color=theme.BORDER, corner_radius=theme.RADIUS)
        custom.grid_columnconfigure(0, weight=1)
        theme.Label(custom, text="Custom Scan", text_color=theme.TEXT,
                    font=theme.font("card", "bold", theme.FONT), anchor="w").grid(
                        row=0, column=0, padx=18, pady=(16, 4), sticky="ew")
        theme.Label(custom, text="Add any mix of files and folders. Folder selections include files beneath them.",
                    text_color=theme.TEXT_MUTED, font=theme.font("body"), anchor="w",
                    wraplength=820).grid(row=1, column=0, padx=18, sticky="ew")
        pickers = ctk.CTkFrame(custom, fg_color="transparent")
        pickers.grid(row=2, column=0, padx=18, pady=(12, 8), sticky="ew")
        theme.Button(pickers, text="Add Files", command=self._choose_file, height=38,
                     fg_color=theme.SURFACE_ALT, hover_color=theme.SURFACE_HOVER,
                     text_color=theme.TEXT, font=theme.font("body", "bold")).pack(side="left", padx=(0, 8))
        theme.Button(pickers, text="Add Folder", command=self._choose_folder, height=38,
                     fg_color=theme.SURFACE_ALT, hover_color=theme.SURFACE_HOVER,
                     text_color=theme.TEXT, font=theme.font("body", "bold")).pack(side="left")

        list_frame = ctk.CTkFrame(custom, fg_color=theme.SURFACE_ALT, corner_radius=theme.RADIUS_SMALL)
        list_frame.grid(row=3, column=0, padx=18, pady=(0, 8), sticky="ew")
        list_frame.grid_columnconfigure(0, weight=1)
        list_frame.grid_rowconfigure(0, weight=1)
        list_font = (theme.FONT, round(14 * theme.TEXT_SCALES[theme.text_size()]))
        self.target_listbox = tk.Listbox(
            list_frame, height=5, selectmode=tk.EXTENDED, activestyle="none",
            background=theme.SURFACE_ALT, foreground=theme.TEXT,
            selectbackground=theme.ACCENT_DARK, selectforeground=theme.TEXT,
            highlightthickness=0, relief="flat", font=list_font,
        )
        self.target_listbox.grid(row=0, column=0, sticky="nsew", padx=(8, 0), pady=8)
        self._target_yscroll = ctk.CTkScrollbar(list_frame, command=self.target_listbox.yview)
        self._target_yscroll.grid(row=0, column=1, sticky="ns", padx=(4, 8), pady=8)
        self._target_xscroll = ctk.CTkScrollbar(list_frame, orientation="horizontal", command=self.target_listbox.xview)
        self._target_xscroll.grid(row=1, column=0, sticky="ew", padx=(8, 0), pady=(0, 8))
        self.target_listbox.configure(
            xscrollcommand=self._target_xscroll.set,
            yscrollcommand=self._target_yscroll.set,
        )
        self.target_listbox.bind("<<ListboxSelect>>", self._update_target_controls)

        target_actions = ctk.CTkFrame(custom, fg_color="transparent")
        target_actions.grid(row=4, column=0, padx=18, pady=(0, 8), sticky="ew")
        target_actions.grid_columnconfigure(0, weight=1)
        self.selected_target_count = theme.Label(target_actions, text="0 targets selected",
                                                 text_color=theme.TEXT_MUTED, anchor="w")
        self.selected_target_count.grid(row=0, column=0, sticky="w")
        self.remove_targets_button = theme.Button(
            target_actions, text="Remove Selected", command=self._remove_selected_targets,
            width=145, height=36, fg_color=theme.SURFACE_ALT,
            hover_color=theme.SURFACE_HOVER, text_color=theme.TEXT,
        )
        self.remove_targets_button.grid(row=0, column=1, padx=(8, 0))
        self.clear_targets_button = theme.Button(
            target_actions, text="Clear All", command=self._clear_targets,
            width=100, height=36, fg_color=theme.SURFACE_ALT,
            hover_color=theme.SURFACE_HOVER, text_color=theme.TEXT,
        )
        self.clear_targets_button.grid(row=0, column=2, padx=(8, 0))
        self.custom_scan_button = theme.Button(
            custom, text="Scan Selected Files and Folders", command=self._start_custom_scan,
            height=44, fg_color=theme.ACCENT, hover_color=theme.ACCENT_HOVER,
            text_color=theme.BG, font=theme.font("body", "bold"), state="disabled",
        )
        self.custom_scan_button.grid(row=5, column=0, padx=18, pady=(0, 16), sticky="ew")
        custom.grid(row=5, column=0, padx=8, pady=(0, 10), sticky="ew")

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

    def _poll_automatic_scan(self) -> None:
        """Attach the Scan page to startup/scheduled scans already in progress."""
        try:
            self._update_background_scan_status()
            progress = self.controller.automatic_scan_progress()
            if not self._scan_running and not self._result_pending and not self._result_visible:
                if progress is not None:
                    key = (progress.get("ui_type", "scheduled"), progress.get("started_at"))
                    if not self._automatic_scan_running or key != self._automatic_scan_key:
                        self._automatic_scan_running = True
                        self._automatic_scan_key = key
                        self.active_scan.start(
                            progress.get("ui_type", "scheduled"),
                            progress.get("current_path", ""),
                            stoppable=True,
                        )
                    counts = {
                        "scanned": progress.get("files_checked", 0),
                        "skipped": progress.get("skipped", 0),
                        "suspicious": progress.get("suspicious", 0),
                        "dangerous": progress.get("dangerous", 0),
                        "errors": progress.get("errors", 0),
                    }
                    self.active_scan.update_progress(
                        processed=progress.get("processed", 0),
                        discovered=progress.get("discovered", 0),
                        counts=counts,
                        current_path=progress.get("current_path", ""),
                        phase=progress.get("phase", "discovering"),
                        total=progress.get("total"),
                        eta_seconds=progress.get("eta_seconds"),
                        elapsed_seconds=progress.get("elapsed"),
                        bytes_processed=progress.get("bytes_processed", 0),
                    )
                    self._show_active_view()
                elif self._automatic_scan_running:
                    self._automatic_scan_running = False
                    self._automatic_scan_key = None
                    self.active_scan.end()
                    self._show_idle_view()
        finally:
            self.after(600, self._poll_automatic_scan)

    def _update_background_scan_status(self) -> None:
        getter = getattr(self.controller, "realtime_scan_activity", None)
        state = getter() if callable(getter) else {"running": False, "active_paths": ()}
        active_paths = tuple(state.get("active_paths", ()))
        active_usb_roots = tuple(state.get("active_usb_roots", ()))
        activity = []
        if active_paths:
            path = str(active_paths[0]).replace("\\", "/").rsplit("/", 1)[-1]
            activity.append(f"Real-time check: {path}")
        if active_usb_roots:
            activity.append(f"USB scan: {active_usb_roots[0]}")
        if activity:
            status = "Background scanning · " + " · ".join(activity)
            color = theme.ACCENT
        elif state.get("degraded"):
            status = "Real-time protection needs attention."
            color = theme.WARNING
        elif state.get("running"):
            status = "Real-time protection active · Background file checks are recorded in Activity."
            color = theme.ACCENT
        else:
            status = "Real-time protection is not currently active."
            color = theme.WARNING
        self.background_scan_status.configure(text=status, text_color=color)

    def refresh_from_state(self, reason: str = "") -> None:
        # Scan state is synchronized continuously through scan_* bus messages,
        # including while this page is hidden. No service/database reload needed.
        return

    def _choose_file(self) -> None:
        paths = filedialog.askopenfilenames(
            title="Add files to Custom Scan", filetypes=(("All files", "*.*"),)
        )
        self._add_targets(paths, "file")

    def _choose_folder(self) -> None:
        path = filedialog.askdirectory(title="Add a folder to Custom Scan", mustexist=True)
        if path:
            self._add_targets((path,), "folder")

    def _add_targets(self, paths, kind: str) -> None:
        known = {str(path).casefold() for path, _kind in self._selected_targets}
        added = 0
        for raw_path in paths:
            if not raw_path:
                continue
            path = normalize_path(raw_path)
            key = str(path).casefold()
            if key in known:
                continue
            known.add(key)
            self._selected_targets.append((path, kind))
            added += 1
        self._render_targets()
        if added == 0 and paths:
            self.selected_target_count.configure(text=f"{len(self._selected_targets):,} targets selected · duplicates ignored")

    def _render_targets(self) -> None:
        self.target_listbox.delete(0, tk.END)
        for path, kind in self._selected_targets:
            self.target_listbox.insert(tk.END, f"{kind.upper():6} | {path}")
        self.selected_target_count.configure(
            text=f"{len(self._selected_targets):,} target{'s' if len(self._selected_targets) != 1 else ''} selected"
        )
        self._update_target_controls()

    def _update_target_controls(self, _event=None) -> None:
        has_targets = bool(self._selected_targets)
        has_selection = bool(self.target_listbox.curselection())
        self.custom_scan_button.configure(state="normal" if has_targets else "disabled")
        self.clear_targets_button.configure(state="normal" if has_targets else "disabled")
        self.remove_targets_button.configure(state="normal" if has_selection else "disabled")

    def _remove_selected_targets(self) -> None:
        selected = set(self.target_listbox.curselection())
        self._selected_targets = [
            target for index, target in enumerate(self._selected_targets) if index not in selected
        ]
        self._render_targets()

    def _clear_targets(self) -> None:
        self._selected_targets.clear()
        self._render_targets()

    def _start_custom_scan(self) -> None:
        if not self._selected_targets:
            return
        if self.controller.start_custom_scan(tuple(path for path, _kind in self._selected_targets)):
            self._clear_targets()

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
        elif self._scan_running or self._automatic_scan_running or self._result_pending:
            self._show_active_view()
        else:
            self._show_idle_view()

    def handle_message(self, message) -> None:
        if message.kind == "scan_started":
            self._automatic_scan_running = False
            self._automatic_scan_key = None
            self._scan_running = True
            self._result_pending = False
            self._result_visible = False
            self.counts = {key: 0 for key in self.counts}
            self.active_scan.start(
                message.payload.get("scan_type", "manual"),
                message.payload.get("path", ""),
                target_count=message.payload.get("target_count"),
            )
            self._show_active_view()

        elif message.kind == "scan_discovered":
            self.active_scan.update_discovery(
                message.payload.get("discovered", 0),
                message.payload.get("processed", 0),
                message.payload.get("path", ""),
                phase=message.payload.get("phase", "discovering"),
                total=message.payload.get("total"),
                eta_seconds=message.payload.get("eta_seconds"),
                bytes_processed=message.payload.get("bytes_processed", 0),
                elapsed_seconds=message.payload.get("elapsed"),
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
                phase=message.payload.get("phase", "scanning"),
                total=message.payload.get("total"),
                eta_seconds=message.payload.get("eta_seconds"),
                bytes_processed=message.payload.get("bytes_processed", 0),
                elapsed_seconds=message.payload.get("elapsed"),
            )

        elif message.kind == "scan_stop_requested":
            self.active_scan.stopping()

        elif message.kind == "scan_stopped":
            self._scan_running = False
            self._result_pending = False
            self._result_visible = False
            self.active_scan.end()
            self.active_scan.cancelled()
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
            self.active_scan.complete()
            self._last_result = dict(message.payload.get("result", {}))
            self.scan_result.show_result(self._last_result)
            self._show_result_view()

        elif message.kind == "scan_rejected":
            return

        elif message.kind == "task_failed" and "scan" in str(message.payload.get("task", "")):
            self._scan_running = False
            self._result_pending = False
            self._result_visible = False
            self.active_scan.fail(str(message.payload.get("error", "Scan failed.")))
            self._show_idle_view()
