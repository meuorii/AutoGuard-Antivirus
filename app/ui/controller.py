"""Presentation controller for Phase 15.

This module owns thread dispatch and read-only presentation queries.  Detection,
quarantine, cleanup, verification, reappearance, and recovery decisions remain
inside the existing service modules.
"""

from __future__ import annotations

import threading
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta
from dataclasses import asdict
from pathlib import Path
from typing import Any, Callable

from app.cleanup_verifier import VerificationStatus
from app.explanations import ExplanationContext, build_explanation
from app.incidents import IncidentEventType, IncidentStatus
from app.models import DetectionStatus, ScanResult, ScanSource, ScanStatus, ScanType
from app.quarantine import QuarantineIntegrityStatus, QuarantineState
from app.recovery import RecoveryStatus
from app.scanner import ScanInterruptedError
from app.startup import AutoGuardServices
from app.ui.messages import UIMessageBus


class AutoGuardUIController:
    def __init__(self, services: AutoGuardServices, bus: UIMessageBus | None = None) -> None:
        self.services = services
        self.bus = bus if bus is not None else UIMessageBus()
        self._executor = ThreadPoolExecutor(max_workers=4, thread_name_prefix="AutoGuardUI")
        self._lock = threading.RLock()
        self._active_tasks: set[str] = set()
        self._scan_cancel_events: dict[str, threading.Event] = {}
        self._current_scan_task: str | None = None
        self._selected_threat_ref: str | None = None
        self._selected_quarantine_ref: str | None = None

    def shutdown(self) -> None:
        # Request cooperative interruption of a UI-launched scan before the
        # executor is released. Scanner persistence remains authoritative.
        self.stop_scan()
        self._executor.shutdown(wait=False, cancel_futures=False)

    def active_tasks(self) -> tuple[str, ...]:
        with self._lock:
            return tuple(sorted(self._active_tasks))

    def _submit(self, task_name: str, operation: Callable[[], Any], success_kind: str) -> None:
        with self._lock:
            self._active_tasks.add(task_name)
        self.bus.publish("task_started", task=task_name, active_tasks=self.active_tasks())

        def runner() -> None:
            try:
                result = operation()
                self.bus.publish(success_kind, task=task_name, result=result)
            except ScanInterruptedError as error:
                # Cooperative UI Stop Scan uses the scanner's existing
                # interruption lifecycle, which persists the session as
                # incomplete before this exception reaches the controller.
                self.bus.publish(
                    "scan_stopped",
                    task=task_name,
                    session_id=error.session_id,
                    reason="Scan stopped safely.",
                )
            except Exception as error:
                self.bus.publish(
                    "task_failed", task=task_name,
                    error=f"{type(error).__name__}: {error}",
                )
            finally:
                with self._lock:
                    self._active_tasks.discard(task_name)
                    self._scan_cancel_events.pop(task_name, None)
                    if self._current_scan_task == task_name:
                        self._current_scan_task = None
                self.bus.publish("task_finished", task=task_name, active_tasks=self.active_tasks())

        self._executor.submit(runner)

    # ---------- Home / read models ----------
    def navigate_to(self, page: str) -> None:
        """Request a presentation-only page change through the UI message bus."""
        self.bus.publish("navigate", page=page)

    def refresh_dashboard(self) -> None:
        self._submit("refresh-dashboard", self._dashboard_snapshot, "dashboard_data")

    @staticmethod
    def _health_running(health: Any | None) -> bool:
        if health is None or not bool(getattr(health, "running", False)):
            return False
        status = getattr(getattr(health, "status", None), "value", None)
        return status is None or str(status).upper() == "RUNNING"

    @staticmethod
    def _display_name(path: str) -> str:
        # Stored Windows paths can be inspected during cross-platform tests.
        if "\\" in path:
            return path.rstrip("\\").rsplit("\\", 1)[-1]
        return Path(path).name or path

    @staticmethod
    def _scan_label(scan_type: ScanType) -> str:
        return {
            ScanType.QUICK: "Quick Scan",
            ScanType.FULL: "Full Scan",
            ScanType.MANUAL: "Custom Scan",
            ScanType.STARTUP: "Startup scan",
            ScanType.SCHEDULED: "Scheduled scan",
            ScanType.USB: "USB scan",
        }.get(scan_type, "Scan")

    def _dashboard_snapshot(self) -> dict[str, Any]:
        file_health = self.services.file_monitor.health() if self.services.file_monitor else None
        usb_health = self.services.usb_monitor.health() if self.services.usb_monitor else None
        scheduler_health = self.services.scheduler.health()
        quarantine = self.services.quarantine.list_quarantined_items()
        active_incidents = self.services.incidents.get_active_incidents()
        recent = self.services.scanner.history.recent_scans(16)

        protection = {
            "real_time": self._health_running(file_health),
            "usb": self._health_running(usb_health),
            "scheduled": bool(getattr(scheduler_health, "running", False)),
        }
        protection_ok = all(protection.values())

        review_statuses = {
            IncidentStatus.OPEN,
            IncidentStatus.INVESTIGATING,
            IncidentStatus.REAPPEARED,
        }
        threats_needing_review = sum(
            1 for incident in active_incidents if incident.status in review_statuses
        )

        active_tasks = self.active_tasks()
        ui_scan_running = any(
            task == "quick-scan" or task == "full-scan" or task.startswith("scan:")
            for task in active_tasks
        )
        scheduler_scan_running = bool(
            getattr(scheduler_health, "quick_scan_running", False)
            or getattr(scheduler_health, "full_scan_running", False)
        )
        scan_running = ui_scan_running or scheduler_scan_running

        # Priority keeps genuine protection failures and review-needed threats
        # visible even if a scan is also running.
        if not protection_ok:
            protection_state = {
                "key": "issue",
                "title": "Protection issue",
                "message": "One or more protection services are not running.",
            }
        elif threats_needing_review:
            protection_state = {
                "key": "attention",
                "title": "Attention needed",
                "message": "AutoGuard found something that needs review.",
            }
        elif scan_running:
            protection_state = {
                "key": "scanning",
                "title": "Scanning",
                "message": "AutoGuard is currently checking your files.",
            }
        else:
            protection_state = {
                "key": "protected",
                "title": "Protected",
                "message": "Everything is working normally.",
            }

        visible_scan_types = {
            ScanType.QUICK, ScanType.FULL, ScanType.MANUAL,
            ScanType.STARTUP, ScanType.SCHEDULED, ScanType.USB,
        }
        last_session = next(
            (session for session in recent if session.scan_type in visible_scan_types),
            None,
        )
        if last_session is None:
            last_scan = {"value": "No scans yet", "detail": "Run a Quick Scan to get started"}
        else:
            label = self._scan_label(last_session.scan_type)
            when = last_session.finished_at or last_session.started_at
            checked = int(last_session.counters.get("scanned_files", 0))
            suffix = "file" if checked == 1 else "files"
            last_scan = {
                "value": label,
                "detail": f"{checked:,} {suffix} checked · {self._friendly_scan_status(last_session.status)}",
                "when": when,
            }

        recent_activity = self._recent_activity(recent, limit=5)

        return {
            "protection_state": protection_state,
            "protection": protection,
            "scan_running": scan_running,
            "last_scan": last_scan,
            "threats_needing_review": threats_needing_review,
            "quarantined_count": sum(
                1 for item in quarantine if item.state.value == "QUARANTINED"
            ),
            "recent_activity": recent_activity,
        }

    @staticmethod
    def _friendly_scan_status(status: Any) -> str:
        value = getattr(status, "value", str(status)).upper()
        return {
            "RUNNING": "In progress",
            "COMPLETED": "Completed",
            "INCOMPLETE": "Finished with some files skipped",
            "FAILED": "Could not finish",
        }.get(value, "Finished")

    def _recent_activity(self, sessions: list[Any], *, limit: int) -> list[dict[str, Any]]:
        events: list[dict[str, Any]] = []
        for session in sessions:
            if len(events) >= limit:
                break
            if session.scan_type in (ScanType.MATCHING_COPY, ScanType.RECOVERY):
                continue
            details = self.services.scanner.history.get_scan(session.id)
            detection = None
            if details is not None:
                detection = next(
                    (
                        result for result in reversed(details.results)
                        if result.detection_status in (
                            DetectionStatus.HIGH_CONFIDENCE,
                            DetectionStatus.LOW_CONFIDENCE,
                        )
                    ),
                    None,
                )
            if detection is not None:
                dangerous = detection.detection_status is DetectionStatus.HIGH_CONFIDENCE
                events.append({
                    "title": "Threat detected" if dangerous else "Suspicious file detected",
                    "detail": self._display_name(detection.path),
                    "when": detection.recorded_at,
                    "tone": "danger" if dangerous else "warning",
                })
                continue

            when = session.finished_at or session.started_at
            if session.scan_type is ScanType.REAL_TIME:
                events.append({
                    "title": "File scanned",
                    "detail": self._display_name(session.source_path),
                    "when": when,
                    "tone": "success",
                })
                continue

            label = self._scan_label(session.scan_type)
            running = getattr(session.status, "value", str(session.status)).upper() == "RUNNING"
            if session.scan_type is ScanType.USB:
                title = "USB drive scan started" if running else "USB drive scanned"
            elif running:
                title = f"{label} started"
            else:
                title = f"{label} completed"
            checked = int(session.counters.get("scanned_files", 0))
            detail = self._friendly_scan_status(session.status)
            if checked:
                detail = f"{checked:,} {'file' if checked == 1 else 'files'} checked"
            events.append({
                "title": title,
                "detail": detail,
                "when": when,
                "tone": "success" if getattr(session.status, "value", "") == "COMPLETED" else "info",
            })
        return events[:limit]

    # ---------- Completed scan read model ----------
    def prepare_scan_result(self, scan_output: Any) -> None:
        """Build the completed-scan presentation model away from the UI thread."""
        summaries = tuple(scan_output) if isinstance(scan_output, (list, tuple)) else (scan_output,)
        session_ids = tuple(
            str(summary.session_id)
            for summary in summaries
            if getattr(summary, "session_id", None)
        )
        task_suffix = session_ids[0] if session_ids else "unknown"
        self._submit(
            f"prepare-scan-result:{task_suffix}",
            lambda: self._scan_result_snapshot(summaries),
            "scan_result_ready",
        )

    @staticmethod
    def _format_duration(seconds: float | None) -> str:
        if seconds is None:
            return "—"
        total = max(0, int(round(seconds)))
        minutes, secs = divmod(total, 60)
        hours, minutes = divmod(minutes, 60)
        if hours:
            return f"{hours} hr {minutes} min" if minutes else f"{hours} hr"
        if minutes:
            return f"{minutes} min {secs} sec" if secs else f"{minutes} min"
        return f"{secs} sec"

    def _scan_result_snapshot(self, summaries: tuple[Any, ...]) -> dict[str, Any]:
        """Translate persisted scan evidence into one user-facing result model.

        The model deliberately contains presentation labels rather than raw
        detection/session enums. Containment is reported only when the incident
        is CONTAINED *and* the latest cleanup verification is VERIFIED.
        """
        history = self.services.scanner.history
        details = []
        for summary in summaries:
            session_id = getattr(summary, "session_id", None)
            if session_id:
                item = history.get_scan(str(session_id))
                if item is not None:
                    details.append(item)

        counter_names = (
            "scanned_files", "dangerous_detections", "suspicious_detections",
            "skipped_size", "locked_files", "unsupported_files", "errors", "file_errors",
        )
        counters = {name: 0 for name in counter_names}
        for item in details:
            for name in counter_names:
                counters[name] += int(item.session.counters.get(name, 0))

        # Fallback keeps the read model usable if an old/non-persisted summary
        # is supplied, while normal production scans use persisted sessions.
        if not details:
            for summary in summaries:
                summary_counts = getattr(summary, "counts", {})
                for name in counter_names:
                    counters[name] += int(summary_counts.get(name, 0))

        scan_types = [item.session.scan_type for item in details]
        scan_type = scan_types[0] if scan_types and all(value is scan_types[0] for value in scan_types) else None
        scan_label = self._scan_label(scan_type) if scan_type is not None else "Scan"

        starts = [item.session.started_at for item in details]
        finishes = [item.session.finished_at for item in details if item.session.finished_at is not None]
        started_at = min(starts) if starts else None
        finished_at = max(finishes) if finishes else None
        duration_seconds = (
            (finished_at - started_at).total_seconds()
            if started_at is not None and finished_at is not None
            else None
        )

        files_checked = counters["scanned_files"]
        suspicious = counters["suspicious_detections"]
        dangerous = counters["dangerous_detections"]
        skipped = (
            counters["skipped_size"]
            + counters["locked_files"]
            + counters["unsupported_files"]
        )
        errors = counters["errors"]

        base = {
            "scan_type": scan_label,
            "duration": self._format_duration(duration_seconds),
            "files_checked": files_checked,
            "threats_found": dangerous,
            "skipped_files": skipped,
            "suspicious_files": suspicious,
        }

        issue_note = ""
        if skipped or errors:
            issue_note = "Some files could not be checked. View scan details for more information."
        if files_checked == 0:
            issue_note = "No files were successfully scanned. View scan details for more information."

        if dangerous == 0 and suspicious == 0:
            return {
                **base,
                "kind": "clean",
                "title": "Scan complete",
                "message": "No threats detected in the files successfully scanned.",
                "note": issue_note,
            }

        if dangerous == 0:
            noun = "file" if suspicious == 1 else "files"
            return {
                **base,
                "kind": "suspicious",
                "title": "Review recommended",
                "message": (
                    f"AutoGuard found {suspicious:,} suspicious {noun}, but no confirmed threat was detected."
                ),
                "note": "Suspicious evidence does not by itself confirm malware. " + issue_note,
            }

        dangerous_hashes = {
            result.sha256
            for item in details
            for result in item.results
            if result.detection_status is DetectionStatus.HIGH_CONFIDENCE and result.sha256
        }
        active_incidents = {
            incident.sha256: incident for incident in self.services.incidents.get_active_incidents()
        }
        contained = 0
        matching_copies = 0
        verification_states: list[VerificationStatus] = []

        for sha256 in dangerous_hashes:
            incident = active_incidents.get(sha256)
            if incident is None:
                continue
            incident_details = self.services.incidents.get_incident(incident.id)
            verifications = self.services.cleanup_verifier.list_verifications(incident.id)
            latest = verifications[-1] if verifications else None
            if latest is not None:
                verification_states.append(latest.status)
            verified = (
                latest is not None
                and latest.status is VerificationStatus.VERIFIED
                and incident.status is IncidentStatus.CONTAINED
            )
            if verified:
                contained += 1
            if incident_details is not None:
                matching_copies += sum(
                    1
                    for event in incident_details.events
                    if event.event_type is IncidentEventType.MATCHING_COPY_FOUND
                    and (started_at is None or event.occurred_at >= started_at)
                )

        fully_contained = bool(dangerous_hashes) and contained == len(dangerous_hashes)
        if verification_states and all(state is VerificationStatus.VERIFIED for state in verification_states) and len(verification_states) == len(dangerous_hashes):
            cleanup_status = "Verified"
        elif any(state is VerificationStatus.FAILED for state in verification_states):
            cleanup_status = "Failed"
        elif any(state is VerificationStatus.PARTIAL for state in verification_states):
            cleanup_status = "Partial"
        else:
            cleanup_status = "Not verified"

        if fully_contained:
            noun = "threat" if contained == 1 else "threats"
            title = "Threat handled"
            message = f"AutoGuard detected and contained {contained:,} confirmed {noun}. Cleanup verification succeeded."
        else:
            title = "Confirmed threat detected"
            message = (
                "AutoGuard detected a confirmed threat, but containment or cleanup could not be fully verified. "
                "Review the threat details."
            )

        return {
            **base,
            "kind": "confirmed_threat",
            "title": title,
            "message": message,
            "note": issue_note,
            "threats_contained": contained,
            "matching_copies_found": matching_copies,
            "cleanup_status": cleanup_status,
            "containment_verified": fully_contained,
        }

    # ---------- Threats read model ----------
    _THREAT_STATUS_LABELS = {
        IncidentStatus.OPEN: ("Needs attention", "Needs attention"),
        IncidentStatus.INVESTIGATING: ("Being reviewed", "Needs attention"),
        IncidentStatus.CONTAINED: ("Contained", "Contained"),
        IncidentStatus.REAPPEARED: ("Detected again", "Needs attention"),
        IncidentStatus.RESTORED: ("Restored", "Needs attention"),
        IncidentStatus.RESOLVED: ("Resolved", "Resolved"),
    }

    @staticmethod
    def _friendly_timestamp(value: Any) -> str:
        if value is None:
            return "Time unavailable"
        try:
            local = value.astimezone() if getattr(value, "tzinfo", None) else value
            return local.strftime("%b %d, %Y · %I:%M %p").replace(" 0", " ")
        except Exception:
            return "Time unavailable"

    def load_threats(self) -> None:
        self._submit("load-threats", self._threat_rows, "threats_data")

    def _threat_rows(self) -> list[dict[str, Any]]:
        rows: list[dict[str, Any]] = []
        for incident in self.services.incidents.list_incidents(200):
            details = self.services.incidents.get_incident(incident.id)
            if details is None:
                continue
            status_label, section = self._THREAT_STATUS_LABELS[incident.status]
            files = tuple(details.files)
            location_count = len(files)
            if location_count <= 1:
                location_text = f"First observed: {incident.first_observed_path}"
            else:
                location_text = f"{location_count:,} observed locations"

            matching_paths = {
                event.path
                for event in details.events
                if event.event_type is IncidentEventType.MATCHING_COPY_FOUND and event.path
            }
            matching_copy_count = len(matching_paths)
            if not matching_paths:
                matching_copy_count = sum(
                    1 for event in details.events
                    if event.event_type is IncidentEventType.MATCHING_COPY_FOUND
                )

            rows.append({
                "threat_ref": incident.id,
                "section": section,
                "status": status_label,
                "status_key": {
                    "Needs attention": "attention",
                    "Being reviewed": "reviewing",
                    "Contained": "contained",
                    "Detected again": "reappeared",
                    "Restored": "restored",
                    "Resolved": "resolved",
                }[status_label],
                "name": self._display_name(incident.first_observed_path),
                "location": location_text,
                "detected": self._friendly_timestamp(incident.last_observed_at),
                "matching_copies": matching_copy_count,
                "action": "Review" if section == "Needs attention" else "View details",
            })
        return rows

    @property
    def selected_threat_ref(self) -> str | None:
        return self._selected_threat_ref

    def open_threat_details(self, threat_ref: str) -> None:
        """Select an internal incident reference and open its user-facing details."""
        if not threat_ref:
            return
        self._selected_threat_ref = str(threat_ref)
        self.bus.publish("threat_details_requested", threat_ref=self._selected_threat_ref)
        self.navigate_to("threats")

    def close_threat_details(self) -> None:
        """Return the Threats destination to its list state."""
        self._selected_threat_ref = None
        self.bus.publish("threat_details_closed")

    def load_threat_details(self, threat_ref: str | None = None) -> None:
        """Load one evidence-backed Threat Details read model off the UI thread."""
        ref = str(threat_ref or self._selected_threat_ref or "").strip()
        if not ref:
            return
        self._submit(
            f"load-threat-details:{ref}",
            lambda: self._threat_details_snapshot(ref),
            "threat_details_data",
        )

    @staticmethod
    def _location_key(path: str) -> str:
        """Normalize a recorded path only for presentation-layer deduplication."""
        return str(path).strip().replace("\\", "/").rstrip("/").casefold()

    def _threat_location_rows(self, details: Any, quarantine_items: tuple[Any, ...]) -> list[dict[str, Any]]:
        """Merge stored location evidence without inferring origin or movement."""
        incident = details.incident
        records: dict[str, dict[str, Any]] = {}

        def merge(path: str | None, *, first_seen: Any = None, last_seen: Any = None) -> None:
            if not path:
                return
            path_text = str(path)
            key = self._location_key(path_text)
            if not key:
                return
            row = records.setdefault(
                key,
                {"path": path_text, "first_seen": None, "last_seen": None},
            )
            if first_seen is not None and (
                row["first_seen"] is None or first_seen < row["first_seen"]
            ):
                row["first_seen"] = first_seen
            if last_seen is not None and (
                row["last_seen"] is None or last_seen > row["last_seen"]
            ):
                row["last_seen"] = last_seen

        # The incident's first-observed path is authoritative only as the first
        # location AutoGuard recorded, never as an infection source.
        merge(
            incident.first_observed_path,
            first_seen=getattr(incident, "created_at", None),
            last_seen=getattr(incident, "created_at", None),
        )
        for item in details.files:
            merge(
                getattr(item, "path", None),
                first_seen=getattr(item, "first_seen", None),
                last_seen=getattr(item, "last_seen", None),
            )

        trail = getattr(self.services, "threat_trail", None)
        if trail is not None:
            for observation in trail.get_observations(incident.sha256):
                merge(
                    getattr(observation, "path", None),
                    first_seen=getattr(observation, "first_seen", None),
                    last_seen=getattr(observation, "last_seen", None),
                )

        for event in details.events:
            merge(
                getattr(event, "path", None),
                first_seen=getattr(event, "occurred_at", None),
                last_seen=getattr(event, "occurred_at", None),
            )

        quarantine_by_path: dict[str, list[Any]] = {}
        for item in quarantine_items:
            path = getattr(item, "original_path", None)
            if path:
                merge(
                    path,
                    first_seen=getattr(item, "created_at", None),
                    last_seen=getattr(item, "quarantined_at", None) or getattr(item, "created_at", None),
                )
                quarantine_by_path.setdefault(self._location_key(path), []).append(item)

        first_key = self._location_key(incident.first_observed_path)
        rows: list[dict[str, Any]] = []
        for key, record in records.items():
            path = record["path"]
            quarantines = quarantine_by_path.get(key, ())
            removed_after_quarantine = any(
                getattr(item, "state", None) is QuarantineState.QUARANTINED
                and bool(getattr(item, "original_removed", False))
                for item in quarantines
            )
            if removed_after_quarantine:
                availability = "Original removed after quarantine"
                availability_key = "contained"
                availability_detail = "AutoGuard recorded that the original file was removed after a verified quarantine copy was created."
            else:
                try:
                    currently_available = Path(path).exists()
                except (OSError, ValueError):
                    currently_available = False
                if currently_available:
                    availability = "Available now"
                    availability_key = "available"
                    availability_detail = "The recorded path is currently accessible."
                else:
                    availability = "Unavailable now"
                    availability_key = "unavailable"
                    availability_detail = "The recorded path is not currently accessible; it may have been deleted, moved, or disconnected."

            observed_at = record["last_seen"] or record["first_seen"]
            rows.append({
                "path": path,
                "first_observed": key == first_key,
                "observed": self._friendly_timestamp(observed_at),
                "availability": availability,
                "availability_key": availability_key,
                "availability_detail": availability_detail,
                "_sort_time": record["first_seen"],
            })

        def sort_key(row: dict[str, Any]) -> tuple[Any, ...]:
            value = row.get("_sort_time")
            try:
                stamp = value.timestamp() if value is not None else float("inf")
            except Exception:
                stamp = float("inf")
            return (0 if row["first_observed"] else 1, stamp, row["path"].casefold())

        rows.sort(key=sort_key)
        for row in rows:
            row.pop("_sort_time", None)
        return rows

    def _timeline_row(self, event: Any) -> dict[str, Any]:
        """Translate one persisted incident event into user-facing timeline text."""
        event_type = event.event_type
        label = "Threat activity recorded"
        explanation = "AutoGuard recorded activity related to this threat."

        mapping = {
            IncidentEventType.FIRST_OBSERVED: (
                "Threat detected",
                "AutoGuard recorded the first confirmed observation of this content.",
            ),
            IncidentEventType.MATCHING_LOCATION_OBSERVED: (
                "Matching location observed",
                "AutoGuard observed identical content at another recorded location.",
            ),
            IncidentEventType.REPEATED_DETECTION: (
                "Threat detected",
                "AutoGuard detected the same confirmed content again.",
            ),
            IncidentEventType.QUARANTINE_STARTED: (
                "Quarantine started",
                "AutoGuard started isolating the detected file.",
            ),
            IncidentEventType.QUARANTINE_SUCCEEDED: (
                "File quarantined",
                "AutoGuard verified the quarantine copy before removing the original file.",
            ),
            IncidentEventType.QUARANTINE_FAILED: (
                "Quarantine failed",
                "AutoGuard recorded that the quarantine action did not complete successfully.",
            ),
            IncidentEventType.QUARANTINE_INTEGRITY_FAILED: (
                "Quarantine verification failed",
                "AutoGuard could not verify the stored quarantine object.",
            ),
            IncidentEventType.MATCHING_CLEANUP_STARTED: (
                "Matching-copy check started",
                "AutoGuard started checking monitored locations for exact matching content.",
            ),
            IncidentEventType.MATCHING_COPY_FOUND: (
                "Matching copy found",
                "AutoGuard found another file with the same exact content hash.",
            ),
            IncidentEventType.MATCHING_COPY_QUARANTINED: (
                "Matching copy quarantined",
                "AutoGuard quarantined an exact matching copy.",
            ),
            IncidentEventType.MATCHING_COPY_ALREADY_CONTAINED: (
                "Matching copy already contained",
                "AutoGuard found an exact matching location that already had verified quarantine evidence.",
            ),
            IncidentEventType.MATCHING_CLEANUP_FAILED: (
                "Matching-copy check issue",
                "AutoGuard recorded a problem while checking or handling a matching location.",
            ),
            IncidentEventType.MATCHING_CLEANUP_FINISHED: (
                "Matching-copy check completed",
                "AutoGuard finished the recorded matching-copy check.",
            ),
            IncidentEventType.CLEANUP_VERIFICATION_STARTED: (
                "Cleanup verification started",
                "AutoGuard started checking whether containment evidence was complete.",
            ),
            IncidentEventType.CLEANUP_VERIFIED: (
                "Cleanup verified",
                "AutoGuard recorded successful cleanup verification for the locations it could check.",
            ),
            IncidentEventType.CLEANUP_VERIFICATION_PARTIAL: (
                "Cleanup partially verified",
                "AutoGuard could not fully verify cleanup using the available evidence.",
            ),
            IncidentEventType.CLEANUP_VERIFICATION_FAILED: (
                "Cleanup verification failed",
                "AutoGuard could not confirm that cleanup was complete.",
            ),
            IncidentEventType.REAPPEARANCE: (
                "Threat detected again",
                "The same confirmed content was observed again after earlier containment evidence.",
            ),
            IncidentEventType.RECOVERY_ATTEMPTED: (
                "Restore requested",
                "A user-requested restore attempt was recorded.",
            ),
            IncidentEventType.RECOVERY_CONFLICT: (
                "Restore needs another location",
                "AutoGuard recorded a destination conflict during the restore attempt.",
            ),
            IncidentEventType.RECOVERY_BLOCKED: (
                "Restore blocked",
                "AutoGuard blocked the restore because the current safety checks did not allow it.",
            ),
            IncidentEventType.RECOVERY_FAILED: (
                "Restore failed",
                "AutoGuard recorded that the restore attempt did not complete successfully.",
            ),
            IncidentEventType.RECOVERY_SUCCEEDED: (
                "File restored",
                "AutoGuard recorded a completed user-requested restore.",
            ),
        }
        if event_type in mapping:
            label, explanation = mapping[event_type]
        elif event_type is IncidentEventType.STATUS_CHANGED:
            labels = {
                IncidentStatus.OPEN: ("Needs attention", "This threat was marked as needing attention."),
                IncidentStatus.INVESTIGATING: ("Review started", "This threat was marked as being reviewed."),
                IncidentStatus.CONTAINED: ("Threat contained", "This threat was marked as contained based on recorded evidence."),
                IncidentStatus.REAPPEARED: ("Threat detected again", "This threat was marked as detected again."),
                IncidentStatus.RESTORED: ("File restored", "This threat was marked as restored after a recovery action."),
                IncidentStatus.RESOLVED: ("Incident resolved", "This threat was marked as resolved."),
            }
            label, explanation = labels.get(
                getattr(event, "new_status", None),
                ("Threat status updated", "AutoGuard recorded a threat status change."),
            )

        count = getattr(event, "reappearance_count", None)
        if event_type is IncidentEventType.REAPPEARANCE and count:
            explanation += f" Recorded reappearance count: {count}."

        return {
            "label": label,
            "time": self._friendly_timestamp(getattr(event, "occurred_at", None)),
            "path": getattr(event, "path", None),
            "explanation": explanation,
        }

    def _threat_timeline_rows(self, details: Any) -> list[dict[str, Any]]:
        def event_key(event: Any) -> tuple[float, int]:
            value = getattr(event, "occurred_at", None)
            try:
                stamp = value.timestamp() if value is not None else float("inf")
            except Exception:
                stamp = float("inf")
            return (stamp, int(getattr(event, "id", 0) or 0))

        events = sorted(details.events, key=event_key)
        return [self._timeline_row(event) for event in events]

    def _threat_details_snapshot(self, threat_ref: str) -> dict[str, Any]:
        details = self.services.incidents.get_incident(threat_ref)
        if details is None:
            raise KeyError("The selected threat is no longer available.")

        incident = details.incident
        status_label, _ = self._THREAT_STATUS_LABELS[incident.status]
        status_key = {
            IncidentStatus.OPEN: "attention",
            IncidentStatus.INVESTIGATING: "reviewing",
            IncidentStatus.CONTAINED: "contained",
            IncidentStatus.REAPPEARED: "reappeared",
            IncidentStatus.RESTORED: "restored",
            IncidentStatus.RESOLVED: "resolved",
        }[incident.status]

        detection = self.services.scanner.history.latest_detection_for_sha256(incident.sha256)
        quarantine_items = tuple(
            item for item in self.services.quarantine.list_quarantined_items()
            if item.incident_id == incident.id and item.sha256 == incident.sha256
        )
        locations = self._threat_location_rows(details, quarantine_items)
        timeline = self._threat_timeline_rows(details)
        verifications = self.services.cleanup_verifier.list_verifications(incident.id)
        latest_verification = verifications[-1] if verifications else None

        recovery_attempts = []
        for item in quarantine_items:
            recovery_attempts.extend(self.services.recovery.list_attempts(item.quarantine_id))
        recovery_attempts.sort(key=lambda item: (item.attempted_at, item.id))

        explanation = None
        if detection is not None:
            explanation = build_explanation(
                ExplanationContext(
                    result=detection,
                    incident=details,
                    quarantine_items=quarantine_items,
                    latest_verification=latest_verification,
                    recovery_attempts=tuple(recovery_attempts),
                )
            )

        matching_found_paths = {
            event.path for event in details.events
            if event.event_type is IncidentEventType.MATCHING_COPY_FOUND and event.path
        }
        matching_found = len(matching_found_paths)
        if not matching_found_paths:
            matching_found = sum(
                event.event_type is IncidentEventType.MATCHING_COPY_FOUND
                for event in details.events
            )
        matching_quarantined_paths = {
            event.path for event in details.events
            if event.event_type is IncidentEventType.MATCHING_COPY_QUARANTINED and event.path
        }
        matching_quarantined = len(matching_quarantined_paths)
        if not matching_quarantined_paths:
            matching_quarantined = sum(
                event.event_type is IncidentEventType.MATCHING_COPY_QUARANTINED
                for event in details.events
            )
        cleanup_started = any(
            event.event_type is IncidentEventType.MATCHING_CLEANUP_STARTED
            for event in details.events
        )

        if detection is not None and detection.matched_signature_name:
            detection_text = (
                f'AutoGuard detected this file because it matched the stored signature '
                f'“{detection.matched_signature_name}”.'
            )
        elif explanation is not None:
            detection_text = explanation.summary
        elif details.files and details.files[0].first_detection_reason:
            detection_text = "AutoGuard recorded confirmed threat evidence for this file."
        else:
            detection_text = "AutoGuard recorded a confirmed threat for this file."

        successful_quarantine = tuple(
            item for item in quarantine_items if item.state is QuarantineState.QUARANTINED
        )
        failed_quarantine = tuple(
            item for item in quarantine_items if item.state is QuarantineState.FAILED
        )
        if successful_quarantine:
            count = len(successful_quarantine)
            action_text = (
                f"AutoGuard isolated {count:,} related {'file' if count == 1 else 'files'} in quarantine."
            )
            if failed_quarantine:
                action_text += " One or more additional quarantine attempts did not complete successfully."
        elif failed_quarantine:
            action_text = (
                "AutoGuard attempted to quarantine this threat, but the recorded quarantine action "
                "did not complete successfully."
            )
        else:
            action_text = "No successful quarantine action is recorded for this threat."

        if matching_found:
            matching_text = (
                f"AutoGuard found {matching_found:,} additional exact matching "
                f"{'copy' if matching_found == 1 else 'copies'}."
            )
            if matching_quarantined:
                matching_text += (
                    f" {matching_quarantined:,} matching "
                    f"{'copy was' if matching_quarantined == 1 else 'copies were'} quarantined."
                )
        elif cleanup_started:
            matching_text = (
                "Matching-Copy Cleanup ran and no additional exact matching copies were recorded."
            )
        else:
            matching_text = "No Matching-Copy Cleanup discovery record is available for this threat."

        if latest_verification is None:
            cleanup_text = "Cleanup verification has not been recorded yet."
            cleanup_label = "Not verified"
        elif latest_verification.status is VerificationStatus.VERIFIED:
            cleanup_text = (
                "Cleanup verification succeeded. No remaining exact matching copies were found in "
                "the locations AutoGuard successfully checked."
            )
            cleanup_label = "Verified"
        elif latest_verification.status is VerificationStatus.PARTIAL:
            parts = []
            if latest_verification.remaining_matching_copies:
                parts.append(
                    f"{latest_verification.remaining_matching_copies:,} exact matching "
                    f"{'copy remained' if latest_verification.remaining_matching_copies == 1 else 'copies remained'}"
                )
            if latest_verification.inaccessible_locations:
                parts.append(
                    f"{latest_verification.inaccessible_locations:,} "
                    f"{'location could' if latest_verification.inaccessible_locations == 1 else 'locations could'} not be fully checked"
                )
            if latest_verification.verification_errors:
                parts.append(
                    f"{latest_verification.verification_errors:,} verification "
                    f"{'error was' if latest_verification.verification_errors == 1 else 'errors were'} recorded"
                )
            detail = "; ".join(parts) if parts else "available evidence was incomplete"
            cleanup_text = f"Cleanup verification was partial: {detail}."
            cleanup_label = "Partial"
        else:
            cleanup_text = (
                "Cleanup verification failed, so AutoGuard could not confirm that containment was complete."
            )
            cleanup_label = "Failed"

        recovery_text = None
        restored_attempts = [
            attempt for attempt in recovery_attempts
            if attempt.status in (RecoveryStatus.RESTORED, RecoveryStatus.RESTORED_WITH_WARNING)
        ]
        if restored_attempts:
            recovery_text = "A user-requested restore was recorded for quarantined content related to this threat."
        elif incident.status is IncidentStatus.RESTORED:
            recovery_text = "This threat is recorded as restored after a user-requested recovery action."

        what_happened = [
            {"label": "Detection", "text": detection_text},
            {"label": "Action taken", "text": action_text},
            {"label": "Matching copies", "text": matching_text},
            {"label": "Cleanup verification", "text": cleanup_text},
        ]
        if recovery_text:
            what_happened.append({"label": "Recovery", "text": recovery_text})

        raw_event_log = "\n".join(
            f"{getattr(event, 'occurred_at', '')} · {event.event_type.value}"
            + (f" · {event.path}" if getattr(event, "path", None) else "")
            for event in details.events
        ) or "No incident events recorded"
        technical = [
            ("SHA-256", incident.sha256),
            ("Incident ID", incident.id),
            ("Raw incident status", incident.status.value),
            ("Detection rule", detection.rule_name if detection is not None and detection.rule_name else "Not recorded"),
            ("Scan session", detection.session_id if detection is not None else "Not recorded"),
            ("Detection record", str(detection.id) if detection is not None else "Not recorded"),
            ("Matched signature", detection.matched_signature_name if detection is not None and detection.matched_signature_name else "Not recorded"),
            ("Cleanup verification", cleanup_label),
            ("Incident events", raw_event_log),
        ]

        return {
            "name": self._display_name(incident.first_observed_path),
            "status": status_label,
            "status_key": status_key,
            "observed": self._friendly_timestamp(incident.last_observed_at),
            "summary": explanation.summary if explanation is not None else detection_text,
            "what_happened": what_happened,
            "caution": (
                "Observed locations show where AutoGuard saw matching content. They do not prove where "
                "the threat originally came from or how it reached the computer."
            ),
            "locations": locations,
            "timeline": timeline,
            "technical_details": technical,
        }

    def load_incidents(self) -> None:
        self._submit("load-incidents", self._incident_rows, "incidents_data")

    def _incident_rows(self) -> list[dict[str, Any]]:
        with self.services.database.connection() as connection:
            ids = [row["id"] for row in connection.execute(
                "SELECT id FROM threat_incidents ORDER BY last_observed_at DESC, rowid DESC LIMIT 200"
            ).fetchall()]
        rows: list[dict[str, Any]] = []
        for incident_id in ids:
            details = self.services.incidents.get_incident(incident_id)
            if details is None:
                continue
            latest_verification = self.services.cleanup_verifier.list_verifications(incident_id)
            rows.append({
                "details": details,
                "verification": latest_verification[-1] if latest_verification else None,
            })
        return rows

    def load_threat_trail(self, limit: int = 200) -> None:
        def load() -> list[dict[str, Any]]:
            with self.services.database.connection() as connection:
                rows = connection.execute(
                    """SELECT e.id, o.sha256, o.path, e.source, e.observed_at, o.seen_count
                       FROM observation_events e
                       JOIN file_observations o ON o.id = e.observation_id
                       ORDER BY e.observed_at DESC, e.id DESC LIMIT ?""",
                    (limit,),
                ).fetchall()
            return [dict(row) for row in rows]
        self._submit("load-threat-trail", load, "threat_trail_data")

    # ---------- Quarantine read model ----------
    @staticmethod
    def _friendly_size(value: int | None) -> str:
        if value is None:
            return "Size unavailable"
        size = float(max(0, value))
        units = ("B", "KB", "MB", "GB", "TB")
        unit = units[0]
        for candidate in units:
            unit = candidate
            if size < 1024 or candidate == units[-1]:
                break
            size /= 1024
        if unit == "B":
            return f"{int(size):,} B"
        return f"{size:.1f} {unit}"

    def load_quarantine(self) -> None:
        self._submit("load-quarantine", self._quarantine_snapshot, "quarantine_data")

    def _quarantine_snapshot(self) -> dict[str, Any]:
        """Return only user-facing list data for currently isolated files."""
        items = tuple(self.services.quarantine.list_quarantined_items())
        isolated = tuple(item for item in items if item.state is QuarantineState.QUARANTINED)
        rows: list[dict[str, Any]] = []
        for item in isolated:
            details = self.services.incidents.get_incident(item.incident_id)
            incident = details.incident if details is not None else None
            if incident is not None:
                threat_status, _ = self._THREAT_STATUS_LABELS.get(
                    incident.status, ("Threat recorded", "Needs attention")
                )
                threat_status_key = {
                    "Needs attention": "attention",
                    "Being reviewed": "reviewing",
                    "Contained": "contained",
                    "Detected again": "reappeared",
                    "Restored": "restored",
                    "Resolved": "resolved",
                }.get(threat_status, "attention")
            else:
                threat_status = "Threat recorded"
                threat_status_key = "attention"
            rows.append({
                "item_ref": item.quarantine_id,
                "name": self._display_name(item.original_path),
                "contained": self._friendly_timestamp(item.quarantined_at or item.created_at),
                "original_location": item.original_path,
                "threat_status": threat_status,
                "threat_status_key": threat_status_key,
            })
        return {"isolated_count": len(isolated), "items": rows}

    @property
    def selected_quarantine_ref(self) -> str | None:
        return self._selected_quarantine_ref

    def open_quarantine_details(self, item_ref: str) -> None:
        if not item_ref:
            return
        self._selected_quarantine_ref = str(item_ref)
        self.bus.publish("quarantine_details_requested", item_ref=self._selected_quarantine_ref)

    def close_quarantine_details(self) -> None:
        self._selected_quarantine_ref = None
        self.bus.publish("quarantine_details_closed")

    def load_quarantine_details(self, item_ref: str | None = None) -> None:
        ref = str(item_ref or self._selected_quarantine_ref or "").strip()
        if not ref:
            return
        self._submit(
            f"load-quarantine-details:{ref}",
            lambda: self._quarantine_details_snapshot(ref),
            "quarantine_details_data",
        )

    def _quarantine_details_snapshot(self, item_ref: str) -> dict[str, Any]:
        item = self.services.quarantine.get_item(item_ref)
        if item is None:
            raise KeyError("The selected quarantined file is no longer available.")
        details = self.services.incidents.get_incident(item.incident_id)
        incident = details.incident if details is not None else None
        if incident is not None:
            threat_status, _ = self._THREAT_STATUS_LABELS.get(
                incident.status, ("Threat recorded", "Needs attention")
            )
            threat_name = self._display_name(incident.first_observed_path)
        else:
            threat_status = "Threat recorded"
            threat_name = self._display_name(item.original_path)

        integrity = item.integrity_status
        if integrity is QuarantineIntegrityStatus.VERIFIED:
            verification_label = "Verified"
            integrity_text = "Stored content matched the recorded SHA-256 and expected size at the latest verification."
            integrity_key = "verified"
        elif integrity is QuarantineIntegrityStatus.FAILED:
            verification_label = "Verification failed"
            integrity_text = item.failure_reason or "The stored content could not be verified."
            integrity_key = "failed"
        else:
            verification_label = "Not verified yet"
            integrity_text = "No completed integrity verification is recorded yet."
            integrity_key = "pending"

        attempts = tuple(self.services.recovery.list_attempts(item.quarantine_id))
        latest_attempt = attempts[-1] if attempts else None
        latest_recovery = None
        if latest_attempt is not None:
            latest_recovery = {
                "status": self._recovery_status_text(latest_attempt.status)[0],
                "when": self._friendly_timestamp(latest_attempt.finished_at),
            }

        return {
            "item_ref": item.quarantine_id,
            "name": self._display_name(item.original_path),
            "contained": self._friendly_timestamp(item.quarantined_at or item.created_at),
            "original_location": item.original_path,
            "threat_name": threat_name,
            "threat_status": threat_status,
            "hash_verification": verification_label,
            "integrity_key": integrity_key,
            "quarantine_integrity": integrity_text,
            "last_verified": self._friendly_timestamp(item.verified_at) if item.verified_at else "Not verified yet",
            "sha256": item.sha256,
            "quarantine_id": item.quarantine_id,
            "incident_id": item.incident_id,
            "original_size": self._friendly_size(item.original_size),
            "original_removed": "Yes" if item.original_removed else "No",
            "latest_recovery": latest_recovery,
            "can_restore": item.state is QuarantineState.QUARANTINED,
            "can_delete": item.state is QuarantineState.QUARANTINED,
        }

    # ---------- Unified Activity read model ----------
    _ACTIVITY_SCAN_LIMIT = 180
    _ACTIVITY_INCIDENT_LIMIT = 120
    _ACTIVITY_OUTPUT_LIMIT = 350

    def load_activity(self) -> None:
        """Load the unified user-facing activity feed off the UI thread."""
        if "load-activity" in self.active_tasks():
            return
        self._submit("load-activity", self._activity_snapshot, "activity_data")

    @staticmethod
    def _activity_local_time(value: Any) -> datetime | None:
        if value is None:
            return None
        try:
            return value.astimezone() if getattr(value, "tzinfo", None) else value
        except Exception:
            return None

    @classmethod
    def _activity_time_labels(cls, value: Any) -> tuple[str, str]:
        local = cls._activity_local_time(value)
        if local is None:
            return "Earlier", "Time unavailable"
        now = datetime.now().astimezone()
        current_date = local.date()
        if current_date == now.date():
            section = "Today"
        elif current_date == (now.date() - timedelta(days=1)):
            section = "Yesterday"
        else:
            section = local.strftime("%b %d, %Y").replace(" 0", " ")
        return section, local.strftime("%I:%M %p").lstrip("0")

    def _activity_snapshot(self) -> list[dict[str, Any]]:
        """Merge existing evidence into one chronological, sanitized feed.

        No activity row is synthesized from an identifier or a current-state
        snapshot alone. Scan rows come from persisted ScanHistory, threat rows
        from persisted IncidentService events, and removable-drive detection
        rows from the USB monitor's existing event history. AutoGuard currently
        has no persisted timestamped protection-service transition history, so
        such transitions are intentionally absent rather than invented.
        """
        events: list[dict[str, Any]] = []
        seen: set[tuple[str, str, str, int]] = set()

        def add(
            category: str,
            title: str,
            when: Any,
            *,
            detail: str = "",
            tone: str = "info",
        ) -> None:
            local = self._activity_local_time(when)
            if local is None:
                return
            try:
                stamp = local.timestamp()
            except Exception:
                return
            safe_detail = str(detail or "").strip()
            key = (category, title, safe_detail.casefold(), int(stamp))
            if key in seen:
                return
            seen.add(key)
            events.append({
                "category": category,
                "title": title,
                "detail": safe_detail,
                "tone": tone,
                "_sort_time": stamp,
                "_when": local,
            })

        # Threat/quarantine/cleanup/recovery activity is already recorded in the
        # incident timeline. Keep that service authoritative rather than reading
        # incident tables from the presentation layer.
        incidents = tuple(self.services.incidents.list_incidents(self._ACTIVITY_INCIDENT_LIMIT))
        incident_shas = {incident.sha256 for incident in incidents}
        meaningful_incident_events = {
            IncidentEventType.FIRST_OBSERVED,
            IncidentEventType.REPEATED_DETECTION,
            IncidentEventType.QUARANTINE_SUCCEEDED,
            IncidentEventType.QUARANTINE_FAILED,
            IncidentEventType.QUARANTINE_INTEGRITY_FAILED,
            IncidentEventType.MATCHING_COPY_FOUND,
            IncidentEventType.MATCHING_COPY_QUARANTINED,
            IncidentEventType.MATCHING_COPY_ALREADY_CONTAINED,
            IncidentEventType.MATCHING_CLEANUP_FAILED,
            IncidentEventType.CLEANUP_VERIFIED,
            IncidentEventType.CLEANUP_VERIFICATION_PARTIAL,
            IncidentEventType.CLEANUP_VERIFICATION_FAILED,
            IncidentEventType.REAPPEARANCE,
            IncidentEventType.RECOVERY_CONFLICT,
            IncidentEventType.RECOVERY_BLOCKED,
            IncidentEventType.RECOVERY_FAILED,
            IncidentEventType.RECOVERY_SUCCEEDED,
            IncidentEventType.STATUS_CHANGED,
        }
        for incident in incidents:
            details = self.services.incidents.get_incident(incident.id)
            if details is None:
                continue
            for event in details.events:
                if event.event_type not in meaningful_incident_events:
                    continue
                if event.event_type is IncidentEventType.STATUS_CHANGED and getattr(event, "new_status", None) is IncidentStatus.OPEN:
                    continue
                friendly = self._timeline_row(event)
                if event.event_type in (IncidentEventType.FIRST_OBSERVED, IncidentEventType.REPEATED_DETECTION):
                    title = "Confirmed threat detected"
                else:
                    title = friendly["label"]
                path = getattr(event, "path", None)
                detail = str(path) if path else friendly["explanation"]
                tone = "danger" if event.event_type in (
                    IncidentEventType.FIRST_OBSERVED,
                    IncidentEventType.REPEATED_DETECTION,
                    IncidentEventType.REAPPEARANCE,
                    IncidentEventType.QUARANTINE_FAILED,
                    IncidentEventType.CLEANUP_VERIFICATION_FAILED,
                    IncidentEventType.RECOVERY_FAILED,
                ) else (
                    "warning" if event.event_type in (
                        IncidentEventType.CLEANUP_VERIFICATION_PARTIAL,
                        IncidentEventType.RECOVERY_CONFLICT,
                        IncidentEventType.RECOVERY_BLOCKED,
                        IncidentEventType.QUARANTINE_INTEGRITY_FAILED,
                        IncidentEventType.MATCHING_CLEANUP_FAILED,
                    ) else "success"
                )
                add("Threats", title, event.occurred_at, detail=detail, tone=tone)

        # Scan lifecycle and file-monitor evidence come from persisted scan
        # history. Expensive per-session result reads are only performed when
        # a real-time file event or recorded detection requires them.
        history = self.services.scanner.history
        sessions = tuple(history.recent_scans(self._ACTIVITY_SCAN_LIMIT))
        for session in sessions:
            if session.scan_type in (ScanType.MATCHING_COPY, ScanType.RECOVERY):
                # Matching-copy and restore activity is represented by the
                # incident timeline above using clearer user-facing events.
                continue

            counters = session.counters
            needs_details = (
                session.scan_type is ScanType.REAL_TIME
                or int(counters.get("suspicious_detections", 0) or 0) > 0
                or int(counters.get("dangerous_detections", 0) or 0) > 0
            )
            details = history.get_scan(session.id) if needs_details else None
            detected = False
            if details is not None:
                for result in details.results:
                    if result.detection_status is DetectionStatus.LOW_CONFIDENCE:
                        detected = True
                        add(
                            "Threats", "Suspicious file detected", result.recorded_at,
                            detail=result.path, tone="warning",
                        )
                    elif result.detection_status is DetectionStatus.HIGH_CONFIDENCE:
                        detected = True
                        # High-confidence detections normally create an incident.
                        # Prefer its canonical FIRST_OBSERVED timeline entry and
                        # only fall back to scan evidence if no incident exists.
                        if not result.sha256 or result.sha256 not in incident_shas:
                            add(
                                "Threats", "Confirmed threat detected", result.recorded_at,
                                detail=result.path, tone="danger",
                            )

            if session.scan_type is ScanType.REAL_TIME:
                if not detected:
                    add(
                        "Scans", "File scanned",
                        session.finished_at or session.started_at,
                        detail=session.source_path, tone="success",
                    )
                continue

            label = self._scan_label(session.scan_type)
            source_detail = session.source_path
            add("Scans", f"{label} started", session.started_at, detail=source_detail, tone="info")
            if session.finished_at is not None:
                status = getattr(session.status, "value", str(session.status)).upper()
                checked = int(counters.get("scanned_files", 0) or 0)
                file_word = "file" if checked == 1 else "files"
                if status == "COMPLETED":
                    title = f"{label} completed"
                    tone = "success"
                elif status == "INCOMPLETE":
                    title = f"{label} stopped early"
                    tone = "warning"
                elif status == "FAILED":
                    title = f"{label} could not finish"
                    tone = "danger"
                else:
                    title = f"{label} finished"
                    tone = "info"
                detail = f"{checked:,} {file_word} checked"
                if session.scan_type in (ScanType.MANUAL, ScanType.USB):
                    detail += f" · {source_detail}"
                add("Scans", title, session.finished_at, detail=detail, tone=tone)

        # USBMonitor keeps an explicit runtime event history. Use only device
        # presence events here; scan started/completed is already persisted as
        # ScanHistory and would otherwise be duplicated.
        usb_monitor = getattr(self.services, "usb_monitor", None)
        if usb_monitor is not None and hasattr(usb_monitor, "recent_events"):
            try:
                usb_events = tuple(usb_monitor.recent_events())
            except Exception:
                usb_events = ()
            for event in usb_events:
                event_value = getattr(getattr(event, "event_type", None), "value", "")
                if event_value == "USB_DETECTED":
                    add(
                        "Scans", "USB drive detected", getattr(event, "occurred_at", None),
                        detail=getattr(event, "drive_root", ""), tone="info",
                    )
                elif event_value == "DEVICE_REMOVED":
                    add(
                        "Scans", "USB drive removed", getattr(event, "occurred_at", None),
                        detail=getattr(event, "drive_root", ""), tone="info",
                    )

        events.sort(key=lambda item: item["_sort_time"], reverse=True)
        result: list[dict[str, Any]] = []
        for event in events[: self._ACTIVITY_OUTPUT_LIMIT]:
            section, clock = self._activity_time_labels(event.pop("_when", None))
            event.pop("_sort_time", None)
            event["date_group"] = section
            event["time"] = clock
            result.append(event)
        return result

    def load_history(self) -> None:
        self._submit(
            "load-history",
            lambda: self.services.scanner.history.recent_scans(100),
            "history_data",
        )

    def load_scan_report(self, session_id: str) -> None:
        self._submit(
            f"report:{session_id}",
            lambda: self.services.reports.build_scan_report(session_id),
            "scan_report_data",
        )

    # ---------- Scan work ----------
    def _begin_ui_scan(self, task: str) -> threading.Event | None:
        """Reserve the single active UI scan and return its cancellation event."""
        with self._lock:
            if self._current_scan_task is not None:
                active = self._current_scan_task
            else:
                event = threading.Event()
                self._current_scan_task = task
                self._scan_cancel_events[task] = event
                return event
        self.bus.publish(
            "scan_rejected",
            task=task,
            active_task=active,
            reason="Another scan is already running.",
        )
        return None

    def stop_scan(self) -> bool:
        """Request safe cooperative interruption of the current UI-launched scan."""
        with self._lock:
            task = self._current_scan_task
            event = self._scan_cancel_events.get(task) if task is not None else None
        if task is None or event is None:
            return False
        event.set()
        self.bus.publish("scan_stop_requested", task=task)
        return True

    def start_scan(self, path: str | Path, *, scan_type: ScanType = ScanType.MANUAL) -> None:
        target = Path(path)
        task = f"scan:{target}"
        cancel_event = self._begin_ui_scan(task)
        if cancel_event is None:
            return
        self.bus.publish("scan_started", path=str(target), scan_type=scan_type.value, task=task)

        def scan():
            discovered = processed = 0

            def on_discovered(path: str, kind: str) -> None:
                nonlocal discovered
                discovered += 1
                self.bus.publish(
                    "scan_discovered", path=path, entry_kind=kind,
                    discovered=discovered, processed=processed, task=task,
                )

            def on_result(result: ScanResult) -> None:
                nonlocal discovered, processed
                processed += 1
                discovered = max(discovered, processed)
                detection = result.detection.status.value if result.detection else None
                self.bus.publish(
                    "scan_result", path=result.path, status=result.status.value,
                    detection=detection, reason=result.reason, processed=processed,
                    discovered=discovered,
                    progress=(processed / discovered) if discovered else 0.0, task=task,
                )

            return self.services.scanner.scan(
                target,
                ScanSource.MANUAL,
                scan_type=scan_type,
                interrupt_check=cancel_event.is_set,
                on_result=on_result,
                on_discovered=on_discovered,
            )

        self._submit(task, scan, "scan_completed")

    def start_quick_scan(self) -> None:
        self._start_path_batch("quick", self.services.scheduler.quick_paths, ScanType.QUICK)

    def start_full_scan(self) -> None:
        self._start_path_batch("full", self.services.scheduler.full_paths, ScanType.FULL)

    def _start_path_batch(self, label: str, paths: tuple[Path, ...], scan_type: ScanType) -> None:
        task = f"{label}-scan"
        cancel_event = self._begin_ui_scan(task)
        if cancel_event is None:
            return
        self.bus.publish("scan_started", path=label, scan_type=scan_type.value, task=task)

        def run_batch() -> list[Any]:
            existing = tuple(path for path in paths if path.exists())
            discovered = processed = 0

            def on_discovered(path: str, kind: str) -> None:
                nonlocal discovered
                discovered += 1
                self.bus.publish(
                    "scan_discovered", path=path, entry_kind=kind,
                    discovered=discovered, processed=processed, task=task,
                )

            def on_result(result: ScanResult) -> None:
                nonlocal discovered, processed
                processed += 1
                discovered = max(discovered, processed)
                self.bus.publish(
                    "scan_result", path=result.path, status=result.status.value,
                    detection=result.detection.status.value if result.detection else None,
                    reason=result.reason, processed=processed, discovered=discovered,
                    progress=(processed / discovered) if discovered else 0.0, task=task,
                )

            summaries: list[Any] = []
            for path in existing:
                if cancel_event.is_set():
                    raise ScanInterruptedError("Scan stopped by the user.")
                summaries.append(
                    self.services.scanner.scan(
                        path,
                        ScanSource.MANUAL,
                        scan_type=scan_type,
                        interrupt_check=cancel_event.is_set,
                        on_result=on_result,
                        on_discovered=on_discovered,
                    )
                )
            return summaries

        self._submit(task, run_batch, "scan_batch_completed")

    # ---------- Quarantine / recovery ----------
    def verify_quarantine(self, quarantine_id: str) -> None:
        def verify() -> dict[str, Any]:
            result = self.services.quarantine.verify_integrity(quarantine_id)
            return {
                "item_ref": quarantine_id,
                "verified": bool(result.verified),
                "title": "Integrity verified" if result.verified else "Integrity verification failed",
                "message": (
                    "The isolated file still matches its recorded SHA-256 and size."
                    if result.verified
                    else (result.error or "The isolated file could not be verified.")
                ),
            }
        self._submit(f"verify-quarantine:{quarantine_id}", verify, "quarantine_verified")

    @staticmethod
    def _recovery_status_text(status: RecoveryStatus) -> tuple[str, str, str]:
        return {
            RecoveryStatus.RESTORED: (
                "Restored", "The file was safely restored to the selected location.", "success"
            ),
            RecoveryStatus.RESTORED_WITH_WARNING: (
                "Restored with warning",
                "The file was restored, but current scanning still found suspicious evidence.",
                "warning",
            ),
            RecoveryStatus.INTEGRITY_FAILED: (
                "Restore blocked",
                "Restore was blocked because the isolated file failed integrity verification.",
                "error",
            ),
            RecoveryStatus.MISSING_QUARANTINE_OBJECT: (
                "Restore unavailable",
                "The isolated file is no longer available for restoration.",
                "error",
            ),
            RecoveryStatus.DESTINATION_CONFLICT: (
                "Choose another destination",
                "A file already exists at that destination. AutoGuard did not overwrite it.",
                "warning",
            ),
            RecoveryStatus.DANGEROUS_BLOCKED: (
                "Restore blocked",
                "Current detection still classifies this file as a confirmed threat, so AutoGuard did not restore it.",
                "error",
            ),
            RecoveryStatus.FAILED: (
                "Restore failed", "AutoGuard could not complete the restore operation.", "error"
            ),
        }.get(status, ("Restore finished", "The restore operation finished.", "info"))

    def restore_quarantine(self, quarantine_id: str, destination: str | Path | None = None) -> None:
        def restore() -> dict[str, Any]:
            result = self.services.recovery.restore(quarantine_id, destination)
            title, default_message, tone = self._recovery_status_text(result.status)
            message = result.warning or result.error or default_message
            return {
                "item_ref": quarantine_id,
                "restored": bool(result.restored),
                "title": title,
                "message": message,
                "tone": tone,
                "restored_path": result.restored_path,
            }
        self._submit(f"restore:{quarantine_id}", restore, "recovery_completed")

    def delete_quarantine(self, quarantine_id: str) -> None:
        def delete() -> dict[str, Any]:
            deleted = bool(self.services.quarantine.delete_quarantine_object(quarantine_id))
            return {
                "item_ref": quarantine_id,
                "deleted": deleted,
                "title": "Removed from quarantine",
                "message": (
                    "The isolated file was permanently deleted. Audit history was retained."
                    if deleted
                    else "The isolated file could not be deleted."
                ),
            }
        self._submit(f"delete-quarantine:{quarantine_id}", delete, "quarantine_deleted")

    def verify_incident_cleanup(self, incident_id: str) -> None:
        self._submit(
            f"verify-incident:{incident_id}",
            lambda: self.services.cleanup_verifier.verify_incident(incident_id),
            "incident_verified",
        )

    # ---------- Settings/status ----------
    def settings_snapshot(self) -> dict[str, Any]:
        return {
            "database": str(self.services.config.database_path),
            "quarantine": str(self.services.config.quarantine_dir),
            "max_file_size_bytes": self.services.config.max_file_size_bytes,
            "monitor_paths": tuple(str(p) for p in (
                self.services.file_monitor.monitored_paths() if self.services.file_monitor else ()
            )),
            "quick_hours": self.services.scheduler.settings.quick_interval_hours,
            "full_days": self.services.scheduler.settings.full_interval_days,
            "file_monitor_enabled": self.services.file_monitor is not None,
            "usb_monitor_enabled": self.services.usb_monitor is not None,
        }