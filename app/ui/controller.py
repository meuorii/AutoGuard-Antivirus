from __future__ import annotations
from concurrent.futures import ThreadPoolExecutor
from dataclasses import asdict
from pathlib import Path
import threading
from typing import Any, Callable
from app.cleanup_verifier import VerificationStatus
from app.explanations import ExplanationContext, build_explanation
from app.incidents import IncidentEventType, IncidentStatus
from app.models import DetectionStatus, ScanResult, ScanSource, ScanStatus, ScanType
from app.quarantine import QuarantineState
from app.recovery import RecoveryStatus
from app.scanner import ScanInterruptedError
from app.startup import AutoGuardServices
from app.ui.messages import UIMessageBus

class AutoGuardUIController:
    def __init__(self, services: AutoGuardServices, bus: UIMessageBus | None = None) -> None:
        self.services, self.bus = services, bus if bus is not None else UIMessageBus()
        self._executor, self._lock = ThreadPoolExecutor(max_workers=4, thread_name_prefix="AutoGuardUI"), threading.RLock()
        self._active_tasks, self._scan_cancel_events = set(), {}
        self._current_scan_task = self._selected_threat_ref = None

    def shutdown(self) -> None:
        self.stop_scan()
        self._executor.shutdown(wait=False, cancel_futures=False)

    def active_tasks(self) -> tuple[str, ...]:
        with self._lock: return tuple(sorted(self._active_tasks))

    def _submit(self, task_name: str, operation: Callable[[], Any], success_kind: str) -> None:
        with self._lock: self._active_tasks.add(task_name)
        self.bus.publish("task_started", task=task_name, active_tasks=self.active_tasks())
        def runner() -> None:
            try:
                result = operation()
                self.bus.publish(success_kind, task=task_name, result=result)
            except ScanInterruptedError as error:
                self.bus.publish("scan_stopped", task=task_name, session_id=error.session_id, reason="Scan stopped safely.")
            except Exception as error:
                self.bus.publish("task_failed", task=task_name, error=f"{type(error).__name__}: {error}")
            finally:
                with self._lock:
                    self._active_tasks.discard(task_name)
                    self._scan_cancel_events.pop(task_name, None)
                    if self._current_scan_task == task_name: self._current_scan_task = None
                self.bus.publish("task_finished", task=task_name, active_tasks=self.active_tasks())
        self._executor.submit(runner)

    def navigate_to(self, page: str) -> None: self.bus.publish("navigate", page=page)
    def refresh_dashboard(self) -> None: self._submit("refresh-dashboard", self._dashboard_snapshot, "dashboard_data")

    @staticmethod
    def _health_running(health: Any | None) -> bool:
        if health is None or not bool(getattr(health, "running", False)): return False
        status = getattr(getattr(health, "status", None), "value", None)
        return status is None or str(status).upper() == "RUNNING"

    @staticmethod
    def _display_name(path: str) -> str:
        return path.rstrip("\\").rsplit("\\", 1)[-1] if "\\" in path else Path(path).name or path

    @staticmethod
    def _scan_label(scan_type: ScanType) -> str:
        return {ScanType.QUICK: "Quick Scan", ScanType.FULL: "Full Scan", ScanType.MANUAL: "Custom Scan", ScanType.STARTUP: "Startup scan", ScanType.SCHEDULED: "Scheduled scan", ScanType.USB: "USB scan"}.get(scan_type, "Scan")

    def _dashboard_snapshot(self) -> dict[str, Any]:
        file_health = self.services.file_monitor.health() if self.services.file_monitor else None
        usb_health = self.services.usb_monitor.health() if self.services.usb_monitor else None
        scheduler_health, quarantine = self.services.scheduler.health(), self.services.quarantine.list_quarantined_items()
        active_incidents, recent = self.services.incidents.get_active_incidents(), self.services.scanner.history.recent_scans(16)
        protection = {"real_time": self._health_running(file_health), "usb": self._health_running(usb_health), "scheduled": bool(getattr(scheduler_health, "running", False))}
        protection_ok, review_statuses = all(protection.values()), {IncidentStatus.OPEN, IncidentStatus.INVESTIGATING, IncidentStatus.REAPPEARED}
        threats_needing_review = sum(1 for incident in active_incidents if incident.status in review_statuses)
        active_tasks = self.active_tasks()
        ui_scan_running = any(task in ("quick-scan", "full-scan") or task.startswith("scan:") for task in active_tasks)
        scheduler_scan_running = bool(getattr(scheduler_health, "quick_scan_running", False) or getattr(scheduler_health, "full_scan_running", False))
        scan_running = ui_scan_running or scheduler_scan_running
        if not protection_ok: protection_state = {"key": "issue", "title": "Protection issue", "message": "One or more protection services are not running."}
        elif threats_needing_review: protection_state = {"key": "attention", "title": "Attention needed", "message": "AutoGuard found something that needs review."}
        elif scan_running: protection_state = {"key": "scanning", "title": "Scanning", "message": "AutoGuard is currently checking your files."}
        else: protection_state = {"key": "protected", "title": "Protected", "message": "Everything is working normally."}
        visible_scan_types = {ScanType.QUICK, ScanType.FULL, ScanType.MANUAL, ScanType.STARTUP, ScanType.SCHEDULED, ScanType.USB}
        last_session = next((session for session in recent if session.scan_type in visible_scan_types), None)
        if last_session is None: last_scan = {"value": "No scans yet", "detail": "Run a Quick Scan to get started"}
        else:
            label, when = self._scan_label(last_session.scan_type), last_session.finished_at or last_session.started_at
            checked = int(last_session.counters.get("scanned_files", 0))
            last_scan = {"value": label, "detail": f"{checked:,} {'file' if checked == 1 else 'files'} checked · {self._friendly_scan_status(last_session.status)}", "when": when}
        return {"protection_state": protection_state, "protection": protection, "scan_running": scan_running, "last_scan": last_scan, "threats_needing_review": threats_needing_review, "quarantined_count": sum(1 for item in quarantine if item.state.value == "QUARANTINED"), "recent_activity": self._recent_activity(recent, limit=5)}

    @staticmethod
    def _friendly_scan_status(status: Any) -> str:
        return {"RUNNING": "In progress", "COMPLETED": "Completed", "INCOMPLETE": "Finished with some files skipped", "FAILED": "Could not finish"}.get(getattr(status, "value", str(status)).upper(), "Finished")

    def _recent_activity(self, sessions: list[Any], *, limit: int) -> list[dict[str, Any]]:
        events = []
        for session in sessions:
            if len(events) >= limit: break
            if session.scan_type in (ScanType.MATCHING_COPY, ScanType.RECOVERY): continue
            details = self.services.scanner.history.get_scan(session.id)
            detection = next((result for result in reversed(details.results) if result.detection_status in (DetectionStatus.HIGH_CONFIDENCE, DetectionStatus.LOW_CONFIDENCE)), None) if details else None
            if detection is not None:
                dangerous = detection.detection_status is DetectionStatus.HIGH_CONFIDENCE
                events.append({"title": "Threat detected" if dangerous else "Suspicious file detected", "detail": self._display_name(detection.path), "when": detection.recorded_at, "tone": "danger" if dangerous else "warning"})
                continue
            when = session.finished_at or session.started_at
            if session.scan_type is ScanType.REAL_TIME:
                events.append({"title": "File scanned", "detail": self._display_name(session.source_path), "when": when, "tone": "success"})
                continue
            label, running = self._scan_label(session.scan_type), getattr(session.status, "value", str(session.status)).upper() == "RUNNING"
            title = "USB drive scan started" if session.scan_type is ScanType.USB and running else "USB drive scanned" if session.scan_type is ScanType.USB else f"{label} started" if running else f"{label} completed"
            checked = int(session.counters.get("scanned_files", 0))
            detail = f"{checked:,} {'file' if checked == 1 else 'files'} checked" if checked else self._friendly_scan_status(session.status)
            events.append({"title": title, "detail": detail, "when": when, "tone": "success" if getattr(session.status, "value", "") == "COMPLETED" else "info"})
        return events[:limit]

    def prepare_scan_result(self, scan_output: Any) -> None:
        summaries = tuple(scan_output) if isinstance(scan_output, (list, tuple)) else (scan_output,)
        session_ids = tuple(str(summary.session_id) for summary in summaries if getattr(summary, "session_id", None))
        task_suffix = session_ids[0] if session_ids else "unknown"
        self._submit(f"prepare-scan-result:{task_suffix}", lambda: self._scan_result_snapshot(summaries), "scan_result_ready")

    @staticmethod
    def _format_duration(seconds: float | None) -> str:
        if seconds is None: return "—"
        total = max(0, int(round(seconds)))
        minutes, secs = divmod(total, 60)
        hours, minutes = divmod(minutes, 60)
        return f"{hours} hr {minutes} min" if hours and minutes else f"{hours} hr" if hours else f"{minutes} min {secs} sec" if minutes and secs else f"{minutes} min" if minutes else f"{secs} sec"

    def _scan_result_snapshot(self, summaries: tuple[Any, ...]) -> dict[str, Any]:
        history = self.services.scanner.history
        details = [item for summary in summaries if getattr(summary, "session_id", None) if (item := history.get_scan(str(summary.session_id))) is not None]
        counter_names = ("scanned_files", "dangerous_detections", "suspicious_detections", "skipped_size", "locked_files", "unsupported_files", "errors", "file_errors")
        counters = {name: sum(int(item.session.counters.get(name, 0)) for item in details) for name in counter_names}
        if not details:
            for summary in summaries:
                summary_counts = getattr(summary, "counts", {})
                for name in counter_names: counters[name] += int(summary_counts.get(name, 0))
        scan_types = [item.session.scan_type for item in details]
        scan_type = scan_types[0] if scan_types and all(value is scan_types[0] for value in scan_types) else None
        starts, finishes = [item.session.started_at for item in details], [item.session.finished_at for item in details if item.session.finished_at is not None]
        started_at, finished_at = min(starts) if starts else None, max(finishes) if finishes else None
        duration_seconds = (finished_at - started_at).total_seconds() if started_at is not None and finished_at is not None else None
        files_checked, suspicious, dangerous = counters["scanned_files"], counters["suspicious_detections"], counters["dangerous_detections"]
        skipped, errors = counters["skipped_size"] + counters["locked_files"] + counters["unsupported_files"], counters["errors"]
        base = {"scan_type": self._scan_label(scan_type) if scan_type is not None else "Scan", "duration": self._format_duration(duration_seconds), "files_checked": files_checked, "threats_found": dangerous, "skipped_files": skipped, "suspicious_files": suspicious}
        issue_note = "Some files could not be checked. View scan details for more information." if skipped or errors else ""
        if files_checked == 0: issue_note = "No files were successfully scanned. View scan details for more information."
        if dangerous == 0 and suspicious == 0: return {**base, "kind": "clean", "title": "Scan complete", "message": "No threats detected in the files successfully scanned.", "note": issue_note}
        if dangerous == 0: return {**base, "kind": "suspicious", "title": "Review recommended", "message": f"AutoGuard found {suspicious:,} suspicious {'file' if suspicious == 1 else 'files'}, but no confirmed threat was detected.", "note": "Suspicious evidence does not by itself confirm malware. " + issue_note}
        dangerous_hashes = {result.sha256 for item in details for result in item.results if result.detection_status is DetectionStatus.HIGH_CONFIDENCE and result.sha256}
        active_incidents = {incident.sha256: incident for incident in self.services.incidents.get_active_incidents()}
        contained, matching_copies, verification_states = 0, 0, []
        for sha256 in dangerous_hashes:
            if (incident := active_incidents.get(sha256)) is None: continue
            incident_details = self.services.incidents.get_incident(incident.id)
            verifications = self.services.cleanup_verifier.list_verifications(incident.id)
            latest = verifications[-1] if verifications else None
            if latest is not None: verification_states.append(latest.status)
            if latest is not None and latest.status is VerificationStatus.VERIFIED and incident.status is IncidentStatus.CONTAINED: contained += 1
            if incident_details is not None: matching_copies += sum(1 for event in incident_details.events if event.event_type is IncidentEventType.MATCHING_COPY_FOUND and (started_at is None or event.occurred_at >= started_at))
        fully_contained = bool(dangerous_hashes) and contained == len(dangerous_hashes)
        if verification_states and all(state is VerificationStatus.VERIFIED for state in verification_states) and len(verification_states) == len(dangerous_hashes): cleanup_status = "Verified"
        elif any(state is VerificationStatus.FAILED for state in verification_states): cleanup_status = "Failed"
        elif any(state is VerificationStatus.PARTIAL for state in verification_states): cleanup_status = "Partial"
        else: cleanup_status = "Not verified"
        title = "Threat handled" if fully_contained else "Confirmed threat detected"
        message = f"AutoGuard detected and contained {contained:,} confirmed {'threat' if contained == 1 else 'threats'}. Cleanup verification succeeded." if fully_contained else "AutoGuard detected a confirmed threat, but containment or cleanup could not be fully verified. Review the threat details."
        return {**base, "kind": "confirmed_threat", "title": title, "message": message, "note": issue_note, "threats_contained": contained, "matching_copies_found": matching_copies, "cleanup_status": cleanup_status, "containment_verified": fully_contained}

    _THREAT_STATUS_LABELS = {IncidentStatus.OPEN: ("Needs attention", "Needs attention"), IncidentStatus.INVESTIGATING: ("Being reviewed", "Needs attention"), IncidentStatus.CONTAINED: ("Contained", "Contained"), IncidentStatus.REAPPEARED: ("Detected again", "Needs attention"), IncidentStatus.RESTORED: ("Restored", "Needs attention"), IncidentStatus.RESOLVED: ("Resolved", "Resolved")}

    @staticmethod
    def _friendly_timestamp(value: Any) -> str:
        if value is None: return "Time unavailable"
        try: return (value.astimezone() if getattr(value, "tzinfo", None) else value).strftime("%b %d, %Y · %I:%M %p").replace(" 0", " ")
        except Exception: return "Time unavailable"

    def load_threats(self) -> None: self._submit("load-threats", self._threat_rows, "threats_data")

    def _threat_rows(self) -> list[dict[str, Any]]:
        rows = []
        for incident in self.services.incidents.list_incidents(200):
            if (details := self.services.incidents.get_incident(incident.id)) is None: continue
            status_label, section = self._THREAT_STATUS_LABELS[incident.status]
            location_count = len(tuple(details.files))
            location_text = f"First observed: {incident.first_observed_path}" if location_count <= 1 else f"{location_count:,} observed locations"
            matching_paths = {event.path for event in details.events if event.event_type is IncidentEventType.MATCHING_COPY_FOUND and event.path}
            matching_copy_count = len(matching_paths) or sum(1 for event in details.events if event.event_type is IncidentEventType.MATCHING_COPY_FOUND)
            rows.append({"threat_ref": incident.id, "section": section, "status": status_label, "status_key": {"Needs attention": "attention", "Being reviewed": "reviewing", "Contained": "contained", "Detected again": "reappeared", "Restored": "restored", "Resolved": "resolved"}[status_label], "name": self._display_name(incident.first_observed_path), "location": location_text, "detected": self._friendly_timestamp(incident.last_observed_at), "matching_copies": matching_copy_count, "action": "Review" if section == "Needs attention" else "View details"})
        return rows

    @property
    def selected_threat_ref(self) -> str | None: return self._selected_threat_ref

    def open_threat_details(self, threat_ref: str) -> None:
        if not threat_ref: return
        self._selected_threat_ref = str(threat_ref)
        self.bus.publish("threat_details_requested", threat_ref=self._selected_threat_ref)
        self.navigate_to("threats")

    def close_threat_details(self) -> None:
        self._selected_threat_ref = None
        self.bus.publish("threat_details_closed")

    def load_threat_details(self, threat_ref: str | None = None) -> None:
        if not (ref := str(threat_ref or self._selected_threat_ref or "").strip()): return
        self._submit(f"load-threat-details:{ref}", lambda: self._threat_details_snapshot(ref), "threat_details_data")

    def _threat_details_snapshot(self, threat_ref: str) -> dict[str, Any]:
        if (details := self.services.incidents.get_incident(threat_ref)) is None: raise KeyError("The selected threat is no longer available.")
        incident = details.incident
        status_label, _ = self._THREAT_STATUS_LABELS[incident.status]
        status_key = {IncidentStatus.OPEN: "attention", IncidentStatus.INVESTIGATING: "reviewing", IncidentStatus.CONTAINED: "contained", IncidentStatus.REAPPEARED: "reappeared", IncidentStatus.RESTORED: "restored", IncidentStatus.RESOLVED: "resolved"}[incident.status]
        detection = self.services.scanner.history.latest_detection_for_sha256(incident.sha256)
        quarantine_items = tuple(item for item in self.services.quarantine.list_quarantined_items() if item.incident_id == incident.id and item.sha256 == incident.sha256)
        verifications = self.services.cleanup_verifier.list_verifications(incident.id)
        latest_verification = verifications[-1] if verifications else None
        recovery_attempts = sorted([attempt for item in quarantine_items for attempt in self.services.recovery.list_attempts(item.quarantine_id)], key=lambda item: (item.attempted_at, item.id))
        explanation = build_explanation(ExplanationContext(result=detection, incident=details, quarantine_items=quarantine_items, latest_verification=latest_verification, recovery_attempts=tuple(recovery_attempts))) if detection is not None else None
        matching_found_paths = {event.path for event in details.events if event.event_type is IncidentEventType.MATCHING_COPY_FOUND and event.path}
        matching_found = len(matching_found_paths) or sum(event.event_type is IncidentEventType.MATCHING_COPY_FOUND for event in details.events)
        matching_quarantined_paths = {event.path for event in details.events if event.event_type is IncidentEventType.MATCHING_COPY_QUARANTINED and event.path}
        matching_quarantined = len(matching_quarantined_paths) or sum(event.event_type is IncidentEventType.MATCHING_COPY_QUARANTINED for event in details.events)
        cleanup_started = any(event.event_type is IncidentEventType.MATCHING_CLEANUP_STARTED for event in details.events)
        detection_text = f'AutoGuard detected this file because it matched the stored signature “{detection.matched_signature_name}”.' if detection is not None and detection.matched_signature_name else explanation.summary if explanation is not None else "AutoGuard recorded confirmed threat evidence for this file." if details.files and details.files[0].first_detection_reason else "AutoGuard recorded a confirmed threat for this file."
        successful_quarantine, failed_quarantine = tuple(item for item in quarantine_items if item.state is QuarantineState.QUARANTINED), tuple(item for item in quarantine_items if item.state is QuarantineState.FAILED)
        if successful_quarantine:
            count = len(successful_quarantine)
            action_text = f"AutoGuard isolated {count:,} related {'file' if count == 1 else 'files'} in quarantine." + (" One or more additional quarantine attempts did not complete successfully." if failed_quarantine else "")
        elif failed_quarantine: action_text = "AutoGuard attempted to quarantine this threat, but the recorded quarantine action did not complete successfully."
        else: action_text = "No successful quarantine action is recorded for this threat."
        matching_text = f"AutoGuard found {matching_found:,} additional exact matching {'copy' if matching_found == 1 else 'copies'}." + (f" {matching_quarantined:,} matching {'copy was' if matching_quarantined == 1 else 'copies were'} quarantined." if matching_quarantined else "") if matching_found else "Matching-Copy Cleanup ran and no additional exact matching copies were recorded." if cleanup_started else "No Matching-Copy Cleanup discovery record is available for this threat."
        if latest_verification is None: cleanup_text, cleanup_label = "Cleanup verification has not been recorded yet.", "Not verified"
        elif latest_verification.status is VerificationStatus.VERIFIED: cleanup_text, cleanup_label = "Cleanup verification succeeded. No remaining exact matching copies were found in the locations AutoGuard successfully checked.", "Verified"
        elif latest_verification.status is VerificationStatus.PARTIAL:
            parts = []
            if latest_verification.remaining_matching_copies: parts.append(f"{latest_verification.remaining_matching_copies:,} exact matching {'copy remained' if latest_verification.remaining_matching_copies == 1 else 'copies remained'}")
            if latest_verification.inaccessible_locations: parts.append(f"{latest_verification.inaccessible_locations:,} {'location could' if latest_verification.inaccessible_locations == 1 else 'locations could'} not be fully checked")
            if latest_verification.verification_errors: parts.append(f"{latest_verification.verification_errors:,} verification {'error was' if latest_verification.verification_errors == 1 else 'errors were'} recorded")
            cleanup_text, cleanup_label = f"Cleanup verification was partial: {'; '.join(parts) if parts else 'available evidence was incomplete'}.", "Partial"
        else: cleanup_text, cleanup_label = "Cleanup verification failed, so AutoGuard could not confirm that containment was complete.", "Failed"
        recovery_text = "A user-requested restore was recorded for quarantined content related to this threat." if [attempt for attempt in recovery_attempts if attempt.status in (RecoveryStatus.RESTORED, RecoveryStatus.RESTORED_WITH_WARNING)] else "This threat is recorded as restored after a user-requested recovery action." if incident.status is IncidentStatus.RESTORED else None
        what_happened = [{"label": "Detection", "text": detection_text}, {"label": "Action taken", "text": action_text}, {"label": "Matching copies", "text": matching_text}, {"label": "Cleanup verification", "text": cleanup_text}]
        if recovery_text is not None: what_happened.append({"label": "Recovery", "text": recovery_text})
        return {"threat_ref": incident.id, "status": status_label, "status_key": status_key, "name": self._display_name(incident.first_observed_path), "first_observed_path": incident.first_observed_path, "sha256": incident.sha256, "first_observed_at": self._friendly_timestamp(incident.first_observed_at), "last_observed_at": self._friendly_timestamp(incident.last_observed_at), "what_happened": what_happened, "quarantine_count": len(quarantine_items), "cleanup_label": cleanup_label, "explanation": asdict(explanation) if explanation is not None else None}