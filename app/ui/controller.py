from __future__ import annotations
import threading
from concurrent.futures import ThreadPoolExecutor
from dataclasses import asdict
from pathlib import Path
from typing import Any, Callable
from app.cleanup_verifier import VerificationStatus
from app.incidents import IncidentEventType, IncidentStatus
from app.models import DetectionStatus, ScanResult, ScanSource, ScanStatus, ScanType
from app.scanner import ScanInterruptedError
from app.startup import AutoGuardServices
from app.ui.messages import UIMessageBus

class AutoGuardUIController:
    def __init__(self, services: AutoGuardServices, bus: UIMessageBus | None = None) -> None:
        self.services, self.bus = services, bus if bus is not None else UIMessageBus()
        self._executor, self._lock = ThreadPoolExecutor(max_workers=4, thread_name_prefix="AutoGuardUI"), threading.RLock()
        self._active_tasks, self._scan_cancel_events = set(), {}
        self._current_scan_task, self._selected_threat_ref = None, None

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
        threats_needing_review, active_tasks = sum(1 for incident in active_incidents if incident.status in review_statuses), self.active_tasks()
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
            checked = int(last_session.counters.get("scanned_files", 0))
            last_scan = {"value": self._scan_label(last_session.scan_type), "detail": f"{checked:,} {'file' if checked == 1 else 'files'} checked · {self._friendly_scan_status(last_session.status)}", "when": last_session.finished_at or last_session.started_at}
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
            detection = next((r for r in reversed(details.results) if r.detection_status in (DetectionStatus.HIGH_CONFIDENCE, DetectionStatus.LOW_CONFIDENCE)), None) if details else None
            if detection is not None:
                dangerous = detection.detection_status is DetectionStatus.HIGH_CONFIDENCE
                events.append({"title": "Threat detected" if dangerous else "Suspicious file detected", "detail": self._display_name(detection.path), "when": detection.recorded_at, "tone": "danger" if dangerous else "warning"})
                continue
            when = session.finished_at or session.started_at
            if session.scan_type is ScanType.REAL_TIME:
                events.append({"title": "File scanned", "detail": self._display_name(session.source_path), "when": when, "tone": "success"})
                continue
            label, running = self._scan_label(session.scan_type), getattr(session.status, "value", str(session.status)).upper() == "RUNNING"
            title = ("USB drive scan started" if running else "USB drive scanned") if session.scan_type is ScanType.USB else (f"{label} started" if running else f"{label} completed")
            checked = int(session.counters.get("scanned_files", 0))
            events.append({"title": title, "detail": f"{checked:,} {'file' if checked == 1 else 'files'} checked" if checked else self._friendly_scan_status(session.status), "when": when, "tone": "success" if getattr(session.status, "value", "") == "COMPLETED" else "info"})
        return events[:limit]

    def prepare_scan_result(self, scan_output: Any) -> None:
        summaries = tuple(scan_output) if isinstance(scan_output, (list, tuple)) else (scan_output,)
        session_ids = tuple(str(s.session_id) for s in summaries if getattr(s, "session_id", None))
        self._submit(f"prepare-scan-result:{session_ids[0] if session_ids else 'unknown'}", lambda: self._scan_result_snapshot(summaries), "scan_result_ready")

    @staticmethod
    def _format_duration(seconds: float | None) -> str:
        if seconds is None: return "—"
        minutes, secs = divmod(max(0, int(round(seconds))), 60)
        hours, minutes = divmod(minutes, 60)
        if hours: return f"{hours} hr {minutes} min" if minutes else f"{hours} hr"
        if minutes: return f"{minutes} min {secs} sec" if secs else f"{minutes} min"
        return f"{secs} sec"

    def _scan_result_snapshot(self, summaries: tuple[Any, ...]) -> dict[str, Any]:
        history = self.services.scanner.history
        details = [history.get_scan(str(s.session_id)) for s in summaries if getattr(s, "session_id", None) and history.get_scan(str(s.session_id))]
        counter_names = ("scanned_files", "dangerous_detections", "suspicious_detections", "skipped_size", "locked_files", "unsupported_files", "errors", "file_errors")
        counters = {name: sum(int(item.session.counters.get(name, 0)) for item in details) for name in counter_names} if details else {name: sum(int(getattr(s, "counts", {}).get(name, 0)) for s in summaries) for name in counter_names}
        scan_types = [item.session.scan_type for item in details]
        scan_type = scan_types[0] if scan_types and all(v is scan_types[0] for v in scan_types) else None
        starts, finishes = [item.session.started_at for item in details], [item.session.finished_at for item in details if item.session.finished_at is not None]
        started_at, finished_at = min(starts) if starts else None, max(finishes) if finishes else None
        duration_seconds = (finished_at - started_at).total_seconds() if started_at and finished_at else None
        files_checked, suspicious, dangerous = counters["scanned_files"], counters["suspicious_detections"], counters["dangerous_detections"]
        skipped, errors = counters["skipped_size"] + counters["locked_files"] + counters["unsupported_files"], counters["errors"]
        base = {"scan_type": self._scan_label(scan_type) if scan_type else "Scan", "duration": self._format_duration(duration_seconds), "files_checked": files_checked, "threats_found": dangerous, "skipped_files": skipped, "suspicious_files": suspicious}
        issue_note = "Some files could not be checked. View scan details for more information." if (skipped or errors) else ("No files were successfully scanned. View scan details for more information." if files_checked == 0 else "")
        if dangerous == 0 and suspicious == 0: return {**base, "kind": "clean", "title": "Scan complete", "message": "No threats detected in the files successfully scanned.", "note": issue_note}
        if dangerous == 0: return {**base, "kind": "suspicious", "title": "Review recommended", "message": f"AutoGuard found {suspicious:,} suspicious {'file' if suspicious == 1 else 'files'}, but no confirmed threat was detected.", "note": "Suspicious evidence does not by itself confirm malware. " + issue_note}
        dangerous_hashes = {r.sha256 for item in details for r in item.results if r.detection_status is DetectionStatus.HIGH_CONFIDENCE and r.sha256}
        active_incidents = {i.sha256: i for i in self.services.incidents.get_active_incidents()}
        contained, matching_copies, verification_states = 0, 0, []
        for sha256 in dangerous_hashes:
            incident = active_incidents.get(sha256)
            if not incident: continue
            incident_details = self.services.incidents.get_incident(incident.id)
            verifications = self.services.cleanup_verifier.list_verifications(incident.id)
            latest = verifications[-1] if verifications else None
            if latest: verification_states.append(latest.status)
            if latest and latest.status is VerificationStatus.VERIFIED and incident.status is IncidentStatus.CONTAINED: contained += 1
            if incident_details: matching_copies += sum(1 for e in incident_details.events if e.event_type is IncidentEventType.MATCHING_COPY_FOUND and (started_at is None or e.occurred_at >= started_at))
        fully_contained = bool(dangerous_hashes) and contained == len(dangerous_hashes)
        cleanup_status = "Verified" if (verification_states and all(s is VerificationStatus.VERIFIED for s in verification_states) and len(verification_states) == len(dangerous_hashes)) else ("Failed" if any(s is VerificationStatus.FAILED for s in verification_states) else ("Partial" if any(s is VerificationStatus.PARTIAL for s in verification_states) else "Not verified"))
        return {**base, "kind": "confirmed_threat", "title": "Threat handled" if fully_contained else "Confirmed threat detected", "message": f"AutoGuard detected and contained {contained:,} confirmed {'threat' if contained == 1 else 'threats'}. Cleanup verification succeeded." if fully_contained else "AutoGuard detected a confirmed threat, but containment or cleanup could not be fully verified. Review the threat details.", "note": issue_note, "threats_contained": contained, "matching_copies_found": matching_copies, "cleanup_status": cleanup_status, "containment_verified": fully_contained}

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
            details = self.services.incidents.get_incident(incident.id)
            if details is None: continue
            status_label, section = self._THREAT_STATUS_LABELS[incident.status]
            location_count = len(tuple(details.files))
            matching_paths = {e.path for e in details.events if e.event_type is IncidentEventType.MATCHING_COPY_FOUND and e.path}
            rows.append({"threat_ref": incident.id, "section": section, "status": status_label, "status_key": {"Needs attention": "attention", "Being reviewed": "reviewing", "Contained": "contained", "Detected again": "reappeared", "Restored": "restored", "Resolved": "resolved"}[status_label], "name": self._display_name(incident.first_observed_path), "location": f"First observed: {incident.first_observed_path}" if location_count <= 1 else f"{location_count:,} observed locations", "detected": self._friendly_timestamp(incident.last_observed_at), "matching_copies": len(matching_paths) if matching_paths else sum(1 for e in details.events if e.event_type is IncidentEventType.MATCHING_COPY_FOUND), "action": "Review" if section == "Needs attention" else "View details"})
        return rows

    @property
    def selected_threat_ref(self) -> str | None: return self._selected_threat_ref

    def open_threat_details(self, threat_ref: str) -> None:
        if not threat_ref: return
        self._selected_threat_ref = str(threat_ref)
        self.bus.publish("threat_details_requested", threat_ref=self._selected_threat_ref)
        self.navigate_to("threats")

    def load_incidents(self) -> None: self._submit("load-incidents", self._incident_rows, "incidents_data")

    def _incident_rows(self) -> list[dict[str, Any]]:
        with self.services.database.connection() as conn: ids = [r["id"] for r in conn.execute("SELECT id FROM threat_incidents ORDER BY last_observed_at DESC, rowid DESC LIMIT 200").fetchall()]
        rows = []
        for i_id in ids:
            details = self.services.incidents.get_incident(i_id)
            if details: verifs = self.services.cleanup_verifier.list_verifications(i_id); rows.append({"details": details, "verification": verifs[-1] if verifs else None})
        return rows

    def load_threat_trail(self, limit: int = 200) -> None:
        def load():
            with self.services.database.connection() as conn: return [dict(r) for r in conn.execute("SELECT e.id, o.sha256, o.path, e.source, e.observed_at, o.seen_count FROM observation_events e JOIN file_observations o ON o.id = e.observation_id ORDER BY e.observed_at DESC, e.id DESC LIMIT ?", (limit,)).fetchall()]
        self._submit("load-threat-trail", load, "threat_trail_data")

    def load_quarantine(self) -> None: self._submit("load-quarantine", self.services.quarantine.list_quarantined_items, "quarantine_data")
    def load_history(self) -> None: self._submit("load-history", lambda: self.services.scanner.history.recent_scans(100), "history_data")
    def load_scan_report(self, session_id: str) -> None: self._submit(f"report:{session_id}", lambda: self.services.reports.build_scan_report(session_id), "scan_report_data")

    def _begin_ui_scan(self, task: str) -> threading.Event | None:
        with self._lock:
            if self._current_scan_task is not None: active = self._current_scan_task
            else:
                event = threading.Event()
                self._current_scan_task, self._scan_cancel_events[task] = task, event
                return event
        self.bus.publish("scan_rejected", task=task, active_task=active, reason="Another scan is already running.")
        return None

    def stop_scan(self) -> bool:
        with self._lock:
            task = self._current_scan_task
            event = self._scan_cancel_events.get(task) if task is not None else None
        if task is None or event is None: return False
        event.set()
        self.bus.publish("scan_stop_requested", task=task)
        return True

    def start_scan(self, path: str | Path, *, scan_type: ScanType = ScanType.MANUAL) -> None:
        target, task = Path(path), f"scan:{Path(path)}"
        cancel_event = self._begin_ui_scan(task)
        if cancel_event is None: return
        self.bus.publish("scan_started", path=str(target), scan_type=scan_type.value, task=task)
        def scan():
            discovered = processed = 0
            def on_discovered(path: str, kind: str) -> None:
                nonlocal discovered
                discovered += 1
                self.bus.publish("scan_discovered", path=path, entry_kind=kind, discovered=discovered, processed=processed, task=task)
            def on_result(result: ScanResult) -> None:
                nonlocal discovered, processed
                processed += 1
                discovered = max(discovered, processed)
                self.bus.publish("scan_result", path=result.path, status=result.status.value, detection=result.detection.status.value if result.detection else None, reason=result.reason, processed=processed, discovered=discovered, progress=(processed / discovered) if discovered else 0.0, task=task)
            return self.services.scanner.scan(target, ScanSource.MANUAL, scan_type=scan_type, interrupt_check=cancel_event.is_set, on_result=on_result, on_discovered=on_discovered)
        self._submit(task, scan, "scan_completed")

    def start_quick_scan(self) -> None: self._start_path_batch("quick", self.services.scheduler.quick_paths, ScanType.QUICK)
    def start_full_scan(self) -> None: self._start_path_batch("full", self.services.scheduler.full_paths, ScanType.FULL)

    def _start_path_batch(self, label: str, paths: tuple[Path, ...], scan_type: ScanType) -> None:
        task = f"{label}-scan"
        cancel_event = self._begin_ui_scan(task)
        if cancel_event is None: return
        self.bus.publish("scan_started", path=label, scan_type=scan_type.value, task=task)
        def run_batch() -> list[Any]:
            existing, discovered, processed = tuple(p for p in paths if p.exists()), 0, 0
            def on_discovered(path: str, kind: str) -> None:
                nonlocal discovered
                discovered += 1
                self.bus.publish("scan_discovered", path=path, entry_kind=kind, discovered=discovered, processed=processed, task=task)
            def on_result(result: ScanResult) -> None:
                nonlocal discovered, processed
                processed += 1
                discovered = max(discovered, processed)
                self.bus.publish("scan_result", path=result.path, status=result.status.value, detection=result.detection.status.value if result.detection else None, reason=result.reason, processed=processed, discovered=discovered, progress=(processed / discovered) if discovered else 0.0, task=task)
            summaries = []
            for path in existing:
                if cancel_event.is_set(): raise ScanInterruptedError("Scan stopped by the user.")
                summaries.append(self.services.scanner.scan(path, ScanSource.MANUAL, scan_type=scan_type, interrupt_check=cancel_event.is_set, on_result=on_result, on_discovered=on_discovered))
            return summaries
        self._submit(task, run_batch, "scan_batch_completed")

    def verify_quarantine(self, quarantine_id: str) -> None: self._submit(f"verify-quarantine:{quarantine_id}", lambda: self.services.quarantine.verify_integrity(quarantine_id), "quarantine_verified")
    def restore_quarantine(self, quarantine_id: str, destination: str | Path | None = None) -> None: self._submit(f"restore:{quarantine_id}", lambda: self.services.recovery.restore(quarantine_id, destination), "recovery_completed")
    def delete_quarantine(self, quarantine_id: str) -> None: self._submit(f"delete-quarantine:{quarantine_id}", lambda: self.services.quarantine.delete_quarantine_object(quarantine_id), "quarantine_deleted")
    def verify_incident_cleanup(self, incident_id: str) -> None: self._submit(f"verify-incident:{incident_id}", lambda: self.services.cleanup_verifier.verify_incident(incident_id), "incident_verified")

    def settings_snapshot(self) -> dict[str, Any]: return {"database": str(self.services.c)}