from __future__ import annotations
import threading
from concurrent.futures import ThreadPoolExecutor
from dataclasses import asdict
from pathlib import Path
from typing import Any, Callable
from app.incidents import IncidentStatus
from app.models import DetectionStatus, ScanResult, ScanSource, ScanStatus, ScanType
from app.startup import AutoGuardServices
from app.ui.messages import UIMessageBus

class AutoGuardUIController:
    def __init__(self, services: AutoGuardServices, bus: UIMessageBus | None = None) -> None:
        self.services, self.bus = services, bus if bus is not None else UIMessageBus()
        self._executor = ThreadPoolExecutor(max_workers=4, thread_name_prefix="AutoGuardUI")
        self._lock = threading.RLock(); self._active_tasks: set[str] = set()

    def shutdown(self) -> None: self._executor.shutdown(wait=False, cancel_futures=False)
    def active_tasks(self) -> tuple[str, ...]:
        with self._lock: return tuple(sorted(self._active_tasks))

    def _submit(self, task_name: str, operation: Callable[[], Any], success_kind: str) -> None:
        with self._lock: self._active_tasks.add(task_name)
        self.bus.publish("task_started", task=task_name, active_tasks=self.active_tasks())
        def runner() -> None:
            try:
                result = operation(); self.bus.publish(success_kind, task=task_name, result=result)
            except Exception as error:
                self.bus.publish("task_failed", task=task_name, error=f"{type(error).__name__}: {error}")
            finally:
                with self._lock: self._active_tasks.discard(task_name)
                self.bus.publish("task_finished", task=task_name, active_tasks=self.active_tasks())
        self._executor.submit(runner)

    def refresh_dashboard(self) -> None: self._submit("refresh-dashboard", self._dashboard_snapshot, "dashboard_data")
    def _dashboard_snapshot(self) -> dict[str, Any]:
        file_health = self.services.file_monitor.health() if self.services.file_monitor else None
        usb_health = self.services.usb_monitor.health() if self.services.usb_monitor else None
        scheduler_health = self.services.scheduler.health()
        quarantine = self.services.quarantine.list_quarantined_items()
        active_incidents = self.services.incidents.get_active_incidents()
        recent = self.services.scanner.history.recent_scans(8); recent_detections: list[dict[str, Any]] = []
        for session in recent:
            details = self.services.scanner.history.get_scan(session.id)
            if details is None: continue
            for result in reversed(details.results):
                if result.detection_status in (DetectionStatus.HIGH_CONFIDENCE, DetectionStatus.LOW_CONFIDENCE):
                    recent_detections.append({"path": result.path, "status": result.detection_status.value, "reason": result.detection_reason or result.reason, "recorded_at": result.recorded_at.isoformat()})
                    if len(recent_detections) >= 5: break
            if len(recent_detections) >= 5: break
        return {"file_monitor": file_health, "usb_monitor": usb_health, "scheduler": scheduler_health, "quarantined_count": sum(1 for item in quarantine if item.state.value == "QUARANTINED"), "active_incidents": len(active_incidents), "recent_scans": recent, "recent_detections": recent_detections, "active_tasks": self.active_tasks(), "monitor_paths": tuple(str(path) for path in (self.services.file_monitor.monitored_paths() if self.services.file_monitor else ()))}

    def load_incidents(self) -> None: self._submit("load-incidents", self._incident_rows, "incidents_data")
    def _incident_rows(self) -> list[dict[str, Any]]:
        with self.services.database.connection() as connection:
            ids = [row["id"] for row in connection.execute("SELECT id FROM threat_incidents ORDER BY last_observed_at DESC, rowid DESC LIMIT 200").fetchall()]
        rows: list[dict[str, Any]] = []
        for incident_id in ids:
            details = self.services.incidents.get_incident(incident_id)
            if details is None: continue
            latest_verification = self.services.cleanup_verifier.list_verifications(incident_id)
            rows.append({"details": details, "verification": latest_verification[-1] if latest_verification else None})
        return rows

    def load_threat_trail(self, limit: int = 200) -> None:
        def load() -> list[dict[str, Any]]:
            with self.services.database.connection() as connection:
                rows = connection.execute("SELECT e.id, o.sha256, o.path, e.source, e.observed_at, o.seen_count FROM observation_events e JOIN file_observations o ON o.id = e.observation_id ORDER BY e.observed_at DESC, e.id DESC LIMIT ?", (limit,)).fetchall()
            return [dict(row) for row in rows]
        self._submit("load-threat-trail", load, "threat_trail_data")

    def load_quarantine(self) -> None: self._submit("load-quarantine", self.services.quarantine.list_quarantined_items, "quarantine_data")
    def load_history(self) -> None: self._submit("load-history", lambda: self.services.scanner.history.recent_scans(100), "history_data")
    def load_scan_report(self, session_id: str) -> None: self._submit(f"report:{session_id}", lambda: self.services.reports.build_scan_report(session_id), "scan_report_data")

    def start_scan(self, path: str | Path, *, scan_type: ScanType = ScanType.MANUAL) -> None:
        target = Path(path); task = f"scan:{target}"; self.bus.publish("scan_started", path=str(target), scan_type=scan_type.value)
        def scan():
            discovered = processed = 0
            def on_discovered(path: str, kind: str) -> None:
                nonlocal discovered; discovered += 1; self.bus.publish("scan_discovered", path=path, entry_kind=kind, discovered=discovered, processed=processed)
            def on_result(result: ScanResult) -> None:
                nonlocal discovered, processed; processed += 1; discovered = max(discovered, processed); d = result.detection.status.value if result.detection else None
                self.bus.publish("scan_result", path=result.path, status=result.status.value, detection=d, reason=result.reason, processed=processed, discovered=discovered, progress=(processed / discovered) if discovered else 0.0)
            return self.services.scanner.scan(target, ScanSource.MANUAL, scan_type=scan_type, on_result=on_result, on_discovered=on_discovered)
        self._submit(task, scan, "scan_completed")

    def start_quick_scan(self) -> None: self._start_path_batch("quick", self.services.scheduler.quick_paths, ScanType.QUICK)
    def start_full_scan(self) -> None: self._start_path_batch("full", self.services.scheduler.full_paths, ScanType.FULL)

    def _start_path_batch(self, label: str, paths: tuple[Path, ...], scan_type: ScanType) -> None:
        task = f"{label}-scan"; self.bus.publish("scan_started", path=label, scan_type=scan_type.value)
        def run_batch() -> list[Any]:
            existing = tuple(path for path in paths if path.exists()); discovered = processed = 0
            def on_discovered(path: str, kind: str) -> None:
                nonlocal discovered; discovered += 1; self.bus.publish("scan_discovered", path=path, entry_kind=kind, discovered=discovered, processed=processed)
            def on_result(result: ScanResult) -> None:
                nonlocal discovered, processed; processed += 1; discovered = max(discovered, processed)
                self.bus.publish("scan_result", path=result.path, status=result.status.value, detection=result.detection.status.value if result.detection else None, reason=result.reason, processed=processed, discovered=discovered, progress=(processed / discovered) if discovered else 0.0)
            return [self.services.scanner.scan(path, ScanSource.MANUAL, scan_type=scan_type, on_result=on_result, on_discovered=on_discovered) for path in existing]
        self._submit(task, run_batch, "scan_batch_completed")

    def verify_quarantine(self, quarantine_id: str) -> None: self._submit(f"verify-quarantine:{quarantine_id}", lambda: self.services.quarantine.verify_integrity(quarantine_id), "quarantine_verified")
    def restore_quarantine(self, quarantine_id: str, destination: str | Path | None = None) -> None: self._submit(f"restore:{quarantine_id}", lambda: self.services.recovery.restore(quarantine_id, destination), "recovery_completed")
    def delete_quarantine(self, quarantine_id: str) -> None: self._submit(f"delete-quarantine:{quarantine_id}", lambda: self.services.quarantine.delete_quarantine_object(quarantine_id), "quarantine_deleted")
    def verify_incident_cleanup(self, incident_id: str) -> None: self._submit(f"verify-incident:{incident_id}", lambda: self.services.cleanup_verifier.verify_incident(incident_id), "incident_verified")

    def settings_snapshot(self) -> dict[str, Any]:
        return {"database": str(self.services.config.database_path), "quarantine": str(self.services.config.quarantine_dir), "max_file_size_bytes": self.services.config.max_file_size_bytes, "monitor_paths": tuple(str(p) for p in (self.services.file_monitor.monitored_paths() if self.services.file_monitor else ())), "quick_hours": self.services.scheduler.settings.quick_interval_hours, "full_days": self.services.scheduler.settings.full_interval_days, "file_monitor_enabled": self.services.file_monitor is not None, "usb_monitor_enabled": self.services.usb_monitor is not None}