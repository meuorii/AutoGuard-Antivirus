from __future__ import annotations
import json
from dataclasses import dataclass; from datetime import datetime; from pathlib import Path
from app.cleanup_verifier import CleanupVerifier
from app.explanations import SAFE_SCAN_WORDING, ExplanationContext, SecurityExplanation, build_explanation
from app.incidents import IncidentDetails, IncidentService
from app.models import DetectionStatus, ScanDetails, ScanSessionStatus, StoredScanResult
from app.quarantine import QuarantineItem, QuarantineService, QuarantineState
from app.recovery import RecoveryAttempt, RecoveryService
from app.scan_history import ScanHistory

@dataclass(frozen=True)
class ReportCounts:
    scanned: int; skipped: int; locked: int; unsupported: int; oversized: int; suspicious: int; dangerous: int; quarantined: int; failed: int
    def to_dict(self) -> dict[str, int]: return {"scanned": self.scanned, "skipped": self.skipped, "locked": self.locked, "unsupported": self.unsupported, "oversized": self.oversized, "suspicious": self.suspicious, "dangerous": self.dangerous, "quarantined": self.quarantined, "failed": self.failed}

@dataclass(frozen=True)
class FileSecurityReport:
    path: str; scan_status: str; sha256: str | None; explanation: SecurityExplanation
    def to_dict(self) -> dict[str, object]: return {"path": self.path, "scan_status": self.scan_status, "sha256": self.sha256, "explanation": self.explanation.to_dict()}

@dataclass(frozen=True)
class ScanSecurityReport:
    scan_id: str; scan_type: str; source: str; source_path: str; started_at: datetime; finished_at: datetime | None; status: str; message: str; counts: ReportCounts; files: tuple[FileSecurityReport, ...]; scan_error: str | None = None
    def to_dict(self) -> dict[str, object]: return {"schema_version": 1, "scan_id": self.scan_id, "scan_type": self.scan_type, "source": self.source, "source_path": self.source_path, "started_at": self.started_at.isoformat(), "finished_at": self.finished_at.isoformat() if self.finished_at else None, "status": self.status, "message": self.message, "counts": self.counts.to_dict(), "scan_error": self.scan_error, "files": [item.to_dict() for item in self.files]}
    def to_json(self, *, indent: int = 2) -> str: return json.dumps(self.to_dict(), indent=indent, sort_keys=True)
    def to_text(self) -> str:
        c = self.counts
        lines = ["AutoGuard Security Report", f"Scan ID: {self.scan_id}", f"Type: {self.scan_type}", f"Source: {self.source}", f"Path: {self.source_path}", f"Status: {self.status}", f"Started: {self.started_at.isoformat()}", f"Finished: {self.finished_at.isoformat() if self.finished_at else 'not finished'}", "", self.message, "", "Counts:", f"  Scanned: {c.scanned}", f"  Skipped: {c.skipped}", f"  Locked: {c.locked}", f"  Unsupported: {c.unsupported}", f"  Oversized: {c.oversized}", f"  Suspicious: {c.suspicious}", f"  Dangerous: {c.dangerous}", f"  Quarantined: {c.quarantined}", f"  Failed: {c.failed}"]
        if self.scan_error: lines.extend(("", f"Scan note/error: {self.scan_error}"))
        for item in self.files:
            exp = item.explanation
            lines.extend(("", f"[{exp.severity.value}] {item.path}", f"  Scan status: {item.scan_status}", f"  Confidence: {exp.confidence if exp.confidence is not None else 'n/a'}", f"  Summary: {exp.summary}"))
            if exp.evidence: lines.append("  Evidence:"); lines.extend(f"    - {value}" for value in exp.evidence)
            if exp.actions: lines.append("  Actions/status:"); lines.extend(f"    - {value}" for value in exp.actions)
            if exp.cautions: lines.append("  Cautions:"); lines.extend(f"    - {value}" for value in exp.cautions)
        return "\n".join(lines) + "\n"
    def export_json(self, path: str | Path) -> Path:
        destination = Path(path).expanduser(); destination.parent.mkdir(parents=True, exist_ok=True); destination.write_text(self.to_json() + "\n", encoding="utf-8"); return destination
    def export_text(self, path: str | Path) -> Path:
        destination = Path(path).expanduser(); destination.parent.mkdir(parents=True, exist_ok=True); destination.write_text(self.to_text(), encoding="utf-8"); return destination

class ReportService:
    """Build reports only from persisted AutoGuard evidence."""
    def __init__(self, history: ScanHistory, incidents: IncidentService, quarantine: QuarantineService, cleanup_verifier: CleanupVerifier, recovery: RecoveryService) -> None:
        self.history = history; self.database = history.database; self.incidents = incidents; self.quarantine = quarantine; self.cleanup_verifier = cleanup_verifier; self.recovery = recovery

    def build_scan_report(self, session_id: str) -> ScanSecurityReport:
        details = self.history.get_scan(session_id)
        if details is None: raise KeyError(f"Unknown scan session: {session_id}")

        all_quarantine = tuple(self.quarantine.list_quarantined_items())
        incident_cache: dict[str, IncidentDetails | None] = {}; verification_cache = {}; recovery_cache: dict[str, tuple[RecoveryAttempt, ...]] = {}
        file_reports: list[FileSecurityReport] = []; quarantined_ids: set[str] = set()

        for result in details.results:
            incident = None; related_items: tuple[QuarantineItem, ...] = (); latest_verification = None; recovery_attempts: tuple[RecoveryAttempt, ...] = ()
            if result.sha256 and result.detection_status in (DetectionStatus.HIGH_CONFIDENCE, DetectionStatus.LOW_CONFIDENCE):
                incident = self._incident_for_hash(result.sha256, result.recorded_at, incident_cache)
                if incident is not None:
                    related_items = tuple(item for item in all_quarantine if item.incident_id == incident.incident.id and item.sha256 == result.sha256)
                    if incident.incident.id not in verification_cache:
                        values = self.cleanup_verifier.list_verifications(incident.incident.id); verification_cache[incident.incident.id] = values[-1] if values else None
                    latest_verification = verification_cache[incident.incident.id]
                    attempts: list[RecoveryAttempt] = []
                    for item in related_items:
                        if item.quarantine_id not in recovery_cache: recovery_cache[item.quarantine_id] = tuple(self.recovery.list_attempts(item.quarantine_id))
                        attempts.extend(recovery_cache[item.quarantine_id])
                    attempts.sort(key=lambda item: (item.attempted_at, item.id)); recovery_attempts = tuple(attempts)
                    for item in related_items:
                        if item.state is QuarantineState.QUARANTINED and item.original_path == result.path: quarantined_ids.add(item.quarantine_id)

            explanation = build_explanation(ExplanationContext(result=result, incident=incident, quarantine_items=related_items, latest_verification=latest_verification, recovery_attempts=recovery_attempts))
            file_reports.append(FileSecurityReport(path=result.path, scan_status=result.result_category.value, sha256=result.sha256, explanation=explanation))

        scanned = sum(item.entry_kind == "file" and item.result_category.value == "SCANNED" for item in details.results)
        locked = sum(item.result_category.value == "SKIPPED_LOCKED" for item in details.results)
        unsupported = sum(item.result_category.value == "SKIPPED_UNSUPPORTED" for item in details.results)
        oversized = sum(item.result_category.value == "SKIPPED_SIZE" for item in details.results)
        skipped = locked + unsupported + oversized
        suspicious = sum(item.detection_status is DetectionStatus.LOW_CONFIDENCE for item in details.results)
        dangerous = sum(item.detection_status is DetectionStatus.HIGH_CONFIDENCE for item in details.results)
        failed = sum(item.result_category.value == "ERROR" for item in details.results)
        report_counts = ReportCounts(scanned=scanned, skipped=skipped, locked=locked, unsupported=unsupported, oversized=oversized, suspicious=suspicious, dangerous=dangerous, quarantined=len(quarantined_ids), failed=failed)
        message = self._message(details, report_counts)

        return ScanSecurityReport(scan_id=details.session.id, scan_type=details.session.scan_type.value, source=details.session.source.value, source_path=details.session.source_path, started_at=details.session.started_at, finished_at=details.session.finished_at, status=details.session.status.value, message=message, counts=report_counts, files=tuple(file_reports), scan_error=details.session.error)

    @staticmethod
    def _message(details: ScanDetails, counts: ReportCounts) -> str:
        if counts.dangerous or counts.suspicious: message = f"Detections recorded in successfully evaluated files: {counts.dangerous} dangerous, {counts.suspicious} suspicious."
        else: message = SAFE_SCAN_WORDING
        if details.session.status is not ScanSessionStatus.COMPLETED or counts.skipped or counts.failed: message += " Scan coverage was incomplete or limited; review skipped, locked, unsupported, oversized, and failed counts before drawing broader conclusions."
        return message

    def _incident_for_hash(self, sha256: str, recorded_at: datetime, cache: dict[str, IncidentDetails | None]) -> IncidentDetails | None:
        key = f"{sha256}:{recorded_at.isoformat()}"
        if key in cache: return cache[key]
        with self.database.connection() as connection:
            row = connection.execute("SELECT id FROM threat_incidents WHERE sha256 = ? AND created_at <= ? ORDER BY created_at DESC, rowid DESC LIMIT 1", (sha256, recorded_at.isoformat())).fetchone()
        value = self.incidents.get_incident(row["id"]) if row is not None else None
        cache[key] = value; return value