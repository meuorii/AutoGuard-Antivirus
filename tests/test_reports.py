from __future__ import annotations
import json; from pathlib import Path; import pytest
from app.cleanup_verifier import CleanupVerifier, VerificationStatus; from app.database import Database; from app.detector import Detector; from app.incidents import IncidentService; from app.matching_cleanup import MatchingCopyCleanup; from app.models import DetectionResult, DetectionStatus, ScanResult, ScanSource, ScanStatus, ScanType; from app.quarantine import QuarantineService; from app.reappearance import ReappearanceWatch; from app.recovery import RecoveryService; from app.reports import ReportService; from app.scan_history import ScanHistory; from app.scanner import Scanner; from app.signatures import AUTOGUARD_TEST_CONTENT, SignatureStore, load_signatures; from app.threat_trail import ThreatTrail

@pytest.fixture
def services(tmp_path):
    database = Database(tmp_path / "data" / "database" / "autoguard.db"); database.initialize()
    incidents = IncidentService(database); trail = ThreatTrail(database); quarantine = QuarantineService(database, tmp_path / "data" / "quarantine", incidents); detector = Detector(load_signatures())
    protected = tmp_path / "protected"; protected.mkdir()
    cleanup = MatchingCopyCleanup(database, incidents, quarantine, trail, monitored_locations=(protected,)); verifier = CleanupVerifier(database, incidents, quarantine, monitored_locations=(protected,)); reappearance = ReappearanceWatch(database, incidents); history = ScanHistory(database)
    scanner = Scanner(detector, trail, history=history, incidents=incidents, quarantine=quarantine, matching_cleanup=cleanup, cleanup_verifier=verifier, reappearance=reappearance)
    recovery = RecoveryService(database, quarantine, detector, incidents); reports = ReportService(history, incidents, quarantine, verifier, recovery)
    return {"database": database, "incidents": incidents, "trail": trail, "quarantine": quarantine, "detector": detector, "protected": protected, "cleanup": cleanup, "verifier": verifier, "history": history, "scanner": scanner, "recovery": recovery, "reports": reports}

def _dangerous_scan(env, name="dangerous.bin"):
    path = env["protected"] / name; path.write_bytes(AUTOGUARD_TEST_CONTENT)
    summary = env["scanner"].scan_file(path, ScanSource.MANUAL)
    return summary, path

def test_dangerous_report_uses_signature_quarantine_cleanup_and_recovery_evidence(services):
    result, path = _dangerous_scan(services); report = services["reports"].build_scan_report(result.session_id)
    assert report.counts.scanned == 1; assert report.counts.dangerous == 1; assert report.counts.quarantined == 1
    explanation = report.files[0].explanation
    assert explanation.severity.value == "DANGEROUS"; assert explanation.confidence == 1.0
    joined = " ".join(explanation.evidence + explanation.actions + explanation.cautions)
    assert "SHA-256" in joined; assert "AutoGuard.Harmless.Test" in joined; assert "Quarantine succeeded" in joined; assert "Matching-Copy Cleanup" in joined; assert "Cleanup verification: VERIFIED" in joined; assert "Recovery is available" in joined; assert not path.exists()

def test_suspicious_report_explains_lower_confidence_and_no_automatic_quarantine(services):
    path = services["protected"] / "invoice.pdf.exe"; path.write_bytes(b"ordinary bytes")
    result = services["scanner"].scan_file(path, ScanSource.MANUAL); report = services["reports"].build_scan_report(result.session_id)
    assert report.counts.suspicious == 1; assert report.counts.dangerous == 0; assert report.counts.quarantined == 0
    explanation = report.files[0].explanation; text = " ".join(explanation.evidence + explanation.actions + explanation.cautions).lower()
    assert explanation.severity.value == "SUSPICIOUS"; assert "lower-confidence" in explanation.summary.lower(); assert "automatic quarantine was not performed" in text; assert "not proven malicious" in text; assert path.exists()

def test_partial_scan_report_counts_skips_and_never_claims_complete_safety(services, tmp_path):
    history = services["history"]; session = history.start_session(ScanType.MANUAL, tmp_path, ScanSource.MANUAL)
    clean_detection = DetectionResult(DetectionStatus.NO_DETECTION, 0.0, "No configured signature or heuristic matched this file.", "no_rule_matched", "0" * 64, str(tmp_path / "clean.txt"))
    history.record_result(session.id, ScanResult(str(tmp_path / "clean.txt"), ScanStatus.SCANNED, clean_detection.reason, detection=clean_detection, sha256=clean_detection.sha256))
    history.record_result(session.id, ScanResult(str(tmp_path / "large.bin"), ScanStatus.SKIPPED_SIZE, "too large"))
    history.record_result(session.id, ScanResult(str(tmp_path / "locked.bin"), ScanStatus.SKIPPED_LOCKED, "locked"))
    history.record_result(session.id, ScanResult(str(tmp_path / "special"), ScanStatus.SKIPPED_UNSUPPORTED, "unsupported"))
    history.record_result(session.id, ScanResult(str(tmp_path / "error.bin"), ScanStatus.ERROR, "read failed"))
    history.finish_session(session.id)

    report = services["reports"].build_scan_report(session.id)
    assert report.status == "INCOMPLETE"; assert report.counts.scanned == 1; assert report.counts.skipped == 3; assert report.counts.locked == 1; assert report.counts.unsupported == 1; assert report.counts.oversized == 1; assert report.counts.failed == 1
    assert "No threats detected in the files successfully scanned." in report.message; assert "coverage was incomplete" in report.message.lower(); assert "system is completely safe" not in report.to_text().lower()

def test_cleanup_failure_is_explained_from_latest_verification(services):
    result, _ = _dangerous_scan(services)
    item = next(value for value in services["quarantine"].list_quarantined_items() if value.state.value == "QUARANTINED")
    Path(item.stored_path).write_bytes(b"corrupted quarantine object")
    verification = services["verifier"].verify_incident(item.incident_id)
    assert verification.status is VerificationStatus.FAILED

    report = services["reports"].build_scan_report(result.session_id); explanation = report.files[0].explanation; text = " ".join(explanation.actions + explanation.cautions)
    assert "Cleanup verification: FAILED" in text; assert "could not be fully verified" in text

def test_reappearance_report_reuses_evidence_and_uses_careful_wording(services):
    first, _ = _dangerous_scan(services, "first.bin"); first_report = services["reports"].build_scan_report(first.session_id)
    assert "reappearance count: 0" in " ".join(first_report.files[0].explanation.evidence)

    returned = services["protected"] / "returned-copy.bin"; returned.write_bytes(AUTOGUARD_TEST_CONTENT)
    second = services["scanner"].scan_file(returned, ScanSource.FILE_MONITOR); report = services["reports"].build_scan_report(second.session_id)
    explanation = report.files[0].explanation; combined = " ".join(explanation.evidence + explanation.cautions)
    assert "reappearance count: 1" in combined; assert "This threat has reappeared after cleanup." in combined; assert "may be recreating it" in combined; assert "caused by" not in combined.lower()

def test_json_serialization_and_exports_are_structured_and_readable(services, tmp_path):
    path = services["protected"] / "clean.txt"; path.write_text("hello", encoding="utf-8")
    result = services["scanner"].scan_file(path, ScanSource.MANUAL); report = services["reports"].build_scan_report(result.session_id)

    payload = json.loads(report.to_json())
    assert payload["schema_version"] == 1; assert payload["scan_id"] == result.session_id; assert payload["counts"]["scanned"] == 1; assert payload["counts"]["dangerous"] == 0
    assert payload["message"].startswith("No threats detected in the files successfully scanned."); assert isinstance(payload["files"], list)

    json_path = report.export_json(tmp_path / "exports" / "scan.json"); text_path = report.export_text(tmp_path / "exports" / "scan.txt")
    assert json.loads(json_path.read_text(encoding="utf-8"))["scan_id"] == result.session_id
    text = text_path.read_text(encoding="utf-8")
    assert "AutoGuard Security Report" in text; assert "No threats detected in the files successfully scanned." in text; assert "system is completely safe" not in text.lower()