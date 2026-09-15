from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest

from app.cleanup_verifier import CleanupVerifier, VerificationStatus
from app.config import AppConfig
from app.database import Database
from app.detector import Detector
from app.hashing import normalize_path
from app.incidents import IncidentEventType, IncidentService, IncidentStatus
from app.matching_cleanup import MatchingCopyCleanup
from app.models import DetectionStatus, ScanSessionStatus, ScanSource, ScanStatus, ScanType
from app.quarantine import QuarantineService, QuarantineState
from app.reappearance import ReappearanceWatch
from app.recovery import RecoveryConflictOption, RecoveryService, RecoveryStatus
from app.scan_history import ScanHistory
from app.scanner import ScanInterruptedError, Scanner
from app.signatures import AUTOGUARD_TEST_CONTENT, AUTOGUARD_TEST_SHA256, SignatureStore, load_signatures
from app.threat_trail import ThreatTrail
from app.file_monitor import FileMonitor


def build_stack(tmp_path: Path, *, max_bytes: int = 512 * 1024 * 1024):
    config = AppConfig(data_dir=tmp_path / "runtime", max_file_size_bytes=max_bytes); config.create_directories()
    database = Database(config.database_path); database.initialize(); incidents = IncidentService(database); trail = ThreatTrail(database)
    quarantine = QuarantineService(database, config.quarantine_dir, incidents); downloads = tmp_path / "Downloads"; desktop = tmp_path / "Desktop"; usb = tmp_path / "FakeUSB"
    for root in (downloads, desktop, usb): root.mkdir(exist_ok=True)
    cleanup = MatchingCopyCleanup(database, incidents, quarantine, trail, monitored_locations=(downloads, desktop, usb))
    verifier = CleanupVerifier(database, incidents, quarantine, monitored_locations=(downloads, desktop, usb)); reappearance = ReappearanceWatch(database, incidents)
    history = ScanHistory(database); detector = Detector(load_signatures())
    scanner = Scanner(detector, trail, max_file_size_bytes=max_bytes, history=history, incidents=incidents, quarantine=quarantine, matching_cleanup=cleanup, cleanup_verifier=verifier, reappearance=reappearance)
    return config, database, incidents, trail, quarantine, cleanup, verifier, reappearance, history, scanner, downloads, desktop, usb


def test_complete_detection_cleanup_reappearance_and_recontainment(tmp_path):
    config, database, incidents, _, quarantine, _, verifier, _, _, scanner, downloads, desktop, usb = build_stack(tmp_path)
    seed = usb / "usb-payload.bin"; copy_a = downloads / "renamed-copy.dat"; copy_b = desktop / "another-name.tmp"
    for path in (seed, copy_a, copy_b): path.write_bytes(AUTOGUARD_TEST_CONTENT)

    first = scanner.scan_file(seed, ScanSource.USB, scan_type=ScanType.USB)
    assert first.detection and first.detection.status is DetectionStatus.HIGH_CONFIDENCE
    active = incidents.get_active_incidents(); assert len(active) == 1; incident_id = active[0].id
    assert active[0].sha256 == AUTOGUARD_TEST_SHA256 and active[0].status is IncidentStatus.CONTAINED
    assert not seed.exists() and not copy_a.exists() and not copy_b.exists()
    items = [q for q in quarantine.list_quarantined_items() if q.incident_id == incident_id and q.state is QuarantineState.QUARANTINED]
    assert len(items) == 3; assert scanner.last_cleanup_verification_results[-1].status is VerificationStatus.VERIFIED

    returned = desktop / "returned-later.bin"; returned.write_bytes(AUTOGUARD_TEST_CONTENT)
    second = scanner.scan_file(returned, ScanSource.FILE_MONITOR, scan_type=ScanType.REAL_TIME)
    assert second.detection and second.detection.status is DetectionStatus.HIGH_CONFIDENCE; assert not returned.exists()
    details = incidents.get_incident(incident_id); assert details is not None
    assert details.incident.status is IncidentStatus.CONTAINED and details.incident.reappearance_count == 1
    re_events = [e for e in details.events if e.event_type is IncidentEventType.REAPPEARANCE]
    assert len(re_events) == 1 and re_events[0].reappearance_count == 1 and re_events[0].path == str(normalize_path(returned))
    assert len(incidents.get_active_incidents()) == 1
    assert scanner.last_cleanup_verification_results[-1].status is VerificationStatus.VERIFIED

    reopened = Database(config.database_path); reopened.initialize(); reopened_details = IncidentService(reopened).get_incident(incident_id)
    assert reopened_details and reopened_details.incident.reappearance_count == 1 and reopened_details.incident.status is IncidentStatus.CONTAINED


def test_interrupted_scan_is_persisted_as_incomplete(tmp_path):
    *_, history, scanner, downloads, _, _ = build_stack(tmp_path)
    for i in range(4): (downloads / f"file-{i}.txt").write_text("safe", encoding="utf-8")
    calls = 0
    def interrupted():
        nonlocal calls; calls += 1; return calls >= 3
    with pytest.raises(ScanInterruptedError) as exc: scanner.scan_directory(downloads, ScanSource.USB, scan_type=ScanType.USB, interrupt_check=interrupted)
    details = history.get_scan(exc.value.session_id); assert details and details.session.status is ScanSessionStatus.INCOMPLETE


def test_inaccessible_and_oversized_files_are_honestly_reported(tmp_path, monkeypatch):
    *_, scanner, downloads, _, _ = build_stack(tmp_path, max_bytes=8)
    locked = downloads / "locked.bin"; locked.write_bytes(b"1234"); oversized = downloads / "large.bin"; oversized.write_bytes(b"0123456789")
    from app.scanner import inspect_file as real_inspect
    def inspect(path, **kwargs):
        if normalize_path(path) == normalize_path(locked): raise PermissionError("simulated locked file")
        return real_inspect(path, **kwargs)
    monkeypatch.setattr("app.scanner.inspect_file", inspect)
    summary = scanner.scan_directory(downloads)
    by_name = {Path(r.path).name: r for r in summary.results}
    assert by_name["locked.bin"].status is ScanStatus.SKIPPED_LOCKED
    assert by_name["large.bin"].status is ScanStatus.SKIPPED_SIZE
    assert summary.counts["locked_files"] == 1 and summary.counts["skipped_size"] == 1


def test_corrupted_quarantine_object_breaks_verification(tmp_path):
    _, _, incidents, _, quarantine, _, verifier, _, _, scanner, _, _, usb = build_stack(tmp_path)
    seed = usb / "threat.bin"; seed.write_bytes(AUTOGUARD_TEST_CONTENT); scanner.scan_file(seed, ScanSource.USB, scan_type=ScanType.USB)
    incident = incidents.get_active_incidents()[0]; item = next(q for q in quarantine.list_quarantined_items() if q.incident_id == incident.id and q.state is QuarantineState.QUARANTINED)
    Path(item.stored_path).write_bytes(b"corrupted")
    result = verifier.verify_incident(incident.id)
    assert result.status is VerificationStatus.FAILED and result.verified_quarantine_objects < result.quarantined_copies
    assert incidents.get_incident(incident.id).incident.status is IncidentStatus.INVESTIGATING


def test_restore_conflict_never_overwrites_existing_file(tmp_path):
    _, database, incidents, _, quarantine, _, _, _, _, scanner, _, _, usb = build_stack(tmp_path)
    source = usb / "restore-me.bin"; source.write_bytes(AUTOGUARD_TEST_CONTENT); scanner.scan_file(source, ScanSource.USB, scan_type=ScanType.USB)
    incident = incidents.get_active_incidents()[0]; item = next(q for q in quarantine.list_quarantined_items() if q.incident_id == incident.id and q.state is QuarantineState.QUARANTINED)
    source.write_bytes(b"existing user content")
    recovery = RecoveryService(database, quarantine, Detector(SignatureStore()), incidents); result = recovery.restore(item.quarantine_id)
    assert result.status is RecoveryStatus.DESTINATION_CONFLICT and source.read_bytes() == b"existing user content"
    assert result.conflict_options == (RecoveryConflictOption.RESTORE_TO_ANOTHER_FILENAME, RecoveryConflictOption.CHOOSE_ANOTHER_DESTINATION, RecoveryConflictOption.CANCEL)


def test_database_persists_scan_incident_quarantine_and_verification_across_restart(tmp_path):
    config, database, incidents, _, quarantine, _, _, _, history, scanner, _, _, usb = build_stack(tmp_path)
    seed = usb / "persist.bin"; seed.write_bytes(AUTOGUARD_TEST_CONTENT); result = scanner.scan_file(seed, ScanSource.USB, scan_type=ScanType.USB)
    incident_id = incidents.get_active_incidents()[0].id; quarantine_ids = [q.quarantine_id for q in quarantine.list_quarantined_items() if q.incident_id == incident_id]
    reopened_db = Database(config.database_path); reopened_db.initialize(); reopened_incidents = IncidentService(reopened_db); reopened_quarantine = QuarantineService(reopened_db, config.quarantine_dir, reopened_incidents); reopened_history = ScanHistory(reopened_db)
    assert reopened_incidents.get_incident(incident_id) is not None
    assert all(reopened_quarantine.get_item(qid) is not None for qid in quarantine_ids)
    assert reopened_history.get_scan(result.session_id).session.status is ScanSessionStatus.COMPLETED


def test_file_monitor_and_manual_scan_can_use_same_runtime_concurrently(tmp_path):
    *_, scanner, downloads, desktop, _ = build_stack(tmp_path)
    monitored = downloads / "monitored.txt"; manual = desktop / "manual.txt"; monitored.write_text("safe monitor", encoding="utf-8"); manual.write_text("safe manual", encoding="utf-8")
    monitor = FileMonitor(scanner, (downloads,), debounce_seconds=0, stability_period_seconds=0, stability_poll_seconds=.001, stability_timeout_seconds=.1)
    assert monitor.queue_path(monitored)
    with ThreadPoolExecutor(max_workers=2) as pool:
        f1 = pool.submit(monitor.process_pending_once, 0.1); f2 = pool.submit(scanner.scan_file, manual, ScanSource.MANUAL)
        assert f1.result() is True and f2.result().status is ScanStatus.SCANNED
    assert monitor.health().scans_dispatched == 1
    assert len(scanner.history.recent_scans(10)) >= 2


def test_application_runtime_shuts_down_cleanly(tmp_path):
    from app.startup import AutoGuardStartup, StartupSettings
    application = AutoGuardStartup(
        AppConfig(data_dir=tmp_path / "runtime"),
        StartupSettings(startup_quick_scan_enabled=False, scheduler_enabled=False, file_monitor_enabled=False, usb_monitor_enabled=False, monitor_paths=(tmp_path,)),
    )
    services = application.start(); assert services.database.path.exists()
    report = application.shutdown(timeout=.5)
    assert report.scheduler_stopped and report.usb_monitor_stopped and report.file_monitor_stopped and report.errors == ()