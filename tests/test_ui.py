"""Headless UI-foundation tests.

These tests intentionally avoid creating a Tk window. They verify the contract
that keeps long-running work away from the future Windows UI thread.
"""
from __future__ import annotations

import threading
import time
from pathlib import Path
from types import SimpleNamespace

from app.models import ScanResult, ScanStatus, ScanSummary, ScanType
from app.database import Database
from app.detector import Detector
from app.scanner import Scanner
from app.signatures import SignatureStore
from app.threat_trail import ThreatTrail
from app.ui.controller import AutoGuardUIController
from app.ui.messages import UIMessageBus


def wait_for(bus: UIMessageBus, kind: str, timeout: float = 2.0):
    deadline = time.monotonic() + timeout
    seen = []
    while time.monotonic() < deadline:
        seen.extend(bus.drain())
        for message in seen:
            if message.kind == kind:
                return message, seen
        time.sleep(0.01)
    raise AssertionError(f"Timed out waiting for {kind}; saw {[m.kind for m in seen]}")


def test_message_bus_preserves_fifo_order():
    bus = UIMessageBus()
    bus.publish("first", value=1)
    bus.publish("second", value=2)
    assert [message.kind for message in bus.drain()] == ["first", "second"]
    assert bus.pending() == 0


def test_message_bus_validates_kind_and_limit():
    bus = UIMessageBus()
    try:
        bus.publish("   ")
    except ValueError:
        pass
    else:
        raise AssertionError("empty message kind should be rejected")
    try:
        bus.drain(0)
    except ValueError:
        pass
    else:
        raise AssertionError("nonpositive drain limit should be rejected")


class FakeScanner:
    def __init__(self):self.thread_id=None
    def count_scan_entries(self,*args,**kwargs):raise AssertionError("UI must not pre-count scan entries")
    def scan(self,path,source,*,scan_type,interrupt_check=None,on_result=None,on_discovered=None):
        self.thread_id=threading.get_ident();result=ScanResult(str(path),ScanStatus.SCANNED,"No threat detected.")
        if on_discovered:on_discovered(str(path),"file")
        if on_result:on_result(result)
        time.sleep(0.04);return ScanSummary((result,),"session-1")


def fake_services(scanner):
    scheduler = SimpleNamespace(
        quick_paths=(Path("quick"),), full_paths=(Path("full"),),
        settings=SimpleNamespace(quick_interval_hours=24.0, full_interval_days=7.0),
    )
    return SimpleNamespace(scanner=scanner, scheduler=scheduler)


def test_controller_dispatches_manual_scan_off_calling_thread():
    bus = UIMessageBus()
    scanner = FakeScanner()
    controller = AutoGuardUIController(fake_services(scanner), bus)
    calling_thread = threading.get_ident()
    started = time.monotonic()
    controller.start_scan("example.txt", scan_type=ScanType.MANUAL)
    elapsed = time.monotonic() - started
    message, seen = wait_for(bus, "scan_completed")
    try:
        assert elapsed < 0.03
        assert scanner.thread_id is not None and scanner.thread_id != calling_thread
        discovered = next(item for item in seen if item.kind == "scan_discovered")
        assert discovered.payload["discovered"] == 1 and discovered.payload["processed"] == 0
        progress = next(item for item in seen if item.kind == "scan_result")
        assert progress.payload["processed"] == 1
        assert progress.payload["discovered"] == 1
        assert progress.payload["progress"] == 1.0
        assert message.payload["result"].session_id == "session-1"
    finally:
        controller.shutdown()


def test_controller_emits_task_failure_without_raising_on_ui_thread():
    class FailingScanner(FakeScanner):
        def scan(self, *args, **kwargs):
            raise PermissionError("simulated locked target")
    bus = UIMessageBus()
    controller = AutoGuardUIController(fake_services(FailingScanner()), bus)
    controller.start_scan("locked.bin")
    failure, _ = wait_for(bus, "task_failed")
    try:
        assert "PermissionError" in failure.payload["error"]
        assert "simulated locked target" in failure.payload["error"]
    finally:
        controller.shutdown()


def test_scan_progress_callback_failure_does_not_change_scanner_result(tmp_path):
    database = Database(tmp_path / "autoguard.db")
    database.initialize()
    scanner = Scanner(Detector(SignatureStore()), ThreatTrail(database))
    target = tmp_path / "safe.txt"
    target.write_text("harmless", encoding="utf-8")
    result = scanner.scan_file(
        target,
        on_result=lambda _: (_ for _ in ()).throw(RuntimeError("UI gone")),
    )
    assert result.status is ScanStatus.SCANNED


def test_scanner_single_pass_discovery_matches_emitted_results(tmp_path):
    database=Database(tmp_path/"autoguard.db");database.initialize();scanner=Scanner(Detector(SignatureStore()),ThreatTrail(database));folder=tmp_path/"folder";folder.mkdir();(folder/"one.txt").write_text("one",encoding="utf-8");nested=folder/"nested";nested.mkdir();(nested/"two.txt").write_text("two",encoding="utf-8")
    discovered=[];emitted=[];summary=scanner.scan(folder,on_discovered=lambda path,kind:discovered.append((path,kind)),on_result=emitted.append)
    assert len(discovered)==2==len(emitted)==len(summary.results)
    assert {path for path,_ in discovered}=={result.path for result in summary.results}

def test_controller_never_runs_metadata_precount_before_scan():
    bus=UIMessageBus();scanner=FakeScanner();controller=AutoGuardUIController(fake_services(scanner),bus);controller.start_scan("instant.txt");_,seen=wait_for(bus,"scan_completed")
    try:
        kinds=[m.kind for m in seen];assert "scan_counting" not in kinds and "scan_total" not in kinds;assert kinds.index("scan_started")<kinds.index("scan_discovered")<kinds.index("scan_result")<kinds.index("scan_completed")
    finally:controller.shutdown()



def _ui_module_ast(relative_path: str):
    import ast

    project_root = Path(__file__).resolve().parents[1]
    return ast.parse((project_root / relative_path).read_text(encoding="utf-8"))


def _literal_assignment(tree, name: str):
    import ast

    for node in tree.body:
        if isinstance(node, ast.Assign):
            if any(isinstance(target, ast.Name) and target.id == name for target in node.targets):
                return ast.literal_eval(node.value)
    raise AssertionError(f"Assignment {name!r} not found")


def _class_attribute_literal(tree, class_name: str, attribute: str):
    import ast

    for node in tree.body:
        if isinstance(node, ast.ClassDef) and node.name == class_name:
            for child in node.body:
                if isinstance(child, ast.Assign):
                    if any(isinstance(target, ast.Name) and target.id == attribute for target in child.targets):
                        return ast.literal_eval(child.value)
    raise AssertionError(f"{class_name}.{attribute} not found")


def test_ux_refresh_phase1_exposes_exactly_six_top_level_pages():
    sidebar = _ui_module_ast("app/ui/sidebar.py")
    nav_items = _literal_assignment(sidebar, "NAV_ITEMS")

    assert nav_items == (
        ("home", "Home"),
        ("scan", "Scan"),
        ("threats", "Threats"),
        ("quarantine", "Quarantine"),
        ("activity", "Activity"),
        ("settings", "Settings"),
    )
    visible_keys = {key for key, _ in nav_items}
    assert {"incidents", "threat_trail", "history"}.isdisjoint(visible_keys)


def test_ux_refresh_phase1_page_registry_matches_navigation_without_legacy_pages():
    import ast

    tree = _ui_module_ast("app/ui/main_window.py")
    default_page = _literal_assignment(tree, "DEFAULT_PAGE")
    page_classes = None
    for node in tree.body:
        if isinstance(node, ast.Assign) and any(
            isinstance(target, ast.Name) and target.id == "PAGE_CLASSES"
            for target in node.targets
        ):
            page_classes = {
                ast.literal_eval(key): value.id
                for key, value in zip(node.value.keys, node.value.values)
            }
            break
    assert page_classes is not None

    assert default_page == "home"
    assert tuple(page_classes) == (
        "home",
        "scan",
        "threats",
        "quarantine",
        "activity",
        "settings",
    )
    assert page_classes["home"] == "DashboardPage"
    assert page_classes["threats"] == "ThreatsPage"
    assert page_classes["activity"] == "ActivityPage"
    assert {"incidents", "threat_trail", "history"}.isdisjoint(page_classes)

    dashboard = _ui_module_ast("app/ui/dashboard.py")
    threats = _ui_module_ast("app/ui/threats_page.py")
    activity = _ui_module_ast("app/ui/activity_page.py")
    assert _class_attribute_literal(dashboard, "DashboardPage", "title") == "Home"
    assert _class_attribute_literal(threats, "ThreatsPage", "title") == "Threats"
    assert _class_attribute_literal(activity, "ActivityPage", "title") == "Activity"



def _home_services(*, file_running=True, usb_running=True, scheduler_running=True,
                   quick_running=False, full_running=False, incidents=(), sessions=(), details=None,
                   quarantined=0):
    def health(running):
        return SimpleNamespace(
            running=running,
            status=SimpleNamespace(value="RUNNING" if running else "STOPPED"),
        )

    class History:
        def recent_scans(self, limit):
            return list(sessions)[:limit]

        def get_scan(self, session_id):
            return (details or {}).get(session_id)

    scheduler_health = SimpleNamespace(
        running=scheduler_running,
        quick_scan_running=quick_running,
        full_scan_running=full_running,
    )
    scheduler = SimpleNamespace(
        quick_paths=(),
        full_paths=(),
        settings=SimpleNamespace(quick_interval_hours=24.0, full_interval_days=7.0),
        health=lambda: scheduler_health,
    )
    quarantine_items = [
        SimpleNamespace(state=SimpleNamespace(value="QUARANTINED"))
        for _ in range(quarantined)
    ]
    return SimpleNamespace(
        file_monitor=SimpleNamespace(health=lambda: health(file_running)),
        usb_monitor=SimpleNamespace(health=lambda: health(usb_running)),
        scheduler=scheduler,
        quarantine=SimpleNamespace(list_quarantined_items=lambda: quarantine_items),
        incidents=SimpleNamespace(get_active_incidents=lambda: list(incidents)),
        scanner=SimpleNamespace(history=History()),
    )


def test_ux_refresh_phase2_home_uses_only_four_user_facing_protection_states():
    from app.incidents import IncidentStatus

    controller = AutoGuardUIController(_home_services(), UIMessageBus())
    try:
        snapshot = controller._dashboard_snapshot()
        assert snapshot["protection_state"] == {
            "key": "protected",
            "title": "Protected",
            "message": "Everything is working normally.",
        }

        controller.services = _home_services(quick_running=True)
        assert controller._dashboard_snapshot()["protection_state"]["title"] == "Scanning"

        controller.services = _home_services(
            incidents=(SimpleNamespace(status=IncidentStatus.OPEN),)
        )
        attention = controller._dashboard_snapshot()["protection_state"]
        assert attention["title"] == "Attention needed"
        assert attention["message"] == "AutoGuard found something that needs review."

        controller.services = _home_services(file_running=False)
        issue = controller._dashboard_snapshot()["protection_state"]
        assert issue["title"] == "Protection issue"
        assert issue["message"] == "One or more protection services are not running."
    finally:
        controller.shutdown()


def test_ux_refresh_phase2_contained_incident_does_not_force_attention_state():
    from app.incidents import IncidentStatus

    controller = AutoGuardUIController(
        _home_services(incidents=(SimpleNamespace(status=IncidentStatus.CONTAINED),)),
        UIMessageBus(),
    )
    try:
        snapshot = controller._dashboard_snapshot()
        assert snapshot["protection_state"]["title"] == "Protected"
        assert snapshot["threats_needing_review"] == 0
    finally:
        controller.shutdown()


def test_ux_refresh_phase2_home_navigation_and_quick_scan_are_presentation_wired():
    import ast

    dashboard_path = Path(__file__).resolve().parents[1] / "app/ui/dashboard.py"
    source = dashboard_path.read_text(encoding="utf-8")
    tree = ast.parse(source)
    strings = {node.value for node in ast.walk(tree) if isinstance(node, ast.Constant) and isinstance(node.value, str)}

    assert {"Last Scan", "Threats", "Quarantine", "Protection", "Recent Activity", "Run Quick Scan", "View activity"} <= strings
    assert "start_quick_scan" in source
    assert 'navigate_to("activity")' in source
    for forbidden in ("SHA-256", "incident ID", "session ID", "worker name"):
        assert forbidden not in source


def test_ux_refresh_phase2_view_activity_request_uses_message_bus():
    bus = UIMessageBus()
    controller = AutoGuardUIController(_home_services(), bus)
    try:
        controller.navigate_to("activity")
        messages = bus.drain()
        assert len(messages) == 1
        assert messages[0].kind == "navigate"
        assert messages[0].payload["page"] == "activity"
    finally:
        controller.shutdown()


def test_ux_refresh_phase3_idle_scan_page_uses_simple_user_facing_choices():
    source = (Path(__file__).resolve().parents[1] / "app/ui/scan_page.py").read_text(encoding="utf-8")

    assert 'text="Scan your PC"' in source
    assert 'title="Quick Scan"' in source
    assert 'title="Full Scan"' in source
    assert 'title="Custom Scan"' in source
    assert 'recommended=True' in source
    assert "Downloads  •  Desktop  •  Documents" in source
    assert '"Start Quick Scan", self.controller.start_quick_scan' in source
    assert '"Start Full Scan", self.controller.start_full_scan' in source
    assert '"Choose File", self._choose_file' in source
    assert '"Choose Folder", self._choose_folder' in source
    assert "Manual Scan" not in source


def test_ux_refresh_phase3_custom_scan_delegates_to_controller_without_scanner_logic():
    import ast

    source = (Path(__file__).resolve().parents[1] / "app/ui/scan_page.py").read_text(encoding="utf-8")
    tree = ast.parse(source)

    controller_calls = [
        node for node in ast.walk(tree)
        if isinstance(node, ast.Attribute)
        and isinstance(node.value, ast.Attribute)
        and isinstance(node.value.value, ast.Name)
        and node.value.value.id == "self"
        and node.value.attr == "controller"
    ]
    names = {node.attr for node in controller_calls}
    assert {"start_scan", "start_quick_scan", "start_full_scan"} <= names

    # UI must not own antivirus work.
    for forbidden in ("hashlib", "sha256(", "Detector(", "inspect_file(", "ThreatTrail("):
        assert forbidden not in source


def test_ux_refresh_phase3_manual_internal_label_is_presented_as_custom_scan():
    import re

    source = (
        Path(__file__).resolve().parents[1]
        / "app/ui/components/scan_progress.py"
    ).read_text(encoding="utf-8")

    assert re.search(r'["\']manual["\']\s*:\s*["\']Custom Scan["\']', source)
    assert not re.search(r'["\']manual["\']\s*:\s*["\']Manual Scan["\']', source)



def test_ux_refresh_phase4_active_scan_is_focused_and_has_no_fake_pause():
    source = (
        Path(__file__).resolve().parents[1]
        / "app/ui/components/active_scan.py"
    ).read_text(encoding="utf-8")

    for required in (
        "Files checked",
        "Threats found",
        "Currently checking",
        "More details",
        "Discovered",
        "Processed",
        "Skipped",
        "Errors",
        "Suspicious",
        "Dangerous",
        "Stop Scan",
    ):
        assert required in source
    assert "Pause" not in source
    assert "hashlib" not in source
    assert "inspect_file(" not in source
    assert "Detector(" not in source


def test_ux_refresh_phase4_scan_page_uses_active_component_and_stop_controller():
    source = (
        Path(__file__).resolve().parents[1] / "app/ui/scan_page.py"
    ).read_text(encoding="utf-8")

    assert "ActiveScanPanel" in source
    assert "on_stop=self.controller.stop_scan" in source
    assert 'message.kind == "scan_stop_requested"' in source
    assert 'message.kind == "scan_stopped"' in source
    assert "Live results" not in source
    assert "CTkTextbox" not in source


def test_ux_refresh_phase4_stop_scan_uses_cooperative_interrupt_without_blocking_ui():
    from app.scanner import ScanInterruptedError

    class InterruptibleScanner(FakeScanner):
        def __init__(self):
            super().__init__()
            self.worker_started = threading.Event()
            self.received_interrupt_check = False

        def scan(
            self, path, source, *, scan_type, interrupt_check=None,
            on_result=None, on_discovered=None,
        ):
            self.thread_id = threading.get_ident()
            self.received_interrupt_check = callable(interrupt_check)
            self.worker_started.set()
            if on_discovered:
                on_discovered(str(path), "file")
            deadline = time.monotonic() + 2.0
            while time.monotonic() < deadline:
                if interrupt_check is not None and interrupt_check():
                    raise ScanInterruptedError("Scan interrupted before completion.", "session-stop")
                time.sleep(0.005)
            raise AssertionError("Stop Scan did not reach the scanner interrupt hook")

    bus = UIMessageBus()
    scanner = InterruptibleScanner()
    controller = AutoGuardUIController(fake_services(scanner), bus)
    calling_thread = threading.get_ident()
    try:
        controller.start_scan("large-folder")
        assert scanner.worker_started.wait(1.0)
        started = time.monotonic()
        assert controller.stop_scan() is True
        assert time.monotonic() - started < 0.05
        stopped, seen = wait_for(bus, "scan_stopped")
        assert scanner.received_interrupt_check
        assert scanner.thread_id != calling_thread
        assert stopped.payload["session_id"] == "session-stop"
        assert not any(message.kind == "task_failed" for message in seen)
        assert not any(message.kind == "scan_completed" for message in seen)
    finally:
        controller.shutdown()


def test_ux_refresh_phase4_stop_scan_is_noop_when_no_ui_scan_is_running():
    controller = AutoGuardUIController(fake_services(FakeScanner()), UIMessageBus())
    try:
        assert controller.stop_scan() is False
    finally:
        controller.shutdown()


def _phase5_result_services(*, session, results=(), incident=None, incident_events=(), verification=None):
    class History:
        def __init__(self):
            self.thread_id = None

        def get_scan(self, session_id):
            self.thread_id = threading.get_ident()
            if session_id != session.id:
                return None
            return SimpleNamespace(session=session, results=tuple(results))

    history = History()

    class Incidents:
        def get_active_incidents(self):
            return [] if incident is None else [incident]

        def get_incident(self, incident_id):
            if incident is None or incident_id != incident.id:
                return None
            return SimpleNamespace(incident=incident, files=(), events=tuple(incident_events))

    class Verifier:
        def list_verifications(self, incident_id):
            if incident is None or incident_id != incident.id or verification is None:
                return []
            return [verification]

    services = SimpleNamespace(
        scanner=SimpleNamespace(history=history),
        incidents=Incidents(),
        cleanup_verifier=Verifier(),
    )
    return services, history


def _phase5_session(*, suspicious=0, dangerous=0, scanned=8, skipped=0, errors=0):
    from datetime import datetime, timedelta, timezone
    from app.models import ScanSessionStatus

    started = datetime(2026, 9, 16, 12, 0, 0, tzinfo=timezone.utc)
    counters = {
        "scanned_files": scanned,
        "dangerous_detections": dangerous,
        "suspicious_detections": suspicious,
        "skipped_size": skipped,
        "locked_files": 0,
        "unsupported_files": 0,
        "errors": errors,
        "file_errors": errors,
    }
    return SimpleNamespace(
        id="phase5-session",
        scan_type=ScanType.QUICK,
        started_at=started,
        finished_at=started + timedelta(seconds=12),
        status=ScanSessionStatus.COMPLETED,
        counters=counters,
    )


def test_ux_refresh_phase5_clean_result_uses_honest_user_facing_wording():
    session = _phase5_session(scanned=42, skipped=3)
    services, _ = _phase5_result_services(session=session)
    controller = AutoGuardUIController(services, UIMessageBus())
    try:
        result = controller._scan_result_snapshot((SimpleNamespace(session_id=session.id),))
    finally:
        controller.shutdown()

    assert result["kind"] == "clean"
    assert result["title"] == "Scan complete"
    assert result["message"] == "No threats detected in the files successfully scanned."
    assert result["scan_type"] == "Quick Scan"
    assert result["duration"] == "12 sec"
    assert result["files_checked"] == 42
    assert result["threats_found"] == 0
    assert result["skipped_files"] == 3
    assert "completely safe" not in result["message"].lower()


def test_ux_refresh_phase5_suspicious_result_does_not_call_it_a_confirmed_threat():
    session = _phase5_session(suspicious=2, dangerous=0)
    services, _ = _phase5_result_services(session=session)
    controller = AutoGuardUIController(services, UIMessageBus())
    try:
        result = controller._scan_result_snapshot((SimpleNamespace(session_id=session.id),))
    finally:
        controller.shutdown()

    assert result["kind"] == "suspicious"
    assert result["title"] == "Review recommended"
    assert "2 suspicious files" in result["message"]
    assert "no confirmed threat was detected" in result["message"].lower()
    assert "LOW_CONFIDENCE" not in str(result)
    assert "HIGH_CONFIDENCE" not in str(result)


def test_ux_refresh_phase5_confirmed_result_claims_handled_only_with_verified_containment():
    from datetime import timedelta
    from app.cleanup_verifier import VerificationStatus
    from app.incidents import IncidentEventType, IncidentStatus
    from app.models import DetectionStatus

    session = _phase5_session(dangerous=1)
    sha256 = "a" * 64
    stored = SimpleNamespace(detection_status=DetectionStatus.HIGH_CONFIDENCE, sha256=sha256)
    incident = SimpleNamespace(id="internal-incident", sha256=sha256, status=IncidentStatus.CONTAINED)
    event = SimpleNamespace(
        event_type=IncidentEventType.MATCHING_COPY_FOUND,
        occurred_at=session.started_at + timedelta(seconds=4),
    )
    verification = SimpleNamespace(status=VerificationStatus.VERIFIED)
    services, _ = _phase5_result_services(
        session=session,
        results=(stored,),
        incident=incident,
        incident_events=(event, event),
        verification=verification,
    )
    controller = AutoGuardUIController(services, UIMessageBus())
    try:
        result = controller._scan_result_snapshot((SimpleNamespace(session_id=session.id),))
    finally:
        controller.shutdown()

    assert result["kind"] == "confirmed_threat"
    assert result["title"] == "Threat handled"
    assert result["containment_verified"] is True
    assert result["threats_contained"] == 1
    assert result["matching_copies_found"] == 2
    assert result["cleanup_status"] == "Verified"
    assert "internal-incident" not in str(result)


def test_ux_refresh_phase5_confirmed_result_does_not_overclaim_failed_cleanup():
    from app.cleanup_verifier import VerificationStatus
    from app.incidents import IncidentStatus
    from app.models import DetectionStatus

    session = _phase5_session(dangerous=1)
    sha256 = "b" * 64
    stored = SimpleNamespace(detection_status=DetectionStatus.HIGH_CONFIDENCE, sha256=sha256)
    incident = SimpleNamespace(id="internal-incident", sha256=sha256, status=IncidentStatus.OPEN)
    verification = SimpleNamespace(status=VerificationStatus.FAILED)
    services, _ = _phase5_result_services(
        session=session,
        results=(stored,),
        incident=incident,
        verification=verification,
    )
    controller = AutoGuardUIController(services, UIMessageBus())
    try:
        result = controller._scan_result_snapshot((SimpleNamespace(session_id=session.id),))
    finally:
        controller.shutdown()

    assert result["title"] == "Confirmed threat detected"
    assert result["containment_verified"] is False
    assert result["threats_contained"] == 0
    assert result["cleanup_status"] == "Failed"
    assert "Threat handled" not in result["title"]


def test_ux_refresh_phase5_result_preparation_runs_off_the_calling_thread():
    session = _phase5_session(scanned=1)
    services, history = _phase5_result_services(session=session)
    bus = UIMessageBus()
    controller = AutoGuardUIController(services, bus)
    calling_thread = threading.get_ident()
    try:
        controller.prepare_scan_result(SimpleNamespace(session_id=session.id))
        message, _ = wait_for(bus, "scan_result_ready")
        assert history.thread_id is not None and history.thread_id != calling_thread
        assert message.payload["result"]["kind"] == "clean"
    finally:
        controller.shutdown()


def test_ux_refresh_phase5_scan_result_component_and_page_contract():
    component = (
        Path(__file__).resolve().parents[1] / "app/ui/components/scan_result.py"
    ).read_text(encoding="utf-8")
    page = (
        Path(__file__).resolve().parents[1] / "app/ui/scan_page.py"
    ).read_text(encoding="utf-8")

    assert "class ScanResultPanel" in component
    assert "No threats detected in the files successfully scanned." in component
    assert "Scan complete" in component
    assert "Review files" in component
    assert "View threat" in component
    for forbidden in ("LOW_CONFIDENCE", "HIGH_CONFIDENCE", "incident_id", "session_id", "sha256"):
        assert forbidden not in component

    assert "ScanResultPanel" in page
    assert "prepare_scan_result" in page
    assert 'message.kind == "scan_result_ready"' in page
    assert 'navigate_to("activity")' in page
    assert 'navigate_to("threats")' in page


def _phase6_incident(status, *, name="sample.bin", matching_paths=(), location_count=1):
    from datetime import datetime, timezone
    from app.incidents import IncidentEventType

    when = datetime(2026, 9, 17, 0, 30, tzinfo=timezone.utc)
    incident = SimpleNamespace(
        id=f"ref-{status.value.lower()}",
        status=status,
        first_observed_path=rf"c:\\users\\fonti\\downloads\\{name}",
        last_observed_at=when,
    )
    files = tuple(
        SimpleNamespace(path=rf"c:\\test\\location-{index}\\{name}")
        for index in range(location_count)
    )
    events = tuple(
        SimpleNamespace(event_type=IncidentEventType.MATCHING_COPY_FOUND, path=path)
        for path in matching_paths
    )
    return incident, SimpleNamespace(incident=incident, files=files, events=events)


def test_ux_refresh_phase6_threat_read_model_translates_statuses_and_sections():
    from app.incidents import IncidentStatus

    configured = [
        _phase6_incident(IncidentStatus.OPEN),
        _phase6_incident(IncidentStatus.INVESTIGATING),
        _phase6_incident(IncidentStatus.CONTAINED),
        _phase6_incident(IncidentStatus.REAPPEARED),
        _phase6_incident(IncidentStatus.RESTORED),
        _phase6_incident(IncidentStatus.RESOLVED),
    ]
    details_by_id = {incident.id: details for incident, details in configured}

    class Incidents:
        def list_incidents(self, limit):
            assert limit == 200
            return [item[0] for item in configured]

        def get_incident(self, threat_ref):
            return details_by_id.get(threat_ref)

    controller = AutoGuardUIController(SimpleNamespace(incidents=Incidents()), UIMessageBus())
    try:
        rows = controller._threat_rows()
    finally:
        controller.shutdown()

    assert [(row["status"], row["section"]) for row in rows] == [
        ("Needs attention", "Needs attention"),
        ("Being reviewed", "Needs attention"),
        ("Contained", "Contained"),
        ("Detected again", "Needs attention"),
        ("Restored", "Needs attention"),
        ("Resolved", "Resolved"),
    ]
    rendered = str(rows)
    for raw in ("OPEN", "INVESTIGATING", "CONTAINED", "REAPPEARED", "RESTORED", "RESOLVED"):
        assert raw not in rendered


def test_ux_refresh_phase6_threat_read_model_uses_location_and_matching_copy_evidence():
    from app.incidents import IncidentStatus

    incident, details = _phase6_incident(
        IncidentStatus.CONTAINED,
        name="test-threat.bin",
        location_count=3,
        matching_paths=(r"c:\\one.bin", r"c:\\two.bin", r"c:\\two.bin"),
    )

    class Incidents:
        def list_incidents(self, limit):
            return [incident]

        def get_incident(self, threat_ref):
            return details

    controller = AutoGuardUIController(SimpleNamespace(incidents=Incidents()), UIMessageBus())
    try:
        row = controller._threat_rows()[0]
    finally:
        controller.shutdown()

    assert row["name"] == "test-threat.bin"
    assert row["location"] == "3 observed locations"
    assert row["matching_copies"] == 2
    assert row["action"] == "View details"
    assert "ref-contained" not in str({k: v for k, v in row.items() if k != "threat_ref"})


def test_ux_refresh_phase6_open_threat_details_prepares_future_navigation():
    bus = UIMessageBus()
    controller = AutoGuardUIController(SimpleNamespace(), bus)
    try:
        controller.open_threat_details("internal-reference")
        messages = bus.drain()
    finally:
        controller.shutdown()

    assert controller.selected_threat_ref == "internal-reference"
    assert [message.kind for message in messages] == ["threat_details_requested", "navigate"]
    assert messages[-1].payload == {"page": "threats"}


def test_ux_refresh_phase6_threats_page_is_user_facing_and_service_driven():
    source = (
        Path(__file__).resolve().parents[1] / "app/ui/threats_page.py"
    ).read_text(encoding="utf-8")
    controller_source = (
        Path(__file__).resolve().parents[1] / "app/ui/controller.py"
    ).read_text(encoding="utf-8")

    assert 'title = "Threats"' in source
    assert "Needs attention" in source
    assert "Contained" in source
    assert "Resolved" in source
    assert "No active threats" in source
    assert "open_threat_details" in source
    for forbidden in ("sha256", "incident_id", "event_type.value", "detection_rule", "SELECT * FROM threat_incidents"):
        assert forbidden not in source

    assert "def load_threats" in controller_source
    assert "self.services.incidents.list_incidents" in controller_source
    assert "self.services.incidents.get_incident" in controller_source


def _phase7_services(*, status=None, verification_status=None):
    from datetime import datetime, timezone
    from app.cleanup_verifier import VerificationStatus
    from app.incidents import IncidentEventType, IncidentStatus
    from app.models import DetectionStatus, SignatureKind
    from app.quarantine import QuarantineState

    status = status or IncidentStatus.CONTAINED
    when = datetime(2026, 9, 17, 1, 10, tzinfo=timezone.utc)
    incident = SimpleNamespace(
        id="internal-phase7-incident",
        sha256="a" * 64,
        status=status,
        first_observed_path=r"c:\users\fonti\downloads\test-threat.bin",
        last_observed_at=when,
        reappearance_count=1 if status is IncidentStatus.REAPPEARED else 0,
    )
    file_item = SimpleNamespace(
        path=incident.first_observed_path,
        first_detection_reason="Exact test-signature evidence was recorded.",
    )
    events = (
        SimpleNamespace(
            event_type=IncidentEventType.MATCHING_CLEANUP_STARTED,
            path=incident.first_observed_path,
        ),
        SimpleNamespace(
            event_type=IncidentEventType.MATCHING_COPY_FOUND,
            path=r"c:\users\fonti\desktop\copy.bin",
        ),
        SimpleNamespace(
            event_type=IncidentEventType.MATCHING_COPY_QUARANTINED,
            path=r"c:\users\fonti\desktop\copy.bin",
        ),
    )
    details = SimpleNamespace(incident=incident, files=(file_item,), events=events)
    detection = SimpleNamespace(
        id=901,
        session_id="internal-scan-session",
        path=incident.first_observed_path,
        sha256=incident.sha256,
        detection_status=DetectionStatus.HIGH_CONFIDENCE,
        detection_confidence=1.0,
        detection_reason="Exact match to the harmless AutoGuard test signature; this is a test detection.",
        reason="Exact match to the harmless AutoGuard test signature; this is a test detection.",
        rule_name="autoguard_test_signature",
        matched_signature_name="AutoGuard.Harmless.Test",
        matched_signature_kind=SignatureKind.AUTOGUARD_TEST,
    )
    quarantine = SimpleNamespace(
        quarantine_id="internal-quarantine-id",
        incident_id=incident.id,
        sha256=incident.sha256,
        state=QuarantineState.QUARANTINED,
        original_path=incident.first_observed_path,
    )
    verification = None
    if verification_status is not False:
        verification = SimpleNamespace(
            status=verification_status or VerificationStatus.VERIFIED,
            verified_quarantine_objects=1,
            quarantined_copies=1,
            remaining_matching_copies=0,
            inaccessible_locations=0,
            verification_errors=0,
        )

    class Incidents:
        def get_incident(self, threat_ref):
            return details if threat_ref == incident.id else None

    class History:
        def latest_detection_for_sha256(self, sha256):
            assert sha256 == incident.sha256
            return detection

    class Quarantine:
        def list_quarantined_items(self):
            return [quarantine]

    class Cleanup:
        def list_verifications(self, threat_ref):
            return [verification] if verification is not None else []

    class Recovery:
        def list_attempts(self, quarantine_id):
            return []

    services = SimpleNamespace(
        incidents=Incidents(),
        scanner=SimpleNamespace(history=History()),
        quarantine=Quarantine(),
        cleanup_verifier=Cleanup(),
        recovery=Recovery(),
    )
    return services, incident


def test_ux_refresh_phase7_threat_details_uses_persisted_evidence_and_hides_ids_from_primary_view():
    services, incident = _phase7_services()
    controller = AutoGuardUIController(services, UIMessageBus())
    try:
        result = controller._threat_details_snapshot(incident.id)
    finally:
        controller.shutdown()

    assert result["name"] == "test-threat.bin"
    assert result["status"] == "Contained"
    labels = [item["label"] for item in result["what_happened"]]
    assert labels == ["Detection", "Action taken", "Matching copies", "Cleanup verification"]
    assert "AutoGuard.Harmless.Test" in result["what_happened"][0]["text"]
    assert "1 related file" in result["what_happened"][1]["text"]
    assert "1 additional exact matching copy" in result["what_happened"][2]["text"]
    assert "Cleanup verification succeeded" in result["what_happened"][3]["text"]
    assert "do not prove where" in result["caution"]

    primary = {key: value for key, value in result.items() if key != "technical_details"}
    rendered_primary = str(primary)
    assert incident.id not in rendered_primary
    assert incident.sha256 not in rendered_primary
    assert "HIGH_CONFIDENCE" not in rendered_primary
    assert "autoguard_test_signature" not in rendered_primary
    assert "internal-scan-session" not in rendered_primary


def test_ux_refresh_phase7_technical_details_contains_advanced_evidence_only():
    services, incident = _phase7_services()
    controller = AutoGuardUIController(services, UIMessageBus())
    try:
        result = controller._threat_details_snapshot(incident.id)
    finally:
        controller.shutdown()

    technical = dict(result["technical_details"])
    assert technical["SHA-256"] == incident.sha256
    assert technical["Incident ID"] == incident.id
    assert technical["Detection rule"] == "autoguard_test_signature"
    assert technical["Scan session"] == "internal-scan-session"
    assert technical["Raw incident status"] == "CONTAINED"
    assert technical["Cleanup verification"] == "Verified"


def test_ux_refresh_phase7_details_does_not_claim_cleanup_success_without_verification():
    from app.incidents import IncidentStatus

    services, incident = _phase7_services(
        status=IncidentStatus.OPEN,
        verification_status=False,
    )
    controller = AutoGuardUIController(services, UIMessageBus())
    try:
        result = controller._threat_details_snapshot(incident.id)
    finally:
        controller.shutdown()

    cleanup = next(
        item["text"] for item in result["what_happened"]
        if item["label"] == "Cleanup verification"
    )
    assert result["status"] == "Needs attention"
    assert cleanup == "Cleanup verification has not been recorded yet."
    assert "succeeded" not in cleanup.lower()


def test_ux_refresh_phase7_component_keeps_technical_details_collapsed_by_default():
    component = (
        Path(__file__).resolve().parents[1] / "app/ui/threat_details_page.py"
    ).read_text(encoding="utf-8")
    threats_page = (
        Path(__file__).resolve().parents[1] / "app/ui/threats_page.py"
    ).read_text(encoding="utf-8")
    controller_source = (
        Path(__file__).resolve().parents[1] / "app/ui/controller.py"
    ).read_text(encoding="utf-8")

    assert "class ThreatDetailsView" in component
    assert 'text="What happened?"' in component
    assert 'text="Technical details  ▾"' in component
    assert "grid_remove()" in component
    assert "ThreatDetailsView" in threats_page
    assert "load_threat_details" in threats_page
    assert "build_explanation" in controller_source
    assert "latest_detection_for_sha256" in controller_source

def _phase8_services():
    from datetime import datetime, timedelta, timezone
    from app.cleanup_verifier import VerificationStatus
    from app.incidents import IncidentEventType, IncidentStatus
    from app.models import DetectionStatus, SignatureKind
    from app.quarantine import QuarantineState

    base = datetime(2026, 9, 17, 0, 0, tzinfo=timezone.utc)
    first_path = r"c:\users\fonti\downloads\test-threat.bin"
    copy_path = r"c:\users\fonti\desktop\copy.bin"
    usb_path = r"e:\sample.bin"
    incident = SimpleNamespace(
        id="internal-phase8-incident",
        sha256="b" * 64,
        status=IncidentStatus.CONTAINED,
        first_observed_path=first_path,
        created_at=base,
        updated_at=base + timedelta(minutes=8),
        last_observed_at=base + timedelta(minutes=8),
        reappearance_count=1,
    )
    files = (
        SimpleNamespace(
            path=first_path,
            first_seen=base,
            last_seen=base + timedelta(minutes=1),
            first_detection_reason="Stored signature evidence",
        ),
        SimpleNamespace(
            path=copy_path,
            first_seen=base + timedelta(minutes=2),
            last_seen=base + timedelta(minutes=3),
            first_detection_reason="Exact matching content",
        ),
    )
    events = (
        SimpleNamespace(
            id=1,
            event_type=IncidentEventType.FIRST_OBSERVED,
            occurred_at=base,
            path=first_path,
            new_status=None,
            reappearance_count=None,
        ),
        SimpleNamespace(
            id=2,
            event_type=IncidentEventType.QUARANTINE_SUCCEEDED,
            occurred_at=base + timedelta(minutes=1),
            path=first_path,
            new_status=None,
            reappearance_count=None,
        ),
        SimpleNamespace(
            id=3,
            event_type=IncidentEventType.MATCHING_COPY_FOUND,
            occurred_at=base + timedelta(minutes=2),
            path=copy_path,
            new_status=None,
            reappearance_count=None,
        ),
        SimpleNamespace(
            id=4,
            event_type=IncidentEventType.MATCHING_COPY_QUARANTINED,
            occurred_at=base + timedelta(minutes=3),
            path=copy_path,
            new_status=None,
            reappearance_count=None,
        ),
        SimpleNamespace(
            id=5,
            event_type=IncidentEventType.CLEANUP_VERIFIED,
            occurred_at=base + timedelta(minutes=4),
            path=first_path,
            new_status=None,
            reappearance_count=None,
        ),
        SimpleNamespace(
            id=6,
            event_type=IncidentEventType.REAPPEARANCE,
            occurred_at=base + timedelta(minutes=5),
            path=usb_path,
            new_status=None,
            reappearance_count=1,
        ),
        SimpleNamespace(
            id=7,
            event_type=IncidentEventType.RECOVERY_SUCCEEDED,
            occurred_at=base + timedelta(minutes=6),
            path=copy_path,
            new_status=None,
            reappearance_count=None,
        ),
        SimpleNamespace(
            id=8,
            event_type=IncidentEventType.STATUS_CHANGED,
            occurred_at=base + timedelta(minutes=7),
            path=None,
            new_status=IncidentStatus.RESOLVED,
            reappearance_count=None,
        ),
    )
    details = SimpleNamespace(incident=incident, files=files, events=events)
    detection = SimpleNamespace(
        id=902,
        session_id="internal-phase8-scan",
        path=first_path,
        sha256=incident.sha256,
        detection_status=DetectionStatus.HIGH_CONFIDENCE,
        detection_confidence=1.0,
        detection_reason="Exact match to the harmless AutoGuard test signature; this is a test detection.",
        reason="Exact match to the harmless AutoGuard test signature; this is a test detection.",
        rule_name="autoguard_test_signature",
        matched_signature_name="AutoGuard.Harmless.Test",
        matched_signature_kind=SignatureKind.AUTOGUARD_TEST,
    )
    quarantine = SimpleNamespace(
        quarantine_id="phase8-quarantine",
        incident_id=incident.id,
        sha256=incident.sha256,
        state=QuarantineState.QUARANTINED,
        original_path=first_path,
        original_removed=True,
        created_at=base + timedelta(seconds=20),
        quarantined_at=base + timedelta(minutes=1),
    )
    verification = SimpleNamespace(
        status=VerificationStatus.VERIFIED,
        verified_quarantine_objects=1,
        quarantined_copies=2,
        remaining_matching_copies=0,
        inaccessible_locations=0,
        verification_errors=0,
    )
    observations = (
        SimpleNamespace(path=first_path, first_seen=base, last_seen=base + timedelta(minutes=1)),
        # Duplicate of incident-file evidence must remain one location.
        SimpleNamespace(path=copy_path.upper(), first_seen=base + timedelta(minutes=2), last_seen=base + timedelta(minutes=3)),
        SimpleNamespace(path=usb_path, first_seen=base + timedelta(minutes=5), last_seen=base + timedelta(minutes=5)),
    )

    class Incidents:
        def get_incident(self, threat_ref):
            return details if threat_ref == incident.id else None

    class History:
        def latest_detection_for_sha256(self, sha256):
            return detection if sha256 == incident.sha256 else None

    class Quarantine:
        def list_quarantined_items(self):
            return [quarantine]

    class Cleanup:
        def list_verifications(self, threat_ref):
            return [verification] if threat_ref == incident.id else []

    class Recovery:
        def list_attempts(self, quarantine_id):
            return []

    class Trail:
        def get_observations(self, sha256):
            assert sha256 == incident.sha256
            return list(observations)

    services = SimpleNamespace(
        incidents=Incidents(),
        scanner=SimpleNamespace(history=History()),
        quarantine=Quarantine(),
        cleanup_verifier=Cleanup(),
        recovery=Recovery(),
        threat_trail=Trail(),
    )
    return services, incident, first_path, copy_path, usb_path


def test_ux_refresh_phase8_locations_merge_and_dedupe_existing_evidence_without_origin_claims():
    services, incident, first_path, copy_path, usb_path = _phase8_services()
    controller = AutoGuardUIController(services, UIMessageBus())
    try:
        result = controller._threat_details_snapshot(incident.id)
    finally:
        controller.shutdown()

    locations = result["locations"]
    assert len(locations) == 3
    assert locations[0]["path"].casefold() == first_path.casefold()
    assert locations[0]["first_observed"] is True
    assert locations[0]["availability"] == "Original removed after quarantine"
    assert sum(item["first_observed"] for item in locations) == 1
    keys = {item["path"].replace("\\", "/").casefold() for item in locations}
    assert len(keys) == 3
    assert any(item["path"].casefold() == copy_path.casefold() for item in locations)
    assert any(item["path"].casefold() == usb_path.casefold() for item in locations)
    primary = str({key: value for key, value in result.items() if key != "technical_details"})
    assert "do not prove" in primary.lower()


def test_ux_refresh_phase8_timeline_is_chronological_and_uses_friendly_labels():
    services, incident, *_ = _phase8_services()
    controller = AutoGuardUIController(services, UIMessageBus())
    try:
        result = controller._threat_details_snapshot(incident.id)
    finally:
        controller.shutdown()

    labels = [item["label"] for item in result["timeline"]]
    assert labels == [
        "Threat detected",
        "File quarantined",
        "Matching copy found",
        "Matching copy quarantined",
        "Cleanup verified",
        "Threat detected again",
        "File restored",
        "Incident resolved",
    ]
    rendered = str(result["timeline"])
    for raw in (
        "FIRST_OBSERVED",
        "QUARANTINE_SUCCEEDED",
        "MATCHING_COPY_FOUND",
        "CLEANUP_VERIFIED",
        "REAPPEARANCE",
    ):
        assert raw not in rendered


def test_ux_refresh_phase8_raw_event_constants_are_available_only_in_technical_details():
    services, incident, *_ = _phase8_services()
    controller = AutoGuardUIController(services, UIMessageBus())
    try:
        result = controller._threat_details_snapshot(incident.id)
    finally:
        controller.shutdown()

    technical = dict(result["technical_details"])
    assert "FIRST_OBSERVED" in technical["Incident events"]
    assert "CLEANUP_VERIFIED" in technical["Incident events"]
    primary = str({key: value for key, value in result.items() if key != "technical_details"})
    assert "FIRST_OBSERVED" not in primary
    assert "CLEANUP_VERIFIED" not in primary


def test_ux_refresh_phase8_component_adds_locations_and_timeline_without_restoring_threat_trail_nav():
    root = Path(__file__).resolve().parents[1]
    component = (root / "app/ui/threat_details_page.py").read_text(encoding="utf-8")
    sidebar = (root / "app/ui/sidebar.py").read_text(encoding="utf-8")

    assert 'text="Locations"' in component
    assert 'text="Timeline"' in component
    assert "AutoGuard observed identical file content in these locations" in component
    assert "First observed location" in component
    assert "do not prove an infection source or direction of spread" in component
    assert 'text="Technical details  ▾"' in component and "grid_remove()" in component
    assert "Threat Trail" not in sidebar


def _phase9_quarantine_services():
    from datetime import datetime, timedelta, timezone
    from app.incidents import IncidentStatus
    from app.models import ScanSource
    from app.quarantine import QuarantineIntegrityStatus, QuarantineState
    from app.recovery import RecoveryStatus

    base = datetime(2026, 9, 17, 1, 0, tzinfo=timezone.utc)
    incident = SimpleNamespace(
        id="incident-phase9",
        sha256="c" * 64,
        status=IncidentStatus.CONTAINED,
        first_observed_path=r"c:\users\fonti\downloads\test-threat.bin",
    )
    details = SimpleNamespace(incident=incident, files=(), events=())
    isolated = SimpleNamespace(
        quarantine_id="quarantine-internal-phase9",
        incident_id=incident.id,
        original_path=r"c:\users\fonti\downloads\test-threat.bin",
        stored_path=r"c:\users\fonti\autoguarddata\quarantine\hidden.agq",
        sha256=incident.sha256,
        original_size=2048,
        created_at=base,
        quarantined_at=base + timedelta(seconds=5),
        reason="Exact stored signature match",
        original_source=ScanSource.FILE_MONITOR,
        state=QuarantineState.QUARANTINED,
        integrity_status=QuarantineIntegrityStatus.VERIFIED,
        verified_sha256=incident.sha256,
        verified_size=2048,
        verified_at=base + timedelta(seconds=5),
        original_removed=True,
        failure_reason=None,
    )
    deleted_audit = SimpleNamespace(
        quarantine_id="deleted-audit-record",
        incident_id=incident.id,
        original_path=r"c:\users\fonti\desktop\old-copy.bin",
        stored_path=r"c:\users\fonti\autoguarddata\quarantine\deleted.agq",
        sha256=incident.sha256,
        original_size=1024,
        created_at=base,
        quarantined_at=base,
        reason="Previously isolated",
        original_source=ScanSource.MANUAL,
        state=QuarantineState.FAILED,
        integrity_status=QuarantineIntegrityStatus.FAILED,
        verified_sha256=None,
        verified_size=None,
        verified_at=None,
        original_removed=True,
        failure_reason="Quarantine object permanently deleted by user.",
    )
    recovery_attempt = SimpleNamespace(
        status=RecoveryStatus.DESTINATION_CONFLICT,
        finished_at=base + timedelta(minutes=4),
    )

    class Quarantine:
        def list_quarantined_items(self):
            return [isolated, deleted_audit]

        def get_item(self, item_ref):
            return isolated if item_ref == isolated.quarantine_id else None

    class Incidents:
        def get_incident(self, incident_id):
            return details if incident_id == incident.id else None

    class Recovery:
        def list_attempts(self, item_ref):
            return [recovery_attempt] if item_ref == isolated.quarantine_id else []

    services = SimpleNamespace(
        quarantine=Quarantine(),
        incidents=Incidents(),
        recovery=Recovery(),
    )
    return services, isolated


def test_ux_refresh_phase9_quarantine_list_uses_safe_user_facing_rows_only():
    services, isolated = _phase9_quarantine_services()
    controller = AutoGuardUIController(services, UIMessageBus())
    try:
        result = controller._quarantine_snapshot()
    finally:
        controller.shutdown()

    assert result["isolated_count"] == 1
    assert len(result["items"]) == 1
    row = result["items"][0]
    assert row["name"] == "test-threat.bin"
    assert row["original_location"] == isolated.original_path
    assert row["threat_status"] == "Contained"
    rendered = str(row)
    assert isolated.stored_path not in rendered
    assert isolated.sha256 not in rendered
    assert ".agq" not in rendered


def test_ux_refresh_phase9_detail_read_model_contains_advanced_integrity_and_ids_without_storage_path():
    services, isolated = _phase9_quarantine_services()
    controller = AutoGuardUIController(services, UIMessageBus())
    try:
        result = controller._quarantine_details_snapshot(isolated.quarantine_id)
    finally:
        controller.shutdown()

    assert result["hash_verification"] == "Verified"
    assert "SHA-256" in result["quarantine_integrity"]
    assert result["sha256"] == isolated.sha256
    assert result["quarantine_id"] == isolated.quarantine_id
    assert result["incident_id"] == isolated.incident_id
    assert result["original_location"] == isolated.original_path
    assert result["latest_recovery"]["status"] == "Choose another destination"
    assert "stored_path" not in result
    assert isolated.stored_path not in str(result)


def test_ux_refresh_phase9_main_quarantine_view_hides_storage_internals_and_has_required_states_actions():
    root = Path(__file__).resolve().parents[1]
    page = (root / "app/ui/quarantine_page.py").read_text(encoding="utf-8")
    detail = (root / "app/ui/quarantine_details_page.py").read_text(encoding="utf-8")

    for required in (
        "safely isolated", "Original location:", 'text="View"',
        'text="Restore"', 'text="Delete"', "No files are currently isolated",
        "Loading quarantine", "Operation failed",
    ):
        assert required in page
    for forbidden in (".agq", "stored_path", "sha256", "quarantine_id"):
        assert forbidden not in page

    assert 'text="Hash verification"' in detail
    assert 'text="Quarantine integrity"' not in detail  # label is passed through _detail_row
    assert '"Quarantine integrity"' in detail
    assert '"SHA-256"' in detail
    assert '"Internal quarantine ID"' in detail
    assert '"Associated incident ID"' in detail


def test_ux_refresh_phase9_restore_delete_verify_delegate_to_existing_services_off_ui_thread():
    root = Path(__file__).resolve().parents[1]
    controller = (root / "app/ui/controller.py").read_text(encoding="utf-8")
    page = (root / "app/ui/quarantine_page.py").read_text(encoding="utf-8")

    assert "self.services.quarantine.verify_integrity(quarantine_id)" in controller
    assert "self.services.recovery.restore(quarantine_id, destination)" in controller
    assert "self.services.quarantine.delete_quarantine_object(quarantine_id)" in controller
    assert 'self._submit(f"verify-quarantine:{quarantine_id}"' in controller
    assert 'self._submit(f"restore:{quarantine_id}"' in controller
    assert 'self._submit(f"delete-quarantine:{quarantine_id}"' in controller
    for forbidden in ("hashlib", "sha256(", "unlink(", "shutil.", "open("):
        assert forbidden not in page


def test_ux_refresh_phase9_delete_confirmation_is_user_facing_and_does_not_mention_agq():
    root = Path(__file__).resolve().parents[1]
    page = (root / "app/ui/quarantine_page.py").read_text(encoding="utf-8")
    assert "Permanently delete isolated file" in page
    assert "file can no longer be restored from quarantine" in page
    assert ".agq" not in page