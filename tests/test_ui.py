from __future__ import annotations
from pathlib import Path
from types import SimpleNamespace
import threading, time, ast, re
from app.models import ScanResult, ScanStatus, ScanSummary, ScanType, ScanSessionStatus, DetectionStatus
from app.database import Database
from app.detector import Detector
from app.scanner import Scanner, ScanInterruptedError
from app.signatures import SignatureStore
from app.threat_trail import ThreatTrail
from app.ui.controller import AutoGuardUIController
from app.ui.messages import UIMessageBus
from app.incidents import IncidentEventType, IncidentStatus
from app.cleanup_verifier import VerificationStatus

def wait_for(bus: UIMessageBus, kind: str, timeout: float = 2.0):
    deadline = time.monotonic() + timeout; seen = []
    while time.monotonic() < deadline:
        seen.extend(bus.drain())
        for message in seen:
            if message.kind == kind: return message, seen
        time.sleep(0.01)
    raise AssertionError(f"Timed out waiting for {kind}; saw {[m.kind for m in seen]}")

def test_message_bus_preserves_fifo_order():
    bus = UIMessageBus(); bus.publish("first", value=1); bus.publish("second", value=2)
    assert [message.kind for message in bus.drain()] == ["first", "second"]; assert bus.pending() == 0

def test_message_bus_validates_kind_and_limit():
    bus = UIMessageBus()
    try: bus.publish("   ")
    except ValueError: pass
    else: raise AssertionError("empty message kind should be rejected")
    try: bus.drain(0)
    except ValueError: pass
    else: raise AssertionError("nonpositive drain limit should be rejected")

class FakeScanner:
    def __init__(self): self.thread_id = None
    def count_scan_entries(self, *args, **kwargs): raise AssertionError("UI must not pre-count scan entries")
    def scan(self, path, source, *, scan_type, interrupt_check=None, on_result=None, on_discovered=None):
        self.thread_id = threading.get_ident(); result = ScanResult(str(path), ScanStatus.SCANNED, "No threat detected.")
        if on_discovered: on_discovered(str(path), "file")
        if on_result: on_result(result)
        time.sleep(0.04); return ScanSummary((result,), "session-1")

def fake_services(scanner):
    return SimpleNamespace(scanner=scanner, scheduler=SimpleNamespace(quick_paths=(Path("quick"),), full_paths=(Path("full"),), settings=SimpleNamespace(quick_interval_hours=24.0, full_interval_days=7.0)))

def test_controller_dispatches_manual_scan_off_calling_thread():
    bus = UIMessageBus(); scanner = FakeScanner(); controller = AutoGuardUIController(fake_services(scanner), bus); calling_thread = threading.get_ident(); started = time.monotonic(); controller.start_scan("example.txt", scan_type=ScanType.MANUAL); elapsed = time.monotonic() - started; message, seen = wait_for(bus, "scan_completed")
    try:
        assert elapsed < 0.03 and scanner.thread_id is not None and scanner.thread_id != calling_thread
        discovered = next(item for item in seen if item.kind == "scan_discovered"); assert discovered.payload["discovered"] == 1 and discovered.payload["processed"] == 0
        progress = next(item for item in seen if item.kind == "scan_result"); assert progress.payload["processed"] == 1 and progress.payload["discovered"] == 1 and progress.payload["progress"] == 1.0 and message.payload["result"].session_id == "session-1"
    finally: controller.shutdown()

def test_controller_emits_task_failure_without_raising_on_ui_thread():
    class FailingScanner(FakeScanner):
        def scan(self, *args, **kwargs): raise PermissionError("simulated locked target")
    bus = UIMessageBus(); controller = AutoGuardUIController(fake_services(FailingScanner()), bus); controller.start_scan("locked.bin"); failure, _ = wait_for(bus, "task_failed")
    try: assert "PermissionError" in failure.payload["error"] and "simulated locked target" in failure.payload["error"]
    finally: controller.shutdown()

def test_scan_progress_callback_failure_does_not_change_scanner_result(tmp_path):
    database = Database(tmp_path / "autoguard.db"); database.initialize(); scanner = Scanner(Detector(SignatureStore()), ThreatTrail(database)); target = tmp_path / "safe.txt"; target.write_text("harmless", encoding="utf-8")
    assert scanner.scan_file(target, on_result=lambda _: (_ for _ in ()).throw(RuntimeError("UI gone"))).status is ScanStatus.SCANNED

def test_scanner_single_pass_discovery_matches_emitted_results(tmp_path):
    database = Database(tmp_path / "autoguard.db"); database.initialize(); scanner = Scanner(Detector(SignatureStore()), ThreatTrail(database)); folder = tmp_path / "folder"; folder.mkdir(); (folder / "one.txt").write_text("one", encoding="utf-8"); nested = folder / "nested"; nested.mkdir(); (nested / "two.txt").write_text("two", encoding="utf-8")
    discovered = []; emitted = []; summary = scanner.scan(folder, on_discovered=lambda path, kind: discovered.append((path, kind)), on_result=emitted.append)
    assert len(discovered) == 2 == len(emitted) == len(summary.results) and {path for path, _ in discovered} == {result.path for result in summary.results}

def test_controller_never_runs_metadata_precount_before_scan():
    bus = UIMessageBus(); scanner = FakeScanner(); controller = AutoGuardUIController(fake_services(scanner), bus); controller.start_scan("instant.txt"); _, seen = wait_for(bus, "scan_completed")
    try:
        kinds = [m.kind for m in seen]; assert "scan_counting" not in kinds and "scan_total" not in kinds and kinds.index("scan_started") < kinds.index("scan_discovered") < kinds.index("scan_result") < kinds.index("scan_completed")
    finally: controller.shutdown()

def _ui_module_ast(relative_path: str):
    return ast.parse((Path(__file__).resolve().parents[1] / relative_path).read_text(encoding="utf-8"))

def _literal_assignment(tree, name: str):
    for node in tree.body:
        if isinstance(node, ast.Assign) and any(isinstance(target, ast.Name) and target.id == name for target in node.targets): return ast.literal_eval(node.value)
    raise AssertionError(f"Assignment {name!r} not found")

def _class_attribute_literal(tree, class_name: str, attribute: str):
    for node in tree.body:
        if isinstance(node, ast.ClassDef) and node.name == class_name:
            for child in node.body:
                if isinstance(child, ast.Assign) and any(isinstance(target, ast.Name) and target.id == attribute for target in child.targets): return ast.literal_eval(child.value)
    raise AssertionError(f"{class_name}.{attribute} not found")

def test_ux_refresh_phase1_exposes_exactly_six_top_level_pages():
    sidebar = _ui_module_ast("app/ui/sidebar.py"); nav_items = _literal_assignment(sidebar, "NAV_ITEMS")
    assert nav_items == (("home", "Home"), ("scan", "Scan"), ("threats", "Threats"), ("quarantine", "Quarantine"), ("activity", "Activity"), ("settings", "Settings")) and {"incidents", "threat_trail", "history"}.isdisjoint({key for key, _ in nav_items})

def test_ux_refresh_phase1_page_registry_matches_navigation_without_legacy_pages():
    tree = _ui_module_ast("app/ui/main_window.py"); default_page = _literal_assignment(tree, "DEFAULT_PAGE"); page_classes = None
    for node in tree.body:
        if isinstance(node, ast.Assign) and any(isinstance(target, ast.Name) and target.id == "PAGE_CLASSES" for target in node.targets):
            page_classes = {ast.literal_eval(key): value.id for key, value in zip(node.value.keys, node.value.values)}; break
    assert page_classes is not None and default_page == "home" and tuple(page_classes) == ("home", "scan", "threats", "quarantine", "activity", "settings")
    assert page_classes["home"] == "DashboardPage" and page_classes["threats"] == "ThreatsPage" and page_classes["activity"] == "ActivityPage" and {"incidents", "threat_trail", "history"}.isdisjoint(page_classes)
    assert _class_attribute_literal(_ui_module_ast("app/ui/dashboard.py"), "DashboardPage", "title") == "Home" and _class_attribute_literal(_ui_module_ast("app/ui/threats_page.py"), "ThreatsPage", "title") == "Threats" and _class_attribute_literal(_ui_module_ast("app/ui/activity_page.py"), "ActivityPage", "title") == "Activity"

def _home_services(*, file_running=True, usb_running=True, scheduler_running=True, quick_running=False, full_running=False, incidents=(), sessions=(), details=None, quarantined=0):
    health = lambda running: SimpleNamespace(running=running, status=SimpleNamespace(value="RUNNING" if running else "STOPPED"))
    History = type("History", (), {"recent_scans": lambda self, limit: list(sessions)[:limit], "get_scan": lambda self, session_id: (details or {}).get(session_id)})
    return SimpleNamespace(file_monitor=SimpleNamespace(health=lambda: health(file_running)), usb_monitor=SimpleNamespace(health=lambda: health(usb_running)), scheduler=SimpleNamespace(quick_paths=(), full_paths=(), settings=SimpleNamespace(quick_interval_hours=24.0, full_interval_days=7.0), health=lambda: SimpleNamespace(running=scheduler_running, quick_scan_running=quick_running, full_scan_running=full_running)), quarantine=SimpleNamespace(list_quarantined_items=lambda: [SimpleNamespace(state=SimpleNamespace(value="QUARANTINED")) for _ in range(quarantined)]), incidents=SimpleNamespace(get_active_incidents=lambda: list(incidents)), scanner=SimpleNamespace(history=History()))

def test_ux_refresh_phase2_home_uses_only_four_user_facing_protection_states():
    controller = AutoGuardUIController(_home_services(), UIMessageBus())
    try:
        assert controller._dashboard_snapshot()["protection_state"] == {"key": "protected", "title": "Protected", "message": "Everything is working normally."}
        controller.services = _home_services(quick_running=True); assert controller._dashboard_snapshot()["protection_state"]["title"] == "Scanning"
        controller.services = _home_services(incidents=(SimpleNamespace(status=IncidentStatus.OPEN),)); attention = controller._dashboard_snapshot()["protection_state"]
        assert attention["title"] == "Attention needed" and attention["message"] == "AutoGuard found something that needs review."
        controller.services = _home_services(file_running=False); issue = controller._dashboard_snapshot()["protection_state"]
        assert issue["title"] == "Protection issue" and issue["message"] == "One or more protection services are not running."
    finally: controller.shutdown()

def test_ux_refresh_phase2_contained_incident_does_not_force_attention_state():
    controller = AutoGuardUIController(_home_services(incidents=(SimpleNamespace(status=IncidentStatus.CONTAINED),)), UIMessageBus())
    try:
        snapshot = controller._dashboard_snapshot(); assert snapshot["protection_state"]["title"] == "Protected" and snapshot["threats_needing_review"] == 0
    finally: controller.shutdown()

def test_ux_refresh_phase2_home_navigation_and_quick_scan_are_presentation_wired():
    source = (Path(__file__).resolve().parents[1] / "app/ui/dashboard.py").read_text(encoding="utf-8"); tree = ast.parse(source)
    assert {"Last Scan", "Threats", "Quarantine", "Protection", "Recent Activity", "Run Quick Scan", "View activity"} <= {node.value for node in ast.walk(tree) if isinstance(node, ast.Constant) and isinstance(node.value, str)} and "start_quick_scan" in source and 'navigate_to("activity")' in source and not any(forbidden in source for forbidden in ("SHA-256", "incident ID", "session ID", "worker name"))

def test_ux_refresh_phase2_view_activity_request_uses_message_bus():
    bus = UIMessageBus(); controller = AutoGuardUIController(_home_services(), bus)
    try:
        controller.navigate_to("activity"); messages = bus.drain(); assert len(messages) == 1 and messages[0].kind == "navigate" and messages[0].payload["page"] == "activity"
    finally: controller.shutdown()

def test_ux_refresh_phase3_idle_scan_page_uses_simple_user_facing_choices():
    source = (Path(__file__).resolve().parents[1] / "app/ui/scan_page.py").read_text(encoding="utf-8")
    assert 'text="Scan your PC"' in source and 'title="Quick Scan"' in source and 'title="Full Scan"' in source and 'title="Custom Scan"' in source and 'recommended=True' in source and "Downloads  *  Desktop  *  Documents" in source and '"Start Quick Scan", self.controller.start_quick_scan' in source and '"Start Full Scan", self.controller.start_full_scan' in source and '"Choose File", self._choose_file' in source and '"Choose Folder", self._choose_folder' in source and "Manual Scan" not in source

def test_ux_refresh_phase3_custom_scan_delegates_to_controller_without_scanner_logic():
    source = (Path(__file__).resolve().parents[1] / "app/ui/scan_page.py").read_text(encoding="utf-8")
    names = {node.attr for node in ast.walk(ast.parse(source)) if isinstance(node, ast.Attribute) and isinstance(node.value, ast.Attribute) and isinstance(node.value.value, ast.Name) and node.value.value.id == "self" and node.value.attr == "controller"}
    assert {"start_scan", "start_quick_scan", "start_full_scan"} <= names and not any(forbidden in source for forbidden in ("hashlib", "sha256(", "Detector(", "inspect_file(", "ThreatTrail("))

def test_ux_refresh_phase3_manual_internal_label_is_presented_as_custom_scan():
    source = (Path(__file__).resolve().parents[1] / "app/ui/components/scan_progress.py").read_text(encoding="utf-8")
    assert re.search(r'["\']manual["\']\s*:\s*["\']Custom Scan["\']', source) and not re.search(r'["\']manual["\']\s*:\s*["\']Manual Scan["\']', source)

def test_ux_refresh_phase4_active_scan_is_focused_and_has_no_fake_pause():
    source = (Path(__file__).resolve().parents[1] / "app/ui/components/active_scan.py").read_text(encoding="utf-8")
    assert all(required in source for required in ("Files checked", "Threats found", "Currently checking", "More details", "Discovered", "Processed", "Skipped", "Errors", "Suspicious", "Dangerous", "Stop Scan")) and not any(forbidden in source for forbidden in ("Pause", "hashlib", "inspect_file(", "Detector("))

def test_ux_refresh_phase4_scan_page_uses_active_component_and_stop_controller():
    source = (Path(__file__).resolve().parents[1] / "app/ui/scan_page.py").read_text(encoding="utf-8")
    assert "ActiveScanPanel" in source and "on_stop=self.controller.stop_scan" in source and 'message.kind == "scan_stop_requested"' in source and 'message.kind == "scan_stopped"' in source and "Live results" not in source and "CTkTextbox" not in source

def test_ux_refresh_phase4_stop_scan_uses_cooperative_interrupt_without_blocking_ui():
    class InterruptibleScanner(FakeScanner):
        def __init__(self): super().__init__(); self.worker_started = threading.Event(); self.received_interrupt_check = False
        def scan(self, path, source, *, scan_type, interrupt_check=None, on_result=None, on_discovered=None):
            self.thread_id = threading.get_ident(); self.received_interrupt_check = callable(interrupt_check); self.worker_started.set()
            if on_discovered: on_discovered(str(path), "file")
            deadline = time.monotonic() + 2.0
            while time.monotonic() < deadline:
                if interrupt_check is not None and interrupt_check(): raise ScanInterruptedError("Scan interrupted before completion.", "session-stop")
                time.sleep(0.005)
            raise AssertionError("Stop Scan did not reach the scanner interrupt hook")
    bus = UIMessageBus(); scanner = InterruptibleScanner(); controller = AutoGuardUIController(fake_services(scanner), bus); calling_thread = threading.get_ident()
    try:
        controller.start_scan("large-folder"); assert scanner.worker_started.wait(1.0); started = time.monotonic()
        assert controller.stop_scan() is True and time.monotonic() - started < 0.05
        stopped, seen = wait_for(bus, "scan_stopped")
        assert scanner.received_interrupt_check and scanner.thread_id != calling_thread and stopped.payload["session_id"] == "session-stop" and not any(message.kind in ("task_failed", "scan_completed") for message in seen)
    finally: controller.shutdown()

def test_ux_refresh_phase4_stop_scan_is_noop_when_no_ui_scan_is_running():
    controller = AutoGuardUIController(fake_services(FakeScanner()), UIMessageBus())
    try: assert controller.stop_scan() is False
    finally: controller.shutdown()

def _phase5_result_services(*, session, results=(), incident=None, incident_events=(), verification=None):
    History = type("History", (), {"__init__": lambda self: setattr(self, "thread_id", None), "get_scan": lambda self, session_id: (setattr(self, "thread_id", threading.get_ident()), SimpleNamespace(session=session, results=tuple(results)))[1] if session_id == session.id else None})
    Incidents = type("Incidents", (), {"get_active_incidents": lambda self: [] if incident is None else [incident], "get_incident": lambda self, incident_id: SimpleNamespace(incident=incident, files=(), events=tuple(incident_events)) if incident is not None and incident_id == incident.id else None})
    Verifier = type("Verifier", (), {"list_verifications": lambda self, incident_id: [verification] if incident is not None and incident_id == incident.id and verification is not None else []})
    history = History(); return SimpleNamespace(scanner=SimpleNamespace(history=history), incidents=Incidents(), cleanup_verifier=Verifier()), history

def _phase5_session(*, suspicious=0, dangerous=0, scanned=8, skipped=0, errors=0):
    from datetime import datetime, timedelta, timezone
    started = datetime(2026, 9, 16, 12, 0, 0, tzinfo=timezone.utc)
    return SimpleNamespace(id="phase5-session", scan_type=ScanType.QUICK, started_at=started, finished_at=started + timedelta(seconds=12), status=ScanSessionStatus.COMPLETED, counters={"scanned_files": scanned, "dangerous_detections": dangerous, "suspicious_detections": suspicious, "skipped_size": skipped, "locked_files": 0, "unsupported_files": 0, "errors": errors, "file_errors": errors})

def test_ux_refresh_phase5_clean_result_uses_honest_user_facing_wording():
    session = _phase5_session(scanned=42, skipped=3); services, _ = _phase5_result_services(session=session); controller = AutoGuardUIController(services, UIMessageBus())
    try: result = controller._scan_result_snapshot((SimpleNamespace(session_id=session.id),))
    finally: controller.shutdown()
    assert result["kind"] == "clean" and result["title"] == "Scan complete" and result["message"] == "No threats detected in the files successfully scanned." and result["scan_type"] == "Quick Scan" and result["duration"] == "12 sec" and result["files_checked"] == 42 and result["threats_found"] == 0 and result["skipped_files"] == 3 and "completely safe" not in result["message"].lower()

def test_ux_refresh_phase5_suspicious_result_does_not_call_it_a_confirmed_threat():
    session = _phase5_session(suspicious=2, dangerous=0); services, _ = _phase5_result_services(session=session); controller = AutoGuardUIController(services, UIMessageBus())
    try: result = controller._scan_result_snapshot((SimpleNamespace(session_id=session.id),))
    finally: controller.shutdown()
    assert result["kind"] == "suspicious" and result["title"] == "Review recommended" and "2 suspicious files" in result["message"] and "no confirmed threat was detected" in result["message"].lower() and "LOW_CONFIDENCE" not in str(result) and "HIGH_CONFIDENCE" not in str(result)

def test_ux_refresh_phase5_confirmed_result_claims_handled_only_with_verified_containment():
    from datetime import timedelta
    session = _phase5_session(dangerous=1); sha256 = "a" * 64; stored = SimpleNamespace(detection_status=DetectionStatus.HIGH_CONFIDENCE, sha256=sha256); incident = SimpleNamespace(id="internal-incident", sha256=sha256, status=IncidentStatus.CONTAINED); event = SimpleNamespace(event_type=IncidentEventType.MATCHING_COPY_FOUND, occurred_at=session.started_at + timedelta(seconds=4)); verification = SimpleNamespace(status=VerificationStatus.VERIFIED)
    services, _ = _phase5_result_services(session=session, results=(stored,), incident=incident, incident_events=(event, event), verification=verification); controller = AutoGuardUIController(services, UIMessageBus())
    try: result = controller._scan_result_snapshot((SimpleNamespace(session_id=session.id),))
    finally: controller.shutdown()
    assert result["kind"] == "confirmed_threat" and result["title"] == "Threat handled" and result["containment_verified"] is True and result["threats_contained"] == 1 and result["matching_copies_found"] == 2 and result["cleanup_status"] == "Verified" and "internal-incident" not in str(result)

def test_ux_refresh_phase5_confirmed_result_does_not_overclaim_failed_cleanup():
    session = _phase5_session(dangerous=1); sha256 = "b" * 64; stored = SimpleNamespace(detection_status=DetectionStatus.HIGH_CONFIDENCE, sha256=sha256); incident = SimpleNamespace(id="internal-incident", sha256=sha256, status=IncidentStatus.OPEN); verification = SimpleNamespace(status=VerificationStatus.FAILED)
    services, _ = _phase5_result_services(session=session, results=(stored,), incident=incident, verification=verification); controller = AutoGuardUIController(services, UIMessageBus())
    try: result = controller._scan_result_snapshot((SimpleNamespace(session_id=session.id),))
    finally: controller.shutdown()
    assert result["title"] == "Confirmed threat detected" and result["containment_verified"] is False and result["threats_contained"] == 0 and result["cleanup_status"] == "Failed" and "Threat handled" not in result["title"]

def test_ux_refresh_phase5_result_preparation_runs_off_the_calling_thread():
    session = _phase5_session(scanned=1); services, history = _phase5_result_services(session=session); bus = UIMessageBus(); controller = AutoGuardUIController(services, bus); calling_thread = threading.get_ident()
    try:
        controller.prepare_scan_result(SimpleNamespace(session_id=session.id)); message, _ = wait_for(bus, "scan_result_ready")
        assert history.thread_id is not None and history.thread_id != calling_thread and message.payload["result"]["kind"] == "clean"
    finally: controller.shutdown()

def test_ux_refresh_phase5_scan_result_component_and_page_contract():
    component = (Path(__file__).resolve().parents[1] / "app/ui/components/scan_result.py").read_text(encoding="utf-8"); page = (Path(__file__).resolve().parents[1] / "app/ui/scan_page.py").read_text(encoding="utf-8")
    assert all(req in component for req in ("class ScanResultPanel", "No threats detected in the files successfully scanned.", "Scan complete", "Review files", "View threat")) and not any(forbidden in component for forbidden in ("LOW_CONFIDENCE", "HIGH_CONFIDENCE", "incident_id", "session_id", "sha256"))
    assert "ScanResultPanel" in page and "prepare_scan_result" in page and 'message.kind == "scan_result_ready"' in page and 'navigate_to("activity")' in page and 'navigate_to("threats")' in page

def _phase6_incident(status, *, name="sample.bin", matching_paths=(), location_count=1):
    from datetime import datetime, timezone
    when = datetime(2026, 9, 17, 0, 30, tzinfo=timezone.utc); incident = SimpleNamespace(id=f"ref-{status.value.lower()}", status=status, first_observed_path=rf"c:\users\fonti\downloads\{name}", last_observed_at=when)
    return incident, SimpleNamespace(incident=incident, files=tuple(SimpleNamespace(path=rf"c:\test\location-{index}\{name}") for index in range(location_count)), events=tuple(SimpleNamespace(event_type=IncidentEventType.MATCHING_COPY_FOUND, path=path) for path in matching_paths))

def test_ux_refresh_phase6_threat_read_model_translates_statuses_and_sections():
    configured = [_phase6_incident(IncidentStatus.OPEN), _phase6_incident(IncidentStatus.INVESTIGATING), _phase6_incident(IncidentStatus.CONTAINED), _phase6_incident(IncidentStatus.REAPPEARED), _phase6_incident(IncidentStatus.RESTORED), _phase6_incident(IncidentStatus.RESOLVED)]; details_by_id = {incident.id: details for incident, details in configured}
    Incidents = type("Incidents", (), {"list_incidents": lambda self, limit: [item[0] for item in configured] if limit == 200 else [], "get_incident": lambda self, threat_ref: details_by_id.get(threat_ref)})
    controller = AutoGuardUIController(SimpleNamespace(incidents=Incidents()), UIMessageBus())
    try: rows = controller._threat_rows()
    finally: controller.shutdown()
    assert [(row["status"], row["section"]) for row in rows] == [("Needs attention", "Needs attention"), ("Being reviewed", "Needs attention"), ("Contained", "Contained"), ("Detected again", "Needs attention"), ("Restored", "Needs attention"), ("Resolved", "Resolved")] and not any(raw in str(rows) for raw in ("OPEN", "INVESTIGATING", "CONTAINED", "REAPPEARED", "RESTORED", "RESOLVED"))

def test_ux_refresh_phase6_threat_read_model_uses_location_and_matching_copy_evidence():
    incident, details = _phase6_incident(IncidentStatus.CONTAINED, name="test-threat.bin", location_count=3, matching_paths=(r"c:\one.bin", r"c:\two.bin", r"c:\two.bin"))
    Incidents = type("Incidents", (), {"list_incidents": lambda self, limit: [incident], "get_incident": lambda self, threat_ref: details})
    controller = AutoGuardUIController(SimpleNamespace(incidents=Incidents()), UIMessageBus())
    try: row = controller._threat_rows()[0]
    finally: controller.shutdown()
    assert row["name"] == "test-threat.bin" and row["location"] == "3 observed locations" and row["matching_copies"] == 2 and row["action"] == "View details" and "ref-contained" not in str({k: v for k, v in row.items() if k != "threat_ref"})

def test_ux_refresh_phase6_open_threat_details_prepares_future_navigation():
    bus = UIMessageBus(); controller = AutoGuardUIController(SimpleNamespace(), bus)
    try:
        controller.open_threat_details("internal-reference"); messages = bus.drain()
    finally: controller.shutdown()
    assert controller.selected_threat_ref == "internal-reference" and [message.kind for message in messages] == ["threat_details_requested", "navigate"] and messages[-1].payload == {"page": "threats"}

def test_ux_refresh_phase6_threats_page_is_user_facing_and_service_driven():
    source = (Path(__file__).resolve().parents[1] / "app/ui/threats_page.py").read_text(encoding="utf-8"); controller_source = (Path(__file__).resolve().parents[1] / "app/ui/controller.py").read_text(encoding="utf-8")
    assert all(req in source for req in ('title = "Threats"', "Needs attention", "Contained", "Resolved", "No active threats", "open_threat_details")) and not any(forbidden in source for forbidden in ("sha256", "incident_id", "event_type.value", "detection_rule", "SELECT * FROM threat_incidents"))
    assert "def load_threats" in controller_source and "self.services.incidents.list_incidents" in controller_source and "self.services.incidents.get_incident" in controller_source