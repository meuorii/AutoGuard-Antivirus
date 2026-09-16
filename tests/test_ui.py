from __future__ import annotations
import threading
import time
from pathlib import Path
from types import SimpleNamespace
from app.database import Database
from app.detector import Detector
from app.models import ScanResult, ScanStatus, ScanSummary, ScanType
from app.scanner import Scanner
from app.signatures import SignatureStore
from app.threat_trail import ThreatTrail
from app.ui.controller import AutoGuardUIController
from app.ui.messages import UIMessageBus


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
    def scan(self, path, source, *, scan_type, on_result=None, on_discovered=None):
        self.thread_id = threading.get_ident(); result = ScanResult(str(path), ScanStatus.SCANNED, "No threat detected.")
        if on_discovered: on_discovered(str(path), "file")
        if on_result: on_result(result)
        time.sleep(0.04); return ScanSummary((result,), "session-1")

def fake_services(scanner):
    scheduler = SimpleNamespace(quick_paths=(Path("quick"),), full_paths=(Path("full"),), settings=SimpleNamespace(quick_interval_hours=24.0, full_interval_days=7.0))
    return SimpleNamespace(scanner=scanner, scheduler=scheduler)

def test_controller_dispatches_manual_scan_off_calling_thread():
    bus = UIMessageBus(); scanner = FakeScanner(); controller = AutoGuardUIController(fake_services(scanner), bus); calling_thread = threading.get_ident()
    started = time.monotonic(); controller.start_scan("example.txt", scan_type=ScanType.MANUAL); elapsed = time.monotonic() - started
    message, seen = wait_for(bus, "scan_completed")
    try:
        assert elapsed < 0.03; assert scanner.thread_id is not None and scanner.thread_id != calling_thread
        discovered = next(item for item in seen if item.kind == "scan_discovered"); assert discovered.payload["discovered"] == 1 and discovered.payload["processed"] == 0
        progress = next(item for item in seen if item.kind == "scan_result"); assert progress.payload["processed"] == 1 and progress.payload["discovered"] == 1 and progress.payload["progress"] == 1.0
        assert message.payload["result"].session_id == "session-1"
    finally: controller.shutdown()

def test_controller_emits_task_failure_without_raising_on_ui_thread():
    class FailingScanner(FakeScanner):
        def scan(self, *args, **kwargs): raise PermissionError("simulated locked target")
    bus = UIMessageBus(); controller = AutoGuardUIController(fake_services(FailingScanner()), bus); controller.start_scan("locked.bin")
    failure, _ = wait_for(bus, "task_failed")
    try: assert "PermissionError" in failure.payload["error"] and "simulated locked target" in failure.payload["error"]
    finally: controller.shutdown()

def test_scan_progress_callback_failure_does_not_change_scanner_result(tmp_path):
    database = Database(tmp_path / "autoguard.db"); database.initialize(); scanner = Scanner(Detector(SignatureStore()), ThreatTrail(database))
    target = tmp_path / "safe.txt"; target.write_text("harmless", encoding="utf-8")
    result = scanner.scan_file(target, on_result=lambda _: (_ for _ in ()).throw(RuntimeError("UI gone")))
    assert result.status is ScanStatus.SCANNED

def test_scanner_single_pass_discovery_matches_emitted_results(tmp_path):
    database = Database(tmp_path / "autoguard.db"); database.initialize(); scanner = Scanner(Detector(SignatureStore()), ThreatTrail(database))
    folder = tmp_path / "folder"; folder.mkdir(); (folder / "one.txt").write_text("one", encoding="utf-8"); nested = folder / "nested"; nested.mkdir(); (nested / "two.txt").write_text("two", encoding="utf-8")
    discovered = []; emitted = []; summary = scanner.scan(folder, on_discovered=lambda path, kind: discovered.append((path, kind)), on_result=emitted.append)
    assert len(discovered) == 2 == len(emitted) == len(summary.results)
    assert {path for path, _ in discovered} == {result.path for result in summary.results}

def test_controller_never_runs_metadata_precount_before_scan():
    bus = UIMessageBus(); scanner = FakeScanner(); controller = AutoGuardUIController(fake_services(scanner), bus); controller.start_scan("instant.txt")
    _, seen = wait_for(bus, "scan_completed")
    try:
        kinds = [m.kind for m in seen]; assert "scan_counting" not in kinds and "scan_total" not in kinds
        assert kinds.index("scan_started") < kinds.index("scan_discovered") < kinds.index("scan_result") < kinds.index("scan_completed")
    finally: controller.shutdown()

def _ui_module_ast(relative_path: str):
    import ast
    project_root = Path(__file__).resolve().parents[1]
    return ast.parse((project_root / relative_path).read_text(encoding="utf-8"))

def _literal_assignment(tree, name: str):
    import ast
    for node in tree.body:
        if isinstance(node, ast.Assign) and any(isinstance(target, ast.Name) and target.id == name for target in node.targets): return ast.literal_eval(node.value)
    raise AssertionError(f"Assignment {name!r} not found")

def _class_attribute_literal(tree, class_name: str, attribute: str):
    import ast
    for node in tree.body:
        if isinstance(node, ast.ClassDef) and node.name == class_name:
            for child in node.body:
                if isinstance(child, ast.Assign) and any(isinstance(target, ast.Name) and target.id == attribute for target in child.targets): return ast.literal_eval(child.value)
    raise AssertionError(f"{class_name}.{attribute} not found")

def test_ux_refresh_phase1_exposes_exactly_six_top_level_pages():
    sidebar = _ui_module_ast("app/ui/sidebar.py"); nav_items = _literal_assignment(sidebar, "NAV_ITEMS")
    assert nav_items == (("home", "Home"), ("scan", "Scan"), ("threats", "Threats"), ("quarantine", "Quarantine"), ("activity", "Activity"), ("settings", "Settings"))
    assert {"incidents", "threat_trail", "history"}.isdisjoint({key for key, _ in nav_items})

def test_ux_refresh_phase1_page_registry_matches_navigation_without_legacy_pages():
    import ast
    tree = _ui_module_ast("app/ui/main_window.py"); default_page = _literal_assignment(tree, "DEFAULT_PAGE"); page_classes = None
    for node in tree.body:
        if isinstance(node, ast.Assign) and any(isinstance(target, ast.Name) and target.id == "PAGE_CLASSES" for target in node.targets):
            page_classes = {ast.literal_eval(key): value.id for key, value in zip(node.value.keys, node.value.values)}; break
    assert page_classes is not None and default_page == "home"
    assert tuple(page_classes) == ("home", "scan", "threats", "quarantine", "activity", "settings")
    assert page_classes["home"] == "DashboardPage" and page_classes["threats"] == "ThreatsPage" and page_classes["activity"] == "ActivityPage"
    assert {"incidents", "threat_trail", "history"}.isdisjoint(page_classes)
    dashboard, threats, activity = _ui_module_ast("app/ui/dashboard.py"), _ui_module_ast("app/ui/threats_page.py"), _ui_module_ast("app/ui/activity_page.py")
    assert _class_attribute_literal(dashboard, "DashboardPage", "title") == "Home"
    assert _class_attribute_literal(threats, "ThreatsPage", "title") == "Threats"
    assert _class_attribute_literal(activity, "ActivityPage", "title") == "Activity"

def _home_services(*, file_running=True, usb_running=True, scheduler_running=True, quick_running=False, full_running=False, incidents=(), sessions=(), details=None, quarantined=0):
    def health(running): return SimpleNamespace(running=running, status=SimpleNamespace(value="RUNNING" if running else "STOPPED"))
    class History:
        def recent_scans(self, limit): return list(sessions)[:limit]
        def get_scan(self, session_id): return (details or {}).get(session_id)

    scheduler_health = SimpleNamespace(running=scheduler_running, quick_scan_running=quick_running, full_scan_running=full_running)
    scheduler = SimpleNamespace(quick_paths=(), full_paths=(), settings=SimpleNamespace(quick_interval_hours=24.0, full_interval_days=7.0), health=lambda: scheduler_health)
    quarantine_items = [SimpleNamespace(state=SimpleNamespace(value="QUARANTINED")) for _ in range(quarantined)]
    return SimpleNamespace(
        file_monitor=SimpleNamespace(health=lambda: health(file_running)), usb_monitor=SimpleNamespace(health=lambda: health(usb_running)),
        scheduler=scheduler, quarantine=SimpleNamespace(list_quarantined_items=lambda: quarantine_items),
        incidents=SimpleNamespace(get_active_incidents=lambda: list(incidents)), scanner=SimpleNamespace(history=History()),
    )

def test_ux_refresh_phase2_home_uses_only_four_user_facing_protection_states():
    from app.incidents import IncidentStatus
    controller = AutoGuardUIController(_home_services(), UIMessageBus())
    try:
        snapshot = controller._dashboard_snapshot()
        assert snapshot["protection_state"] == {"key": "protected", "title": "Protected", "message": "Everything is working normally."}
        controller.services = _home_services(quick_running=True)
        assert controller._dashboard_snapshot()["protection_state"]["title"] == "Scanning"
        controller.services = _home_services(incidents=(SimpleNamespace(status=IncidentStatus.OPEN),))
        attention = controller._dashboard_snapshot()["protection_state"]
        assert attention["title"] == "Attention needed" and attention["message"] == "AutoGuard found something that needs review."
        controller.services = _home_services(file_running=False)
        issue = controller._dashboard_snapshot()["protection_state"]
        assert issue["title"] == "Protection issue" and issue["message"] == "One or more protection services are not running."
    finally: controller.shutdown()

def test_ux_refresh_phase2_contained_incident_does_not_force_attention_state():
    from app.incidents import IncidentStatus
    controller = AutoGuardUIController(_home_services(incidents=(SimpleNamespace(status=IncidentStatus.CONTAINED),)), UIMessageBus())
    try:
        snapshot = controller._dashboard_snapshot()
        assert snapshot["protection_state"]["title"] == "Protected" and snapshot["threats_needing_review"] == 0
    finally: controller.shutdown()

def test_ux_refresh_phase2_home_navigation_and_quick_scan_are_presentation_wired():
    import ast
    dashboard_path = Path(__file__).resolve().parents[1] / "app/ui/dashboard.py"
    source = dashboard_path.read_text(encoding="utf-8"); tree = ast.parse(source)
    strings = {node.value for node in ast.walk(tree) if isinstance(node, ast.Constant) and isinstance(node.value, str)}

    assert {"Last Scan", "Threats", "Quarantine", "Protection", "Recent Activity", "Run Quick Scan", "View activity"} <= strings
    assert "start_quick_scan" in source and 'navigate_to("activity")' in source
    for forbidden in ("SHA-256", "incident ID", "session ID", "worker name"): assert forbidden not in source

def test_ux_refresh_phase2_view_activity_request_uses_message_bus():
    bus = UIMessageBus(); controller = AutoGuardUIController(_home_services(), bus)
    try:
        controller.navigate_to("activity"); messages = bus.drain()
        assert len(messages) == 1 and messages[0].kind == "navigate" and messages[0].payload["page"] == "activity"
    finally: controller.shutdown()