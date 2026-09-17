from __future__ import annotations

from contextlib import contextmanager
from pathlib import Path
from types import SimpleNamespace

from app.database import Database
from app.detector import Detector
from app.incidents import IncidentService
from app.models import ScanSource
from app.scanner import Scanner
from app.signatures import SignatureStore
from app.threat_trail import ThreatTrail


def test_incident_service_can_batch_list_details_without_n_plus_one(tmp_path):
    db = Database(tmp_path / "autoguard.db")
    db.initialize()
    service = IncidentService(db)
    sha = "a" * 64
    incident = service.create_incident(sha, tmp_path / "one.bin", ScanSource.MANUAL, "test")
    service.attach_matching_file(incident.id, tmp_path / "two.bin", ScanSource.MANUAL, "test")

    rows = service.list_incident_details(20)
    assert len(rows) == 1
    assert rows[0].incident.id == incident.id
    assert len(rows[0].files) == 2
    assert rows[0].events


def test_large_scan_reuses_database_connections_instead_of_opening_per_file(tmp_path):
    db = Database(tmp_path / "autoguard.db")
    db.initialize()
    scanner = Scanner(Detector(SignatureStore()), ThreatTrail(db))
    folder = tmp_path / "files"
    folder.mkdir()
    for index in range(40):
        (folder / f"{index}.txt").write_text(f"safe-{index}", encoding="utf-8")

    original = db.connection
    opens = 0

    @contextmanager
    def counted_connection():
        nonlocal opens
        opens += 1
        with original() as connection:
            yield connection

    db.connection = counted_connection  # type: ignore[method-assign]
    summary = scanner.scan_directory(folder)
    assert len(summary.results) == 40
    # Session start + two scan-lifetime connections + session finish + final
    # active-incident lookup should stay essentially constant, not 2x files.
    assert opens < 12


def test_performance_hotfix_uses_slow_fallback_refresh_and_targeted_scan_routing():
    source = (Path(__file__).resolve().parents[1] / "app/ui/main_window.py").read_text(encoding="utf-8")
    assert "PASSIVE_REFRESH_MS = 10000" in source
    assert 'message.kind in {"scan_discovered", "scan_result"}' in source
    assert 'recipients = (self.pages["scan"],)' in source


def test_threats_page_has_load_failure_retry_state():
    source = (Path(__file__).resolve().parents[1] / "app/ui/threats_page.py").read_text(encoding="utf-8")
    assert 'message.kind == "task_failed"' in source
    assert 'text="Threat data could not be loaded"' in source
    assert 'text="Retry"' in source
