from pathlib import Path

from app.logging_config import application_logger, configure_production_logging, monitor_logger, scanner_logger, shutdown_production_logging
from app.signatures import AUTOGUARD_TEST_SHA256, load_signatures


def test_production_logging_creates_separate_rotating_logs(tmp_path):
    paths = configure_production_logging(tmp_path / "logs")
    application_logger().info("application ready"); scanner_logger().warning("scanner evidence"); monitor_logger().error("monitor failure")
    shutdown_production_logging()
    assert set(paths) == {"application", "scanner", "monitor", "error"}
    assert "application ready" in paths["application"].read_text(encoding="utf-8")
    assert "scanner evidence" in paths["scanner"].read_text(encoding="utf-8")
    assert "monitor failure" in paths["monitor"].read_text(encoding="utf-8")
    assert "monitor failure" in paths["error"].read_text(encoding="utf-8")


def test_packaging_configuration_bundles_signatures_and_keeps_runtime_data_external():
    root = Path(__file__).resolve().parents[1]; spec = (root / "AutoGuard.spec").read_text(encoding="utf-8"); config = (root / "app/config.py").read_text(encoding="utf-8")
    assert "data/signatures.json" in spec.replace("\\\\", "/") or "signatures.json" in spec
    assert "customtkinter" in spec and "collect_data_files" in spec
    assert 'Path.home() / "AutoGuardData"' in config
    store = load_signatures(); assert store.lookup(AUTOGUARD_TEST_SHA256) is not None