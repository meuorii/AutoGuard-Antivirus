from __future__ import annotations
import logging
from logging.handlers import RotatingFileHandler
from pathlib import Path

_FORMAT = "%(asctime)s %(levelname)s %(name)s [%(threadName)s] %(message)s"
_MAX_BYTES = 5 * 1024 * 1024; _BACKUPS = 3


def _handler(path: Path, level: int = logging.INFO) -> RotatingFileHandler:
    handler = RotatingFileHandler(path, maxBytes=_MAX_BYTES, backupCount=_BACKUPS, encoding="utf-8")
    handler.setLevel(level); handler.setFormatter(logging.Formatter(_FORMAT)); return handler


def _reset_logger(name: str, level: int, handlers: list[logging.Handler]) -> logging.Logger:
    logger = logging.getLogger(name); logger.setLevel(level); logger.propagate = False
    for old in tuple(logger.handlers): old.close(); logger.removeHandler(old)
    for handler in handlers: logger.addHandler(handler)
    return logger


def configure_production_logging(logs_dir: str | Path) -> dict[str, Path]:
    root = Path(logs_dir).expanduser(); root.mkdir(parents=True, exist_ok=True)
    paths = {
        "application": root / "application.log",
        "scanner": root / "scanner.log",
        "monitor": root / "monitor.log",
        "error": root / "error.log",
    }
    error_handler = _handler(paths["error"], logging.ERROR)
    _reset_logger("autoguard.application", logging.INFO, [_handler(paths["application"]), error_handler])
    _reset_logger("autoguard.scanner", logging.INFO, [_handler(paths["scanner"]), _handler(paths["error"], logging.ERROR)])
    _reset_logger("autoguard.monitor", logging.INFO, [_handler(paths["monitor"]), _handler(paths["error"], logging.ERROR)])
    return paths


def application_logger() -> logging.Logger: return logging.getLogger("autoguard.application")
def scanner_logger() -> logging.Logger: return logging.getLogger("autoguard.scanner")
def monitor_logger() -> logging.Logger: return logging.getLogger("autoguard.monitor")


def shutdown_production_logging() -> None:
    """Flush and close AutoGuard-owned handlers (important on Windows)."""
    for name in ("autoguard.application", "autoguard.scanner", "autoguard.monitor"):
        logger = logging.getLogger(name)
        for handler in tuple(logger.handlers):
            try: handler.flush(); handler.close()
            finally: logger.removeHandler(handler)