"""Runtime resource paths and Windows shell identity for AutoGuard."""
from __future__ import annotations

import os
import sys
from pathlib import Path


WINDOWS_APP_USER_MODEL_ID = "AutoGuard.Desktop"


def resource_root() -> Path:
    """Return the project/bundled resource root without changing runtime data paths."""
    bundled = getattr(sys, "_MEIPASS", None)
    if bundled:
        return Path(bundled)
    return Path(__file__).resolve().parents[1]


def resource_path(*parts: str) -> Path:
    return resource_root().joinpath(*parts)


def autoguard_logo_path() -> Path:
    return resource_path("assets", "autoguard_logo.png")


def autoguard_icon_path() -> Path:
    return resource_path("assets", "autoguard.ico")


def configure_windows_app_identity(
    app_id: str = WINDOWS_APP_USER_MODEL_ID, *, platform_name: str | None = None,
) -> bool:
    platform = os.name if platform_name is None else platform_name
    if platform != "nt":
        return False
    try:
        import ctypes

        ctypes.windll.shell32.SetCurrentProcessExplicitAppUserModelID(str(app_id))
        return True
    except Exception:
        return False