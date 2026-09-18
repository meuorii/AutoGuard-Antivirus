"""Runtime resource paths for source and PyInstaller builds."""
from __future__ import annotations

import sys
from pathlib import Path


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
