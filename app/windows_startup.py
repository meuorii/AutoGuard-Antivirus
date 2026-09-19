"""Windows sign-in startup integration for AutoGuard.

AutoGuard uses the current user's ``Run`` registry key so enabling startup does
not require administrator privileges.  The registered command always starts the
same application with ``--start-hidden`` so protection initializes normally
while the main window stays in the system tray.
"""
from __future__ import annotations

import os
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol


RUN_KEY = r"Software\Microsoft\Windows\CurrentVersion\Run"
VALUE_NAME = "AutoGuard"
START_HIDDEN_ARGUMENT = "--start-hidden"


class StartupRegistry(Protocol):
    def read(self, name: str) -> str | None: ...
    def write(self, name: str, value: str) -> None: ...
    def delete(self, name: str) -> None: ...


class WinRegStartupRegistry:
    """Small HKCU registry adapter, imported lazily for cross-platform tests."""

    def read(self, name: str) -> str | None:
        import winreg

        try:
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, RUN_KEY, 0, winreg.KEY_READ) as key:
                value, _ = winreg.QueryValueEx(key, name)
                return str(value)
        except FileNotFoundError:
            return None

    def write(self, name: str, value: str) -> None:
        import winreg

        with winreg.CreateKeyEx(
            winreg.HKEY_CURRENT_USER,
            RUN_KEY,
            0,
            winreg.KEY_SET_VALUE,
        ) as key:
            winreg.SetValueEx(key, name, 0, winreg.REG_SZ, value)

    def delete(self, name: str) -> None:
        import winreg

        try:
            with winreg.OpenKey(
                winreg.HKEY_CURRENT_USER,
                RUN_KEY,
                0,
                winreg.KEY_SET_VALUE,
            ) as key:
                winreg.DeleteValue(key, name)
        except FileNotFoundError:
            return


@dataclass(frozen=True)
class WindowsStartupState:
    available: bool
    enabled: bool
    status: str
    detail: str
    command: str | None = None


class WindowsStartupManager:
    """Read and update AutoGuard's per-user Windows startup registration."""

    def __init__(
        self,
        *,
        platform_name: str | None = None,
        registry: StartupRegistry | None = None,
        executable: Path | None = None,
        source_entry: Path | None = None,
        frozen: bool | None = None,
    ) -> None:
        self.platform_name = os.name if platform_name is None else platform_name
        self.registry = registry
        self.executable = Path(sys.executable if executable is None else executable)
        self.source_entry = (
            Path(__file__).resolve().parents[1] / "main.py"
            if source_entry is None
            else Path(source_entry)
        )
        self.frozen = bool(getattr(sys, "frozen", False)) if frozen is None else bool(frozen)

    @property
    def available(self) -> bool:
        return self.platform_name == "nt"

    def startup_command(self) -> str:
        r"""Return the exact command stored in HKCU\...\Run.

        Packaged builds register only ``AutoGuard.exe --start-hidden``. Source
        runs remain testable by registering the current Python interpreter plus
        ``main.py`` and the same hidden-start switch.
        """
        if self.frozen:
            argv = [str(self.executable), START_HIDDEN_ARGUMENT]
        else:
            argv = [str(self.executable), str(self.source_entry), START_HIDDEN_ARGUMENT]
        return subprocess.list2cmdline(argv)

    def _registry(self) -> StartupRegistry:
        if self.registry is not None:
            return self.registry
        if not self.available:
            raise RuntimeError("Windows startup is only available on Windows.")
        self.registry = WinRegStartupRegistry()
        return self.registry

    def state(self) -> WindowsStartupState:
        if not self.available:
            return WindowsStartupState(
                available=False,
                enabled=False,
                status="Unavailable",
                detail="Start with Windows is available only on Windows.",
            )

        try:
            value = self._registry().read(VALUE_NAME)
        except Exception as error:
            return WindowsStartupState(
                available=False,
                enabled=False,
                status="Unavailable",
                detail=f"Windows startup state could not be read: {type(error).__name__}: {error}",
            )

        if value is None:
            return WindowsStartupState(
                available=True,
                enabled=False,
                status="Off",
                detail="AutoGuard will not start automatically when you sign in to Windows.",
            )

        expected = self.startup_command()
        if value.strip() == expected.strip():
            detail = "AutoGuard starts automatically in the system tray when you sign in to Windows."
        else:
            # An existing AutoGuard entry still means Windows will attempt to
            # launch it. Enabling again refreshes it to the current executable.
            detail = "AutoGuard has a Windows startup entry. Turning this setting on again refreshes it to the current application path."
        return WindowsStartupState(
            available=True,
            enabled=True,
            status="On",
            detail=detail,
            command=value,
        )

    def set_enabled(self, enabled: bool) -> WindowsStartupState:
        if not self.available:
            raise RuntimeError("Start with Windows is unavailable on this platform.")

        registry = self._registry()
        if enabled:
            registry.write(VALUE_NAME, self.startup_command())
        else:
            registry.delete(VALUE_NAME)

        state = self.state()
        if state.enabled != bool(enabled):
            raise RuntimeError(
                f"Windows startup could not be {'enabled' if enabled else 'disabled'} safely."
            )
        return state
