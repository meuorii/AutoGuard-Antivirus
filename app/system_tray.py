"""Windows system-tray integration for AutoGuard.

The tray is a presentation shell only. It never constructs scanners, monitors,
schedulers, databases, or antivirus services. It reads health from the shared
``AutoGuardServices`` instance and queues user actions for the Tk main thread.
"""
from __future__ import annotations

import os
import queue
import threading
from dataclasses import dataclass
from datetime import datetime
from enum import Enum
from typing import Any, Callable

from app.logging_config import application_logger
from app.protection_state import state_from_health, state_from_service
from app.resources import autoguard_logo_path
from app.startup import AutoGuardServices


class TrayAction(str, Enum):
    OPEN = "open"
    QUICK_SCAN = "quick_scan"
    EXIT = "exit"


@dataclass(frozen=True)
class TrayStatus:
    real_time: str
    usb: str
    scheduled: str
    quick_scan_running: bool
    full_scan_running: bool
    next_quick_scan: datetime | None
    next_full_scan: datetime | None

    @property
    def protection(self) -> str:
        states = (self.real_time, self.usb, self.scheduled)
        if any(value in {"Off", "Unavailable"} for value in states):
            return "Protection issue"
        if any(value == "Needs attention" for value in states):
            return "Needs attention"
        return "On"


class SystemTray:
    """Own one Windows notification-area icon and queue actions for Tk.

    ``pystray`` callbacks execute on the tray thread. They never call Tk APIs
    directly. Instead, callbacks enqueue :class:`TrayAction` values, and
    ``MainWindow`` drains them on the Tk main thread.
    """

    def __init__(
        self,
        services: AutoGuardServices,
        *,
        enabled: bool = True,
        platform_name: str | None = None,
        icon_factory: Callable[["SystemTray"], Any] | None = None,
    ) -> None:
        self.services = services
        self.enabled = bool(enabled)
        self.platform_name = os.name if platform_name is None else platform_name
        self._icon_factory = icon_factory
        self._actions: queue.Queue[TrayAction] = queue.Queue()
        self._lock = threading.RLock()
        self._icon: Any | None = None
        self._thread: threading.Thread | None = None
        self._running = False
        self._last_error: str | None = None

    @property
    def running(self) -> bool:
        with self._lock:
            return self._running

    @property
    def last_error(self) -> str | None:
        with self._lock:
            return self._last_error

    def start(self) -> bool:
        """Start the tray icon once. Returns False when unavailable/disabled."""
        with self._lock:
            if self._running:
                return True
            if not self.enabled or (self.platform_name != "nt" and self._icon_factory is None):
                return False
        try:
            icon = self._icon_factory(self) if self._icon_factory is not None else self._create_windows_icon()
        except Exception as error:
            with self._lock:
                self._last_error = f"{type(error).__name__}: {error}"
            application_logger().warning("System tray unavailable: %s", self._last_error)
            return False

        thread = threading.Thread(
            target=self._run_icon,
            args=(icon,),
            name="AutoGuardSystemTray",
            daemon=True,
        )
        with self._lock:
            self._icon = icon
            self._thread = thread
            self._running = True
            self._last_error = None
        thread.start()
        return True

    def stop(self, *, timeout: float = 2.0) -> None:
        """Stop only the tray presentation thread; backend shutdown stays elsewhere."""
        if timeout < 0:
            raise ValueError("timeout must be nonnegative.")
        with self._lock:
            icon = self._icon
            thread = self._thread
            self._running = False
            self._icon = None
            self._thread = None
        if icon is not None:
            try:
                icon.stop()
            except Exception as error:
                application_logger().warning("System tray stop failed: %s: %s", type(error).__name__, error)
        if thread is not None and thread is not threading.current_thread():
            thread.join(timeout=timeout)

    def refresh_menu(self) -> None:
        """Ask the tray backend to re-evaluate dynamic menu labels."""
        with self._lock:
            icon = self._icon
        if icon is None:
            return
        updater = getattr(icon, "update_menu", None)
        if callable(updater):
            try:
                updater()
            except Exception:
                # Menu refresh is best-effort and must never affect protection.
                pass

    def request(self, action: TrayAction | str) -> None:
        self._actions.put(TrayAction(action))

    def drain_actions(self, limit: int = 20) -> tuple[TrayAction, ...]:
        if type(limit) is not int or limit <= 0:
            raise ValueError("limit must be a positive integer.")
        result: list[TrayAction] = []
        for _ in range(limit):
            try:
                result.append(self._actions.get_nowait())
            except queue.Empty:
                break
        return tuple(result)

    def status_snapshot(self) -> TrayStatus:
        file_state = self._service_state(self.services.file_monitor)
        usb_state = self._service_state(self.services.usb_monitor)
        try:
            scheduler_health = self.services.scheduler.health()
            scheduled = state_from_health(scheduler_health).status
            quick_running = bool(getattr(scheduler_health, "quick_scan_running", False))
            full_running = bool(getattr(scheduler_health, "full_scan_running", False))
        except Exception:
            scheduled = "Unavailable"
            quick_running = False
            full_running = False

        next_times = {"quick": None, "full": None}
        getter = getattr(self.services.scheduler, "next_run_times", None)
        if callable(getter):
            try:
                value = getter()
                if isinstance(value, dict):
                    next_times.update(value)
            except Exception:
                pass

        return TrayStatus(
            real_time=file_state,
            usb=usb_state,
            scheduled=scheduled,
            quick_scan_running=quick_running,
            full_scan_running=full_running,
            next_quick_scan=next_times.get("quick"),
            next_full_scan=next_times.get("full"),
        )

    @staticmethod
    def _service_state(service: Any | None) -> str:
        return state_from_service(service).status

    @staticmethod
    def _format_next(value: datetime | None) -> str:
        if value is None:
            return "Not scheduled"
        try:
            local = value.astimezone() if value.tzinfo is not None else value
            return local.strftime("%b %d, %I:%M %p").replace(" 0", " ")
        except Exception:
            return "Scheduled"

    def _run_icon(self, icon: Any) -> None:
        try:
            icon.run()
        except Exception as error:
            with self._lock:
                self._last_error = f"{type(error).__name__}: {error}"
            application_logger().warning("System tray runtime failed: %s", self._last_error)
        finally:
            with self._lock:
                if self._icon is icon:
                    self._running = False
                    self._icon = None
                    self._thread = None

    def _create_windows_icon(self) -> Any:
        try:
            import pystray
            from PIL import Image
        except ImportError as error:
            raise RuntimeError(
                "System tray dependencies are missing. Install requirements.txt."
            ) from error

        image = Image.open(autoguard_logo_path()).convert("RGBA")
        image.thumbnail((64, 64), Image.Resampling.LANCZOS)
        tray_image = Image.new("RGBA", (64, 64), (0, 0, 0, 0))
        tray_image.alpha_composite(
            image, ((64 - image.width) // 2, (64 - image.height) // 2)
        )
        image = tray_image

        def disabled(text_provider: Callable[[], str]):
            return pystray.MenuItem(
                lambda _item: text_provider(),
                lambda _icon, _item: None,
                enabled=False,
            )

        menu = pystray.Menu(
            pystray.MenuItem("Open AutoGuard", lambda _icon, _item: self.request(TrayAction.OPEN), default=True),
            pystray.Menu.SEPARATOR,
            disabled(lambda: f"Protection: {self.status_snapshot().protection}"),
            disabled(lambda: f"Real-time protection: {self.status_snapshot().real_time}"),
            disabled(lambda: f"USB protection: {self.status_snapshot().usb}"),
            disabled(lambda: f"Scheduled scanning: {self.status_snapshot().scheduled}"),
            pystray.Menu.SEPARATOR,
            disabled(lambda: f"Next Quick Scan: {self._format_next(self.status_snapshot().next_quick_scan)}"),
            disabled(lambda: f"Next Full Scan: {self._format_next(self.status_snapshot().next_full_scan)}"),
            pystray.Menu.SEPARATOR,
            pystray.MenuItem(
                lambda _item: "Quick Scan running…" if self.status_snapshot().quick_scan_running else "Run Quick Scan",
                lambda _icon, _item: self.request(TrayAction.QUICK_SCAN),
                enabled=lambda _item: not self.status_snapshot().quick_scan_running,
            ),
            pystray.Menu.SEPARATOR,
            pystray.MenuItem("Exit AutoGuard", lambda _icon, _item: self.request(TrayAction.EXIT)),
        )
        return pystray.Icon("AutoGuard", image, "AutoGuard", menu)