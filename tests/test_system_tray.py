from __future__ import annotations

import threading
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

from app.system_tray import SystemTray, TrayAction


class FakeHealthService:
    def __init__(self, running: bool):
        self.running = running

    def health(self):
        return SimpleNamespace(running=self.running)


class FakeScheduler:
    def __init__(self, quick, full, *, running=True, quick_running=False, full_running=False):
        self._times = {"quick": quick, "full": full}
        self._health = SimpleNamespace(
            running=running,
            quick_scan_running=quick_running,
            full_scan_running=full_running,
        )

    def health(self):
        return self._health

    def next_run_times(self):
        return dict(self._times)


class FakeIcon:
    def __init__(self):
        self.stopped = threading.Event()
        self.started = threading.Event()
        self.update_calls = 0

    def run(self):
        self.started.set()
        self.stopped.wait(2.0)

    def stop(self):
        self.stopped.set()

    def update_menu(self):
        self.update_calls += 1


def services(*, realtime=True, usb=True, scheduled=True):
    now = datetime.now(timezone.utc)
    return SimpleNamespace(
        file_monitor=FakeHealthService(realtime),
        usb_monitor=FakeHealthService(usb),
        scheduler=FakeScheduler(now + timedelta(hours=2), now + timedelta(days=3), running=scheduled),
    )


def test_tray_status_reads_existing_service_health_and_schedule():
    tray = SystemTray(services(), platform_name="nt", enabled=True, icon_factory=lambda _: FakeIcon())
    status = tray.status_snapshot()
    assert status.protection == "On"
    assert status.real_time == "On"
    assert status.usb == "On"
    assert status.scheduled == "On"
    assert status.next_quick_scan is not None
    assert status.next_full_scan is not None


def test_tray_actions_are_queued_for_tk_main_thread():
    tray = SystemTray(services(), platform_name="nt", enabled=True, icon_factory=lambda _: FakeIcon())
    tray.request(TrayAction.OPEN)
    tray.request(TrayAction.QUICK_SCAN)
    tray.request(TrayAction.EXIT)
    assert tray.drain_actions() == (
        TrayAction.OPEN,
        TrayAction.QUICK_SCAN,
        TrayAction.EXIT,
    )
    assert tray.drain_actions() == ()


def test_tray_start_stop_is_idempotent_and_does_not_touch_backend_services():
    icon = FakeIcon()
    current = services()
    tray = SystemTray(current, platform_name="nt", enabled=True, icon_factory=lambda _: icon)
    assert tray.start() is True
    assert icon.started.wait(1.0)
    assert tray.start() is True
    tray.refresh_menu()
    assert icon.update_calls == 1
    tray.stop(timeout=1.0)
    assert icon.stopped.is_set()
    assert not tray.running
    # The tray only read health; it has no start/stop methods for these services.
    assert current.file_monitor.running is True
    assert current.usb_monitor.running is True


def test_tray_is_not_started_when_disabled():
    tray = SystemTray(services(), platform_name="nt", enabled=False, icon_factory=lambda _: FakeIcon())
    assert tray.start() is False
    assert not tray.running


def test_main_window_close_contract_hides_to_tray_and_has_explicit_exit():
    from pathlib import Path

    source = (Path(__file__).resolve().parents[1] / "app" / "ui" / "main_window.py").read_text(encoding="utf-8")
    assert 'self.protocol("WM_DELETE_WINDOW", self._handle_window_close)' in source
    assert "self.withdraw()" in source
    assert "TrayAction.EXIT" in source
    assert "self.tray.stop" in source
