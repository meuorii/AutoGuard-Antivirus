"""Shared user-facing protection-service state mapping.

This module translates existing service ``health()`` objects into one consistent
presentation state for Home, Settings, and the Windows system tray.  It does not
start, stop, or otherwise mutate protection services.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class ProtectionServiceState:
    available: bool
    running: bool
    status: str
    detail: str

    @property
    def healthy(self) -> bool:
        return self.status == "On"

    @property
    def degraded(self) -> bool:
        return self.status == "Needs attention"



def state_from_health(
    health: Any | None,
    *,
    available: bool = True,
    unavailable_label: str = "Unavailable",
    unavailable_detail: str = "This protection service is unavailable.",
) -> ProtectionServiceState:
    """Translate a service health object without inventing stronger state.

    ``running`` answers whether the service lifecycle is active.  ``status`` can
    still be ``Needs attention`` when the service is running but reports a
    degraded health condition.  This distinction is what keeps Home, Settings,
    and the tray from disagreeing about On/Off state.
    """
    if not available or health is None:
        return ProtectionServiceState(
            available=False,
            running=False,
            status=unavailable_label,
            detail=unavailable_detail,
        )

    running = bool(getattr(health, "running", False))
    raw_status = getattr(getattr(health, "status", None), "value", None)
    raw = str(raw_status).upper() if raw_status is not None else None
    last_error = getattr(health, "last_error", None)

    if not running or raw == "STOPPED":
        status = "Off"
    elif raw == "DEGRADED" or (raw is None and last_error):
        status = "Needs attention"
    else:
        status = "On"

    if last_error:
        detail = str(last_error)
    elif status == "On":
        detail = "Protection is active."
    elif status == "Needs attention":
        detail = "Protection is running, but one or more health checks need attention."
    else:
        detail = "Protection is currently stopped."

    return ProtectionServiceState(
        available=True,
        running=running,
        status=status,
        detail=detail,
    )


def state_from_service(
    service: Any | None,
    *,
    unavailable_label: str = "Unavailable",
    unavailable_detail: str = "This protection service is unavailable.",
) -> ProtectionServiceState:
    """Read ``service.health()`` and return the shared presentation state."""
    if service is None:
        return state_from_health(
            None,
            available=False,
            unavailable_label=unavailable_label,
            unavailable_detail=unavailable_detail,
        )
    try:
        health = service.health()
    except Exception as error:
        return ProtectionServiceState(
            available=False,
            running=False,
            status=unavailable_label,
            detail=f"Health check failed: {type(error).__name__}: {error}",
        )
    return state_from_health(
        health,
        unavailable_label=unavailable_label,
        unavailable_detail=unavailable_detail,
    )
