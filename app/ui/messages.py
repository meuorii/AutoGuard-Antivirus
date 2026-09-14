from __future__ import annotations

import queue
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any


@dataclass(frozen=True)
class UIMessage:
    kind: str
    payload: dict[str, Any] = field(default_factory=dict)
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


class UIMessageBus:
    """Small FIFO queue safe for producers on arbitrary worker threads."""

    def __init__(self) -> None: self._queue: queue.Queue[UIMessage] = queue.Queue()

    def publish(self, kind: str, **payload: Any) -> UIMessage:
        if not kind or not kind.strip(): raise ValueError("UI message kind must not be empty.")
        message = UIMessage(kind.strip(), dict(payload)); self._queue.put(message); return message

    def drain(self, limit: int = 200) -> list[UIMessage]:
        if type(limit) is not int or limit <= 0: raise ValueError("limit must be a positive integer.")
        messages: list[UIMessage] = []
        for _ in range(limit):
            try: messages.append(self._queue.get_nowait())
            except queue.Empty: break
        return messages

    def pending(self) -> int: return self._queue.qsize()