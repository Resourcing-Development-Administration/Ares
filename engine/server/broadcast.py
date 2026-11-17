"""
Broadcaster — per-task pub/sub for live activity events.
Port of ARTEX server/broadcast.go.
"""
from __future__ import annotations

import asyncio
from collections import defaultdict
from typing import Any


class Broadcaster:
    """
    Per-task pub/sub for live activity events.
    The engine publishes each activity at its single emit point;
    SSE/WebSocket handlers subscribe per task.
    """

    def __init__(self, buffer_size: int = 256):
        self._buffer_size = buffer_size
        self._lock = asyncio.Lock()
        self._subs: dict[str, set[asyncio.Queue]] = defaultdict(set)

    async def subscribe(self, task_id: str) -> asyncio.Queue:
        """
        Subscribe to activities for a task. Returns a queue.
        Call unsubscribe() when done to avoid queue leaks.
        """
        q: asyncio.Queue = asyncio.Queue(maxsize=self._buffer_size)
        async with self._lock:
            self._subs[task_id].add(q)
        return q

    async def unsubscribe(self, task_id: str, q: asyncio.Queue) -> None:
        async with self._lock:
            subs = self._subs.get(task_id)
            if subs:
                subs.discard(q)
                if not subs:
                    del self._subs[task_id]

    async def publish(self, task_id: str, activity: dict[str, Any]) -> None:
        """
        Fan an activity out to all subscribers of a task.
        Non-blocking: drops the event if a subscriber's buffer is full —
        the client reconnects with its last cursor and catches up from DB.
        """
        async with self._lock:
            subs = set(self._subs.get(task_id, ()))
        for q in subs:
            try:
                q.put_nowait(activity)
            except asyncio.QueueFull:
                pass  # client will catch up on reconnect

    async def publish_all(self, activity: dict[str, Any]) -> None:
        """Broadcast to ALL task subscribers (e.g. global system events)."""
        async with self._lock:
            all_subs = {q for qs in self._subs.values() for q in qs}
        for q in all_subs:
            try:
                q.put_nowait(activity)
            except asyncio.QueueFull:
                pass

    def subscriber_count(self, task_id: str | None = None) -> int:
        if task_id:
            return len(self._subs.get(task_id, ()))
        return sum(len(v) for v in self._subs.values())


# Module-level singleton
_broadcaster: Broadcaster | None = None


def init(buffer_size: int = 256) -> Broadcaster:
    global _broadcaster
    _broadcaster = Broadcaster(buffer_size)
    return _broadcaster


def get() -> Broadcaster | None:
    return _broadcaster
