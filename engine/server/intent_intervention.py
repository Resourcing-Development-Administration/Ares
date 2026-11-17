"""
intent_intervention — User-triggered mid-run interventions on planner intents.
Port of ARTEX server/intent_intervention.go.
"""
from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class InterventionKind(str, Enum):
    ADD_HINT = "add_hint"       # inject a hint into the running planner
    KILL_INTENT = "kill_intent" # cancel a specific running intent
    PAUSE_TASK = "pause_task"   # pause all workers for a task
    RESUME_TASK = "resume_task" # resume a paused task
    REDIRECT = "redirect"       # change the focus of a running intent


@dataclass
class Intervention:
    kind: InterventionKind
    task_id: int
    intent_id: int = 0      # 0 = task-level (not intent-specific)
    payload: dict = field(default_factory=dict)


class InterventionBus:
    """
    Delivery bus for user-triggered mid-run interventions.
    One queue per task; planner/worker polls or awaits.
    """

    def __init__(self):
        self._queues: dict[int, asyncio.Queue] = {}
        self._lock = asyncio.Lock()

    async def _queue_for(self, task_id: int) -> asyncio.Queue:
        async with self._lock:
            if task_id not in self._queues:
                self._queues[task_id] = asyncio.Queue(maxsize=64)
            return self._queues[task_id]

    async def send(self, iv: Intervention) -> None:
        q = await self._queue_for(iv.task_id)
        try:
            q.put_nowait(iv)
        except asyncio.QueueFull:
            pass

    async def receive(self, task_id: int, timeout: float = 0.0) -> Intervention | None:
        q = await self._queue_for(task_id)
        try:
            if timeout > 0:
                return await asyncio.wait_for(q.get(), timeout=timeout)
            return q.get_nowait()
        except (asyncio.TimeoutError, asyncio.QueueEmpty):
            return None

    async def drain(self, task_id: int) -> list[Intervention]:
        """Drain all pending interventions for a task (non-blocking)."""
        q = await self._queue_for(task_id)
        result: list[Intervention] = []
        while True:
            try:
                result.append(q.get_nowait())
            except asyncio.QueueEmpty:
                break
        return result

    async def close(self, task_id: int) -> None:
        async with self._lock:
            self._queues.pop(task_id, None)


_bus: InterventionBus | None = None


def init() -> InterventionBus:
    global _bus
    _bus = InterventionBus()
    return _bus


def get() -> InterventionBus | None:
    return _bus
