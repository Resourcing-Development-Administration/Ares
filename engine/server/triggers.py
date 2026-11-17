"""
triggers — Event-driven trigger rules that fire on task/finding events.
Port of ARTEX server/triggers.go.
"""
from __future__ import annotations

import asyncio
import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Awaitable


class TriggerEvent(str, Enum):
    TASK_STARTED = "task_started"
    TASK_COMPLETED = "task_completed"
    TASK_FAILED = "task_failed"
    FINDING_CREATED = "finding_created"
    FINDING_CONFIRMED = "finding_confirmed"
    INTENT_COMPLETED = "intent_completed"
    FACT_RECORDED = "fact_recorded"


@dataclass
class TriggerRule:
    id: str
    event: TriggerEvent
    condition: str              # simple expression: "severity=critical" etc.
    action: str                 # "notify", "spawn_task", "add_hint"
    action_params: dict = field(default_factory=dict)
    enabled: bool = True


TriggerHandler = Callable[[TriggerRule, dict], Awaitable[None]]


class TriggerEngine:
    """
    Evaluates trigger rules against incoming events and fires handlers.
    """

    def __init__(self):
        self._rules: list[TriggerRule] = []
        self._handlers: dict[str, TriggerHandler] = {}

    def add_rule(self, rule: TriggerRule) -> None:
        self._rules.append(rule)

    def remove_rule(self, rule_id: str) -> None:
        self._rules = [r for r in self._rules if r.id != rule_id]

    def register_handler(self, action: str, handler: TriggerHandler) -> None:
        self._handlers[action] = handler

    def _matches(self, rule: TriggerRule, payload: dict) -> bool:
        """Evaluate a simple condition expression against event payload."""
        if not rule.condition:
            return True
        # Simple k=v conditions
        for part in rule.condition.split("AND"):
            part = part.strip()
            if "=" in part:
                k, v = part.split("=", 1)
                if str(payload.get(k.strip(), "")).lower() != v.strip().lower():
                    return False
        return True

    async def fire(self, event: TriggerEvent, payload: dict) -> None:
        """Evaluate all matching rules for an event and invoke their handlers."""
        for rule in self._rules:
            if not rule.enabled:
                continue
            if rule.event != event:
                continue
            if not self._matches(rule, payload):
                continue
            handler = self._handlers.get(rule.action)
            if handler is not None:
                try:
                    await handler(rule, payload)
                except Exception:
                    pass


_engine: TriggerEngine | None = None


def init() -> TriggerEngine:
    global _engine
    _engine = TriggerEngine()
    return _engine


def get() -> TriggerEngine | None:
    return _engine
