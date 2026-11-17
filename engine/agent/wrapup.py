"""
Wrap-up prompt management — per-agent defaults + DB-override hooks.
Port of ARTEX agent/wrapup.go.
"""
from __future__ import annotations

import threading
from typing import Callable

_lock = threading.RLock()
_wrapup_override: Callable[[str], tuple[str, bool]] | None = None
_wrapup_turns_override: Callable[[str], tuple[int, bool]] | None = None
_task_timeout_override: Callable[[str], tuple[str, bool]] | None = None
_task_timeout_turns_override: Callable[[str], tuple[int, bool]] | None = None


# ── Built-in defaults ─────────────────────────────────────────────────────────

SETTLE_WRAPUP_PROMPT = (
    "Your turn budget is about to run out. "
    "First write back all completed-but-unpersisted results (findings, facts, assets). "
    "Then summarize in a single standalone sentence of plain text what you found "
    "and which key conclusions you reached."
)

PLANNER_WRAPUP_DEFAULT = (
    "Your turn budget for THIS planning round is about to run out — note that only "
    "[this round] ends; the system will wake you again. Land the conclusions this "
    "round has already figured out: (1) submit exploration directions due for dispatch "
    "now with one add_intent batch call; (2) for goals proven met, call prove_goal; "
    "(3) record serial exploit chains with TodoWrite. Finish the round directly when "
    "done; no summary text needed."
)

MAINAGENT_WRAPUP_DEFAULT = (
    "Your turn budget is about to run out and this interaction is about to end. "
    "Do not start any new exploration. Summarize for the user in a single standalone "
    "sentence of plain text: current progress, key conclusions, and the suggested next step."
)

GENERIC_WRAPUP_DEFAULT = (
    "You are about to be terminated because your budget is exhausted. "
    "First write back completed-but-unpersisted results, then summarize in a single "
    "standalone sentence of plain text what you did and which key conclusions you reached."
)

WORKER_TASK_TIMEOUT_DEFAULT = (
    "**The entire task has reached its timeout limit and is about to end** "
    "(not your run's budget — the whole engagement is out of time). "
    "This is the last chance: (1) write back ALL content you've identified but not yet "
    "persisted — new assets, exploration facts, confirmed findings; (2) do not start any "
    "new commands or probes; (3) summarize in a single standalone sentence of plain text "
    "your key conclusions on this intent."
)

PLANNER_TASK_TIMEOUT_DEFAULT = (
    "**The entire task has reached its timeout limit and is about to end** "
    "(not this round — the whole task terminates). Based on the current full set of "
    "facts and findings, make the final goal judgment: for goals proven met by evidence, "
    "call prove_goal. **Do not generate any new intents** (any intent dispatched now "
    "won't be executed). Conclude once judged; no summary text needed."
)

_WRAPUP_DEFAULTS: dict[str, str] = {
    "worker":    SETTLE_WRAPUP_PROMPT,
    "planner":   PLANNER_WRAPUP_DEFAULT,
    "mainagent": MAINAGENT_WRAPUP_DEFAULT,
}

_WRAPUP_TURNS_DEFAULTS: dict[str, int] = {
    "worker": 10, "planner": 10, "mainagent": 10,
}

_TASK_TIMEOUT_DEFAULTS: dict[str, str] = {
    "worker":  WORKER_TASK_TIMEOUT_DEFAULT,
    "planner": PLANNER_TASK_TIMEOUT_DEFAULT,
}

GENERIC_WRAPUP_TURNS = 10


# ── Hook setters ──────────────────────────────────────────────────────────────

def set_wrapup_override(f: Callable[[str], tuple[str, bool]] | None) -> None:
    global _wrapup_override
    with _lock:
        _wrapup_override = f


def set_wrapup_turns_override(f: Callable[[str], tuple[int, bool]] | None) -> None:
    global _wrapup_turns_override
    with _lock:
        _wrapup_turns_override = f


def set_task_timeout_override(f: Callable[[str], tuple[str, bool]] | None) -> None:
    global _task_timeout_override
    with _lock:
        _task_timeout_override = f


def set_task_timeout_turns_override(f: Callable[[str], tuple[int, bool]] | None) -> None:
    global _task_timeout_turns_override
    with _lock:
        _task_timeout_turns_override = f


# ── Defaults ──────────────────────────────────────────────────────────────────

def wrapup_default(agent_key: str) -> str:
    return _WRAPUP_DEFAULTS.get(agent_key, GENERIC_WRAPUP_DEFAULT)


def wrapup_turns_default(agent_key: str) -> int:
    return _WRAPUP_TURNS_DEFAULTS.get(agent_key, GENERIC_WRAPUP_TURNS)


def task_timeout_default(agent_key: str) -> str:
    return _TASK_TIMEOUT_DEFAULTS.get(agent_key, "")


# ── Resolvers ─────────────────────────────────────────────────────────────────

def resolve_wrapup(agent_key: str) -> str:
    with _lock:
        ovr = _wrapup_override
    if ovr is not None:
        try:
            text, ok = ovr(agent_key)
            if ok and text.strip():
                return text
        except Exception:
            pass
    return wrapup_default(agent_key)


def resolve_wrapup_turns(agent_key: str) -> int:
    with _lock:
        ovr = _wrapup_turns_override
    if ovr is not None:
        try:
            v, ok = ovr(agent_key)
            if ok and v > 0:
                return v
        except Exception:
            pass
    return wrapup_turns_default(agent_key)


def resolve_task_timeout_wrapup(agent_key: str) -> str:
    with _lock:
        ovr = _task_timeout_override
    if ovr is not None:
        try:
            text, ok = ovr(agent_key)
            if ok and text.strip():
                return text
        except Exception:
            pass
    return task_timeout_default(agent_key)


def resolve_task_timeout_turns(agent_key: str) -> int:
    with _lock:
        ovr = _task_timeout_turns_override
    if ovr is not None:
        try:
            v, ok = ovr(agent_key)
            if ok and v > 0:
                return v
        except Exception:
            pass
    return resolve_wrapup_turns(agent_key)


def build_settlement(agent_key: str, disabled_tools: list[str] | None = None) -> dict:
    """Build the settlement config for an agent run."""
    return {
        "prompt": resolve_wrapup(agent_key),
        "disabled_tools": disabled_tools or [],
        "max_turns": resolve_wrapup_turns(agent_key),
    }


def build_settlement_for_task(
    agent_key: str,
    disabled_tools: list[str] | None = None,
    clamped: bool = False,
) -> dict:
    """
    Build settlement for a worker/planner run that is aware of the task deadline.
    clamped=True means this run is bounded by the task deadline.
    """
    per_run = resolve_wrapup(agent_key)
    base = {
        "prompt": per_run,
        "disabled_tools": disabled_tools or [],
        "max_turns": resolve_wrapup_turns(agent_key),
    }
    if clamped:
        tt = resolve_task_timeout_wrapup(agent_key)
        if tt:
            base["prompt_by_reason"] = {
                "timeout": tt,
                "max_turns": per_run,
            }
            base["max_turns"] = resolve_task_timeout_turns(agent_key)
    return base
