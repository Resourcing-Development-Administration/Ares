"""
TaskClock — carries a task's absolute deadline into agent runs. Port of ARTEX agent/taskclock.go.
"""
from __future__ import annotations

import time
from dataclasses import dataclass


@dataclass
class TaskClock:
    """
    Carries a task-level absolute deadline. Zero/None = no task timeout.
    final=True means this is the coordinator-driven FINAL planner round.
    """
    deadline_unix: float = 0.0  # absolute deadline (unix seconds); 0 = no timeout
    final: bool = False          # coordinator-driven FINAL round


def clamp_max_duration(
    deadline_unix: float,
    own_budget_s: float,
) -> tuple[float, bool]:
    """
    Fold a task deadline into a run's own wall-clock budget.

    - own_budget_s: the agent's own run time in seconds (0 = unlimited).
    - Returns (eff_seconds, clamped) where clamped=True means the TASK deadline
      is the binding constraint. eff_seconds is floored at 1.0.
    """
    if deadline_unix <= 0:
        return own_budget_s, False

    remaining = deadline_unix - time.time()
    if remaining < 1.0:
        remaining = 1.0

    clamped = own_budget_s <= 0 or remaining <= own_budget_s
    eff = remaining
    if own_budget_s > 0 and own_budget_s < remaining:
        eff = own_budget_s

    return eff, clamped


def remaining_seconds(tc: TaskClock | None) -> float:
    """Return seconds remaining until the task deadline, or 0 if no deadline."""
    if tc is None or tc.deadline_unix <= 0:
        return 0.0
    r = tc.deadline_unix - time.time()
    return max(0.0, r)


def is_expired(tc: TaskClock | None) -> bool:
    """Return True if the task deadline has passed."""
    if tc is None or tc.deadline_unix <= 0:
        return False
    return time.time() >= tc.deadline_unix
