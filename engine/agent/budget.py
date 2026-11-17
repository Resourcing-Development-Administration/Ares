"""
Hierarchical run budgets — port of ARTEX/agent/budget.go.

Two levels: task (whole scan) → intent (one worker round).
A child's effective budget = min(its own cap, parent's remaining above wrap-up reserve).

Env vars:
  ARES_TASK_BUDGET_TOKENS    int (0 = unlimited)
  ARES_TASK_BUDGET_TURNS     int (0 = unlimited)
  ARES_INTENT_BUDGET_TOKENS  int (0 = unlimited)
  ARES_INTENT_BUDGET_TURNS   int (0 = unlimited)
"""
from __future__ import annotations

import os
import threading
from dataclasses import dataclass, field

UNLIMITED: int = 2**62

BUDGET_MARGIN_PERCENT: int = 5
BUDGET_MARGIN_MIN_TOKENS: int = 20_000
BUDGET_MARGIN_MIN_TURNS: int = 2
DEFAULT_WORKER_ESTIMATE_TOKENS: int = 50_000
DEFAULT_WORKER_ESTIMATE_TURNS: int = 10

WRAPUP_PASSTHROUGH = frozenset(
    {"record_fact", "insert_assets", "report_finding", "update_finding_report", "record_coverage"}
)

WORKER_BUDGET_WRAPUP = (
    "[Budget reached] This intent's token/turn budget is used up; the tool call was not executed. "
    "Do not run any more commands or probes. Write back what you identified but have not persisted yet "
    "(insert_assets, record_fact, report_finding), then, in a single standalone sentence of plain text, "
    "summarize what you did and your key conclusions."
)

TASK_BUDGET_WRAPUP = (
    "**The task's token/turn budget is exhausted and the task is about to end** (a normal end, not an error). "
    "Based on the current facts and findings, make the final goal judgment. "
    "**Do not generate any new intents** (they will not be executed). "
    "Then, in a single standalone sentence of plain text, summarize where the task stands."
)


def WRAPUP_BLOCKS_TOOL(tool_name: str) -> bool:
    return tool_name not in WRAPUP_PASSTHROUGH


@dataclass
class Budget:
    tokens: int = UNLIMITED
    turns: int = UNLIMITED

    def remaining(self, spent: "Spend") -> "Budget":
        return Budget(
            tokens=max(self.tokens - spent.tokens, 0) if self.tokens != UNLIMITED else UNLIMITED,
            turns=max(self.turns - spent.turns, 0) if self.turns != UNLIMITED else UNLIMITED,
        )

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, Budget):
            return NotImplemented
        return self.tokens == other.tokens and self.turns == other.turns


@dataclass
class Spend:
    tokens: int = 0
    turns: int = 0

    def add(self, tokens: int, turns: int = 1) -> "Spend":
        return Spend(self.tokens + tokens, self.turns + turns)


def _budget_cap(n: int) -> int:
    return UNLIMITED if n <= 0 else n


def wrapup_margin(task: Budget) -> Budget:
    def _margin(capacity: int, floor: int) -> int:
        if capacity == UNLIMITED:
            return 0
        return max(capacity * BUDGET_MARGIN_PERCENT // 100, floor)
    return Budget(
        tokens=_margin(task.tokens, BUDGET_MARGIN_MIN_TOKENS),
        turns=_margin(task.turns, BUDGET_MARGIN_MIN_TURNS),
    )


def _effective_budget(own: Budget, parent_remaining: Budget) -> Budget:
    return Budget(
        tokens=min(own.tokens, parent_remaining.tokens),
        turns=min(own.turns, parent_remaining.turns),
    )


def _left(capacity: int, spent: int) -> int:
    if capacity == UNLIMITED:
        return UNLIMITED
    return max(capacity - spent, 0)


@dataclass
class BudgetState:
    task: Budget
    remaining: Budget
    margin: Budget
    spent: Spend
    estimate: Spend
    at_margin: bool
    dispatch: bool  # may start another worker round

    def line(self) -> str:
        def _of(rem: int, cap: int) -> str:
            return "unlimited" if cap == UNLIMITED else f"{rem} of {cap}"
        return (
            f"[Task budget] remaining: tokens {_of(self.remaining.tokens, self.task.tokens)}, "
            f"turns {_of(self.remaining.turns, self.task.turns)} "
            f"(wrap-up reserve: {self.margin.tokens} tokens, {self.margin.turns} turns)"
        )

    def as_dict(self) -> dict:
        return {
            "tokens_remaining": self.remaining.tokens if self.remaining.tokens != UNLIMITED else None,
            "tokens_total": self.task.tokens if self.task.tokens != UNLIMITED else None,
            "turns_remaining": self.remaining.turns if self.remaining.turns != UNLIMITED else None,
            "turns_total": self.task.turns if self.task.turns != UNLIMITED else None,
            "at_margin": self.at_margin,
            "dispatch": self.dispatch,
        }


class IntentMeter:
    """Meters one worker round against intent + task budgets."""

    def __init__(self, ledger: "BudgetLedger") -> None:
        self._ledger = ledger
        self._spent = Spend()

    def record(self, tokens_used: int, turns: int = 1) -> None:
        with self._ledger._lock:
            self._spent = self._spent.add(tokens_used, turns)
            self._ledger._spent = self._ledger._spent.add(tokens_used, turns)

    def remaining(self) -> Budget:
        with self._ledger._lock:
            if self._ledger._wrapup:
                return Budget(0, 0)
            task_rem = self._ledger._task.remaining(self._ledger._spent)
            margin = wrapup_margin(self._ledger._task)
            parent_rem = Budget(
                _left(task_rem.tokens, margin.tokens),
                _left(task_rem.turns, margin.turns),
            )
            intent_rem = self._ledger._intent.remaining(self._spent)
            return _effective_budget(intent_rem, parent_rem)

    def exhausted(self) -> bool:
        r = self.remaining()
        return r.tokens == 0 or r.turns == 0

    def finish(self) -> None:
        with self._ledger._lock:
            self._ledger._worker_runs += 1
            self._ledger._worker_spent = self._ledger._worker_spent.add(
                self._spent.tokens, self._spent.turns
            )


class BudgetLedger:
    """In-memory task-level budget tracker."""

    def __init__(self, task_budget: Budget, intent_budget: Budget) -> None:
        self._task = task_budget
        self._intent = intent_budget
        self._spent = Spend()
        self._worker_runs: int = 0
        self._worker_spent = Spend()
        self._wrapup = False
        self._lock = threading.Lock()

    @classmethod
    def from_env(cls) -> "BudgetLedger | None":
        task, intent = budgets_from_env()
        if task == Budget() and intent == Budget():
            return None
        return cls(task, intent)

    def record(self, tokens_used: int, turns: int = 1) -> None:
        with self._lock:
            self._spent = self._spent.add(tokens_used, turns)

    def state(self) -> BudgetState:
        with self._lock:
            rem = self._task.remaining(self._spent)
            margin = wrapup_margin(self._task)
            est_tokens = DEFAULT_WORKER_ESTIMATE_TOKENS
            est_turns = DEFAULT_WORKER_ESTIMATE_TURNS
            if self._worker_runs > 0:
                est_tokens = self._worker_spent.tokens // self._worker_runs
                est_turns = self._worker_spent.turns // self._worker_runs
            est_tokens = min(est_tokens, self._intent.tokens)
            est_turns = min(est_turns, self._intent.turns)
            at = (
                (rem.tokens != UNLIMITED and rem.tokens <= margin.tokens)
                or (rem.turns != UNLIMITED and rem.turns <= margin.turns)
            )
            dispatch = (
                not self._wrapup
                and not at
                and rem.tokens >= est_tokens
                and rem.turns >= est_turns
            )
            return BudgetState(
                task=self._task, remaining=rem, margin=margin,
                spent=self._spent,
                estimate=Spend(est_tokens, est_turns),
                at_margin=at, dispatch=dispatch,
            )

    def begin_wrapup(self) -> bool:
        with self._lock:
            first = not self._wrapup
            self._wrapup = True
            return first

    def start_intent(self) -> IntentMeter:
        return IntentMeter(self)


def budgets_from_env() -> tuple[Budget, Budget]:
    def _env(k: str) -> int:
        try:
            return int(os.environ.get(k, "0").strip())
        except ValueError:
            return 0

    task = Budget(
        tokens=_budget_cap(_env("ARES_TASK_BUDGET_TOKENS")),
        turns=_budget_cap(_env("ARES_TASK_BUDGET_TURNS")),
    )
    intent = Budget(
        tokens=_budget_cap(_env("ARES_INTENT_BUDGET_TOKENS")),
        turns=_budget_cap(_env("ARES_INTENT_BUDGET_TURNS")),
    )
    return task, intent

# ARTEX-port: hierarchical task+intent budgets with wrap-up reserve
