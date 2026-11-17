"""
Abort cause definitions for agent run cancellations.
Port of ARTEX agent/cancelcause.go.
"""
from __future__ import annotations
from dataclasses import dataclass


@dataclass
class AbortCause(Exception):
    """Named cause for a cancelled agent run context."""
    code: str
    short: str
    text: str

    def __str__(self) -> str:
        return self.text

    def __repr__(self) -> str:
        return f"AbortCause(code={self.code!r}, short={self.short!r})"


def _cause(code: str, short: str, text: str) -> AbortCause:
    return AbortCause(code=code, short=short, text=text)


# ── Task-level execution context ──────────────────────────────────────────────

ABORT_PAUSED_BY_USER = _cause(
    "paused_by_user", "The user paused the task",
    "The user paused the task via POST /api/tasks/{id}/control, action=pause. "
    "Running intents return to frontier(open) and are re-claimed after the task resumes.",
)
ABORT_PAUSED_BY_ORCHESTRATOR = _cause(
    "paused_by_orchestrator", "The orchestrating agent paused the task",
    "The orchestrating agent called the pause_task tool. Running intents return to "
    "frontier(open) and are executed again after resuming.",
)
ABORT_TASK_DELETED = _cause(
    "task_deleted", "The task was deleted",
    "The task is being deleted; the deletion barrier has cancelled all running agents; "
    "this run's results will not be used.",
)
ABORT_GOAL_MET = _cause(
    "goal_met", "The planner judged the task goals met",
    "The planner judged the task goals met and set the task to done, then cancelled "
    "Workers still running; these intents are marked stopped, not failed.",
)
ABORT_SETTLE_DRAIN_TIMEOUT = _cause(
    "settle_drain_timeout", "Task timeout wrap-up wait expired",
    "After the task hit timeout it waited for running Workers to wrap up gracefully, "
    "but the 90-second drain grace was not enough; a hard cancel was performed.",
)
ABORT_SHUTDOWN = _cause(
    "shutdown", "The backend process is shutting down",
    "The backend process received SIGINT or SIGTERM. All running agents are cancelled; "
    "after restart, leftover running intents are reset to open.",
)

# ── Per-work context ──────────────────────────────────────────────────────────

ABORT_KILLED_BY_PLANNER = _cause(
    "killed_by_planner", "The planner terminated this intent",
    "The planner actively terminated this intent via kill_work; the intent is marked "
    "stopped and is not automatically re-claimed.",
)
ABORT_WORK_PAUSED_BY_USER = _cause(
    "work_paused_by_user", "The user paused this Worker intent",
    "The user paused a running Worker. All recorded intents, facts, vulnerabilities, "
    "and activity records are kept; execution restarts from scratch after resuming.",
)
ABORT_WORK_CANCELLED_BY_USER = _cause(
    "work_cancelled_by_user", "The user deleted this Worker intent",
    "The user deleted a running Worker; after the Worker exits, the server handles "
    "the intent per the user-chosen deletion mode.",
)
ABORT_WORK_CLAIM_LOST = _cause(
    "work_claim_lost", "Another Worker took this intent over",
    "This Worker's claim on the intent expired and another Worker took the intent over. "
    "This run was cancelled and its result is discarded.",
)
ABORT_WORK_FINISHED = _cause(
    "work_finished", "Worker finished normally, context freed",
    "The Worker finished normally, and the engine released its context resources. "
    "This is not an interruption.",
)

# ── Main Agent and standalone conversation contexts ───────────────────────────

ABORT_CHAT_STOPPED_BY_USER = _cause(
    "chat_stopped_by_user", "The user stopped this conversation turn",
    "The user clicked stop, actively aborting this main agent run. Activity records "
    "already produced are kept.",
)
ABORT_CHAT_TURN_FINISHED = _cause(
    "chat_turn_finished", "Turn finished normally; context released",
    "This conversation turn finished normally; the server is releasing that turn's "
    "context resources. This is not an interruption.",
)
ABORT_RUN_HARD_TIMEOUT = _cause(
    "run_hard_timeout", "The per-run hard timeout backstop fired",
    "A single run exceeded the soft wall-clock budget plus the extra grace; "
    "a model request or tool did not return for a long time.",
)

# ── Registry ──────────────────────────────────────────────────────────────────

_ALL_CAUSES: dict[str, AbortCause] = {
    c.code: c for c in [
        ABORT_PAUSED_BY_USER, ABORT_PAUSED_BY_ORCHESTRATOR, ABORT_TASK_DELETED,
        ABORT_GOAL_MET, ABORT_SETTLE_DRAIN_TIMEOUT, ABORT_SHUTDOWN,
        ABORT_KILLED_BY_PLANNER, ABORT_WORK_PAUSED_BY_USER,
        ABORT_WORK_CANCELLED_BY_USER, ABORT_WORK_CLAIM_LOST, ABORT_WORK_FINISHED,
        ABORT_CHAT_STOPPED_BY_USER, ABORT_CHAT_TURN_FINISHED, ABORT_RUN_HARD_TIMEOUT,
    ]
}


def lookup(code: str) -> AbortCause | None:
    return _ALL_CAUSES.get(code)


def from_exception(exc: BaseException) -> tuple[str, str, str, bool]:
    """Extract (code, short, text, ok) from an exception."""
    if isinstance(exc, AbortCause):
        return exc.code, exc.short, exc.text, True
    return "other", str(exc)[:80], str(exc), False
