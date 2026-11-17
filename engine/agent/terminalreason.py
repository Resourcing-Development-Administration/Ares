"""
Terminal reason enum and text rendering. Port of ARTEX agent/terminalreason.go.
"""
from __future__ import annotations

from enum import Enum
from typing import Any


class TerminalReason(str, Enum):
    COMPLETED          = "completed"
    MAX_TURNS          = "max_turns"
    TIMEOUT            = "timeout"
    MODEL_ERROR        = "model_error"
    BLOCKING_LIMIT     = "blocking_limit"
    PROMPT_TOO_LONG    = "prompt_too_long"
    IMAGE_ERROR        = "image_error"
    STOP_HOOK_PREVENTED = "stop_hook_prevented"
    HOOK_STOPPED       = "hook_stopped"
    ABORTED_STREAMING  = "aborted_streaming"
    ABORTED_TOOLS      = "aborted_tools"


REASON_HINTS: dict[TerminalReason, str] = {
    TerminalReason.COMPLETED: "the model ended this turn normally but left no text summary; facts and assets are as recorded by this turn's tool calls",
    TerminalReason.MAX_TURNS: "reached the turn cap (MaxTurns): wrap-up wrote back facts and assets; the intent is marked exhausted so the planner can continue in a different direction",
    TerminalReason.TIMEOUT: "reached this run's wall-clock budget (MaxDuration): at the deadline the in-flight tool is interrupted and the run settles in place",
    TerminalReason.MODEL_ERROR: "the model or API call failed (network, auth, rate limiting, provider 5xx) and retries were exhausted; check the execution trace before deciding whether to redispatch",
    TerminalReason.BLOCKING_LIMIT: "context length hit the hard cap; narrow the intent's granularity or compress tool output",
    TerminalReason.PROMPT_TOO_LONG: "the prompt was too long and context-compaction retries were exhausted; cannot continue",
    TerminalReason.IMAGE_ERROR: "the current model does not support this turn's multimodal content; switch to a vision-capable model",
    TerminalReason.STOP_HOOK_PREVENTED: "a Stop hook prevented this turn from ending; check whether the task's Guard rules are too strict",
    TerminalReason.HOOK_STOPPED: "a tool or hook actively stopped execution; check the interception note on the last tool_result",
    TerminalReason.ABORTED_STREAMING: "the run was cancelled while the model was streaming its output",
    TerminalReason.ABORTED_TOOLS: "the run was cancelled during tool execution",
}


def reason_hint(reason: str | TerminalReason) -> str:
    try:
        r = TerminalReason(reason)
        return REASON_HINTS.get(r, f"unknown terminal state: {reason}")
    except ValueError:
        return f"unknown terminal state: {reason}"


def reason_label(reason: str | TerminalReason | None) -> str:
    if not reason:
        return "context_canceled"
    return str(reason)


def terminal_text(
    reason: str | TerminalReason | None,
    turns: int = 0,
    duration_s: float = 0.0,
    tool_name: str = "",
    tool_pending: bool = False,
    abort_cause: str = "",
    err: str = "",
) -> tuple[str, str]:
    """
    Render a compact summary + Markdown detail block for a terminal event
    with no final text. Returns (summary, detail_markdown).
    """
    r = reason_label(reason)
    aborted = r in ("aborted_streaming", "aborted_tools", "context_canceled")

    if aborted:
        cause = abort_cause or "cancellation reason unavailable"
        stage = "mid-execution"
        if r == "aborted_streaming":
            stage = "the model output stage"
        elif r == "aborted_tools":
            stage = "the tool execution stage"
        progress = _progress_suffix(turns, duration_s)
        summary = f"(run interrupted: {cause}; stopped during {stage}{progress}, unfinished)"
    elif r in ("max_turns", "timeout"):
        progress = _progress_suffix(turns, duration_s)
        summary = f"(run budget cap reached ({r}); wrap-up wrote back facts{progress}; no text summary this run)"
    else:
        hint = reason_hint(r)
        short_hint = hint[:80] + "…" if len(hint) > 80 else hint
        summary = f"(no text summary; terminal state {r}: {short_hint})"

    lines = [summary, "", f"- **Terminal state**: `{r}` - {reason_hint(r)}"]
    if aborted and abort_cause:
        lines.append(f"- **Interruption cause**: {abort_cause}")
    if err:
        lines.append(f"- **Underlying error**: `{err}`")
    if turns:
        lines.append(f"- **Executed**: {turns} model turns")
    if duration_s > 0:
        lines.append(f"- **Run duration**: {_round_dur(duration_s)}")
    if not tool_name:
        lines.append("- **Tool calls**: the run ended before any tool call was made")
    elif tool_pending:
        lines.append(f"- **Tool in flight at interruption**: `{tool_name}` (no result returned)")
    else:
        lines.append(f"- **Last tool before interruption**: `{tool_name}` (returned normally)")

    return summary, "\n".join(lines)


def _progress_suffix(turns: int, duration_s: float) -> str:
    parts = []
    if turns:
        parts.append(f"{turns} turns")
    if duration_s > 0:
        parts.append(_round_dur(duration_s))
    return (", ran for " + " / ".join(parts)) if parts else ""


def _round_dur(s: float) -> str:
    if s < 60:
        return f"{s:.1f}s"
    if s < 3600:
        return f"{int(s // 60)}m{int(s % 60)}s"
    return f"{int(s // 3600)}h{int((s % 3600) // 60)}m"
