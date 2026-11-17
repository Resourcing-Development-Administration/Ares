"""
NOA (Number-of-Actions) budget — context compression mechanism.
Simplified Python port of ARTEX agent/noa.go.

In ARTEX this wraps norma's noaadapter which provides model-driven context
compression. Here we provide the Python equivalent: a budget tracker that
monitors the number of tool calls and triggers compression when approaching
the context limit.
"""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable

DEFAULT_WINDOW_K = 200  # 200k token default context window


@dataclass
class NoaOptions:
    archive_base_dir: str = ""
    session_id: str = ""
    model_context_limit: int = DEFAULT_WINDOW_K * 1000
    on_warn: Callable[[str], None] | None = None


@dataclass
class NoaBudget:
    """
    Tracks tool-call count and triggers context compression when approaching limits.
    Analogous to ARTEX's noaBudgetProvider: wraps the agent's context window.
    """
    options: NoaOptions
    _action_count: int = field(default=0, init=False)
    _compress_threshold: float = field(default=0.75, init=False)

    def record_action(self) -> None:
        self._action_count += 1

    def should_compress(self, estimated_tokens: int) -> bool:
        limit = self.options.model_context_limit
        return estimated_tokens > int(limit * self._compress_threshold)

    def archive_path(self) -> str:
        if not self.options.archive_base_dir or not self.options.session_id:
            return ""
        return str(
            Path(self.options.archive_base_dir) / "noa" / self.options.session_id
        )

    def warn(self, msg: str) -> None:
        if self.options.on_warn:
            self.options.on_warn(msg)

    @property
    def action_count(self) -> int:
        return self._action_count


def enable_noa(
    opts: dict,
    enabled: Callable[[], bool] | None,
    archive_root: str,
    session_id: str,
    on_warn: Callable[[str], None] | None = None,
) -> NoaBudget | None:
    """
    Wire NOA into agent options when the resolver reports enabled.
    Returns a NoaBudget on success, None when disabled or failed.

    opts: mutable dict of agent options (modified in place when NOA enabled)
    enabled: callable returning bool; None = off
    """
    if enabled is None or not enabled():
        return None

    window = opts.get("context_window", DEFAULT_WINDOW_K * 1000)

    try:
        budget = NoaBudget(
            options=NoaOptions(
                archive_base_dir=archive_root,
                session_id=session_id,
                model_context_limit=window,
                on_warn=on_warn or (lambda m: None),
            )
        )
        # Disable built-in compaction when NOA takes over
        opts.pop("compaction", None)
        opts["noa_budget"] = budget
        archive = budget.archive_path()
        if archive:
            os.makedirs(archive, exist_ok=True)
        return budget
    except Exception as exc:
        if on_warn:
            on_warn(
                f"failed to enable NOA compression, falling back to built-in compaction: {exc}"
            )
        return None
