"""
RunInfo — run attribution metadata attached to each agent run.
Port of ARTEX agent/runinfo.go.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass
class RunInfo:
    """
    Identifies which run a tool call belongs to.
    Zero values = attribution unknown (optional).
    """
    task_id: int = 0
    exploration_id: int = 0
    intent_id: int = 0
    session_id: str = ""


_RUN_INFO_KEY = "ares_run_info"


def set_run_info(context_dict: dict, ri: RunInfo) -> None:
    context_dict[_RUN_INFO_KEY] = ri


def get_run_info(context_dict: dict) -> RunInfo:
    return context_dict.get(_RUN_INFO_KEY, RunInfo())
