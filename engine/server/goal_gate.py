"""
Goal gate — validates task goals for minimum quality before spending tokens.
Port of ARTEX server/goal_gate.go.
"""
from __future__ import annotations

import re

GOAL_MIN_LEN = 80

_TARGETLESS_RE = re.compile(r"\[targetless\]")
_URL_RE = re.compile(r"(?i)\bhttps?://\S+")
_DOMAIN_RE = re.compile(r"(?i)\b[a-z0-9][a-z0-9-]{1,61}\.[a-z]{2,}(:[0-9]+)?(/\S*)?\b")
_IPV4_RE = re.compile(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(:\d+)?\b")
_LOCALHOST_RE = re.compile(r"(?i)\blocalhost:[0-9]+\b")
_PATH_RE = re.compile(r"(?i)(^|\s)/[a-z0-9_-]+(/[a-z0-9_.-]+)+")


def check_goal(goal: str) -> str | None:
    """
    Validate a task goal for minimum quality.
    Returns None if valid, or an error message string if invalid.

    A goal must:
    1. Be at least GOAL_MIN_LEN characters (or contain [targetless] marker).
    2. Name a concrete target (URL, domain, IP, localhost:port, or path).
       Goals with [targetless] skip target-name check.
    """
    g = goal.strip()

    if _TARGETLESS_RE.search(g):
        return None  # explicit targetless opt-out

    if len(g) < GOAL_MIN_LEN:
        return (
            f"Goal is too short to carry a testable objective (min {GOAL_MIN_LEN} chars): "
            "name the target and what counts as success. "
            "Add the literal marker [targetless] only for genuinely target-less analysis tasks."
        )

    if (
        _URL_RE.search(g)
        or _DOMAIN_RE.search(g)
        or _IPV4_RE.search(g)
        or _LOCALHOST_RE.search(g)
        or _PATH_RE.search(g)
    ):
        return None

    return (
        "Goal names no target: include the URL/host/IP/path under test "
        "(or the literal marker [targetless] for target-less analysis tasks) "
        "so workers cannot be dispatched against an unrelated asset."
    )


def is_valid(goal: str) -> bool:
    return check_goal(goal) is None
