"""
chat_mentions — Parse and resolve @mentions in chat messages.
Port of ARTEX server/chat_mentions.go.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any

_MENTION_RE = re.compile(r"@(\w[\w\-\.]*)")


@dataclass
class Mention:
    raw: str        # original @token
    token: str      # token without @
    kind: str       # "task", "skill", "user", "unknown"
    ref_id: int     # numeric id if resolved, 0 otherwise


def extract_mentions(text: str) -> list[Mention]:
    """Extract all @mention tokens from a chat message."""
    mentions: list[Mention] = []
    for m in _MENTION_RE.finditer(text):
        token = m.group(1)
        mentions.append(Mention(raw=m.group(0), token=token, kind="unknown", ref_id=0))
    return mentions


def resolve_mentions(
    mentions: list[Mention],
    task_names: dict[str, int] | None = None,
    skill_names: set[str] | None = None,
) -> list[Mention]:
    """
    Resolve mention tokens against known tasks and skills.
    task_names: map of task name → task id.
    skill_names: set of known skill names.
    """
    resolved: list[Mention] = []
    task_names = task_names or {}
    skill_names = skill_names or set()

    for m in mentions:
        token_lower = m.token.lower()
        if token_lower in task_names:
            resolved.append(Mention(raw=m.raw, token=m.token, kind="task", ref_id=task_names[token_lower]))
        elif m.token in skill_names or token_lower in skill_names:
            resolved.append(Mention(raw=m.raw, token=m.token, kind="skill", ref_id=0))
        else:
            resolved.append(m)

    return resolved


def render_mention_context(mentions: list[Mention]) -> str:
    """Render a brief context block for resolved mentions to include in agent prompt."""
    task_refs = [m for m in mentions if m.kind == "task"]
    skill_refs = [m for m in mentions if m.kind == "skill"]
    if not task_refs and not skill_refs:
        return ""
    lines = ["[Mentioned context]:"]
    for m in task_refs:
        lines.append(f"- Task #{m.ref_id} ({m.token})")
    for m in skill_refs:
        lines.append(f"- Skill: {m.token}")
    return "\n".join(lines)
