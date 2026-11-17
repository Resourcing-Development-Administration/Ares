"""
Operation constraints — renders allow/deny constraint blocks for agent system prompts.
Port of ARTEX agent/constraints.go.
"""
from __future__ import annotations


def constraint_block(constraints: list[dict] | None) -> str:
    """
    Render allow/deny constraints as a high-priority block for the agent prompt.
    constraints: list of dicts with keys 'kind' ('allow'|'deny') and 'text'.
    Returns empty string when there are no constraints.
    """
    if not constraints:
        return ""

    allow: list[str] = []
    deny: list[str] = []
    for c in constraints:
        text = (c.get("text") or "").strip()
        if not text:
            continue
        if c.get("kind") == "allow":
            allow.append(f"- {text}")
        else:
            deny.append(f"- {text}")

    if not allow and not deny:
        return ""

    lines = [
        "\n\n[Operation constraints (highest priority, above every exploration/expansion "
        "heuristic below; before generating any intent or executing any action you must "
        "first self-check for violations — if it violates a constraint, do not proceed)]:"
    ]
    if allow:
        lines.append("Allowed operations:")
        lines.extend(allow)
    if deny:
        lines.append("Forbidden operations:")
        lines.extend(deny)
    lines.append(
        "\n(Discovering a new target/port/host outside the constraints does not grant "
        "authorization: unless it falls within the allowed range above, record it as an "
        "out-of-scope fact and skip it — do not spawn intents or execute actions for it.)"
    )
    return "\n".join(lines)
