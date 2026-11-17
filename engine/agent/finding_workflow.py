"""
Finding workflow — manages the lifecycle of findings: draft → confirmed → verified.
Integrates traffic binding when enabled. Port of ARTEX agent/finding_workflow.go.
"""
from __future__ import annotations

import copy
import threading
from typing import Callable

_lock = threading.Lock()
_traffic_binding_hook: Callable[[], bool] | None = None


def set_finding_traffic_binding_enabled(f: Callable[[], bool] | None) -> None:
    global _traffic_binding_hook
    with _lock:
        _traffic_binding_hook = f


def finding_traffic_binding_enabled() -> bool:
    with _lock:
        f = _traffic_binding_hook
    return f is not None and f()


# Strip traffic parameters from report_finding schema when binding is disabled
_TRAFFIC_PARAMS = frozenset(["traffic_refs", "evidence_hint_id"])


def strip_traffic_parameters(schema: dict) -> None:
    """Remove traffic binding parameters from a tool's input schema."""
    props = schema.get("properties", {})
    required = schema.get("required", [])
    for p in _TRAFFIC_PARAMS:
        props.pop(p, None)
    schema["required"] = [r for r in required if r not in _TRAFFIC_PARAMS]


class FindingState:
    DRAFT     = "draft"
    CONFIRMED = "confirmed"
    VERIFIED  = "verified"
    RETESTING = "retesting"
    FIXED     = "fixed"
    WONTFIX   = "wontfix"


WORKFLOW_GUIDANCE = (
    "\n\n**Finding lifecycle**: use report_finding to record a vulnerability. "
    "Findings start as draft and are confirmed once you've verified the reproduction "
    "steps. Use update_finding_report to update the status as the investigation progresses. "
    "Bind supporting traffic evidence via traffic_refs when available."
)

REPORTER_GUIDANCE = (
    "\n\nBy default the report agent verifies and binds traffic before writing the report. "
    "The reporter keeps verification commands, key output, and any known real traffic IDs "
    "and their purpose in evidence; no extra packet capture is needed for binding. "
    "Explicit immediate binding is still supported: traffic_refs or evidence_hint_id may "
    "submit already-verified references. TCP/no-capture cases do not need these optional "
    "parameters. The returned finding_id and finding_node_id denote the standalone record "
    "and the exploration node respectively."
)


def apply_workflow_tools(
    agent_key: str,
    tools: list[dict],
) -> tuple[list[dict], str]:
    """
    Apply finding workflow tool modifications.
    Returns (modified_tools, extra_guidance).
    """
    if not finding_traffic_binding_enabled():
        filtered = []
        for tool in tools:
            name = tool.get("name", "")
            if name == "bind_finding_traffic":
                continue
            if agent_key == "reporter" and name in (
                "traffic_search", "traffic_get", "traffic_blob", "traffic_messages"
            ):
                continue
            if name in ("report_finding", "add_hint", "add_task_hint"):
                tool = copy.deepcopy(tool)
                strip_traffic_parameters(tool.get("input_schema", {}))
            filtered.append(tool)
        return filtered, ""

    return list(tools), WORKFLOW_GUIDANCE if agent_key != "reporter" else REPORTER_GUIDANCE
