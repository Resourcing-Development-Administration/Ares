"""
FindingRecorder — interface for recording findings from agent tools.
Port of ARTEX agent/finding_recorder.go.
"""
from __future__ import annotations

from typing import Any, Protocol


FINDING_TRAFFIC_GUIDANCE = (
    "\n\n**Vulnerability traffic evidence (optional)**: when reporting a vulnerability "
    "via report_finding, if there are HTTP requests/responses you have reviewed and "
    "confirmed to support the conclusion, you may bind their real IDs via traffic_refs "
    "in reproduction order. For TCP and other non-HTTP vulnerabilities, when nothing was "
    "captured, or when there is no exact match, omit it or pass [], keep other verifiable "
    "evidence such as command output and logs in evidence, and state why nothing was bound. "
    "Do not guess IDs, and do not re-probe just to capture packets."
)

FINDING_ID_GUIDANCE = (
    "\n\n**Finding ID conventions**: finding_id is the standalone vulnerability record ID; "
    "finding_node_id is the exploration node ID. The id returned by list_findings / "
    "list_task_findings / node_detail remains the exploration node ID; read the standalone "
    "ID from the finding_id in the same response. get_finding_traffic / bind_finding_traffic "
    "use the standalone finding_id. Do not feed the number on the first line of report_finding "
    "to the evidence tools, and do not guess other numbers after an ID error."
)


class FindingRecorder(Protocol):
    """
    Protocol for recording findings. The host injects an implementation;
    agents never synthesize or copy evidence bodies themselves.
    """

    async def record(
        self,
        finding: dict[str, Any],
        traffic_refs: list[dict] | None = None,
    ) -> dict[str, Any]:
        """
        Record a finding and return the recorded finding with its assigned IDs.
        finding keys: title, severity, description, evidence, target, cve, cwe, cvss
        traffic_refs: list of {id, role} dicts referencing captured traffic exchanges
        """
        ...


class NoopFindingRecorder:
    """Fallback recorder when no DB backend is wired."""

    async def record(
        self,
        finding: dict[str, Any],
        traffic_refs: list[dict] | None = None,
    ) -> dict[str, Any]:
        import uuid
        import time
        fid = str(uuid.uuid4())[:8]
        return {**finding, "finding_id": fid, "recorded_at": time.time()}
