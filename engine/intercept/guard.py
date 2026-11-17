"""
Guard — orquestador del ciclo de vida de llamadas a herramientas.

Conecta gate + judge + risk scoring para cada tool call.
mode="worker": checks completos (gate + risk + judge).
mode="planner": solo scope/gate, sin judge (agente read-only).
"""
from __future__ import annotations

import logging
import re
import time
from collections import deque
from dataclasses import dataclass, field
from enum import Enum
from typing import Literal

from engine.intercept.gate import InterceptGate, GateDecision
from engine.intercept.judge import InterceptJudge


class Decision(str, Enum):
    APPROVED = "approved"
    DENIED = "denied"
    PENDING_HUMAN = "pending_human"


@dataclass
class AuditEntry:
    ts: float
    tool_name: str
    args_keys: list[str]
    decision: Decision
    reason: str
    risk_score: int = 0


class Guard:
    """Conecta gate + judge + risk scoring al ciclo de vida de cada tool call.

    mode="worker": checks completos (gate + risk + judge).
    mode="planner": solo scope/gate, sin judge (agente read-only).
    """

    def __init__(
        self,
        gate: InterceptGate,
        judge: InterceptJudge | None = None,
        mode: Literal["worker", "planner"] = "worker",
    ):
        self._gate = gate
        self._judge = judge
        self._mode = mode
        self._audit: deque[AuditEntry] = deque(maxlen=1000)

    async def pre_tool(
        self, tool_name: str, args: dict, context: dict
    ) -> tuple[Decision, str]:
        # 1. Extraer targets de los args
        targets = _extract_targets(args)

        # 2. Gate check para cada target
        for target in targets:
            gd = await self._gate.check_async(
                target, test_id=tool_name, test_level=context.get("level", 1)
            )
            if gd.action == "deny":
                return self._audit_return(tool_name, args, Decision.DENIED, gd.reason)

        # 3. Planner mode: solo scope
        if self._mode == "planner":
            return self._audit_return(tool_name, args, Decision.APPROVED, "planner:scope-ok")

        # 4. Risk scoring
        risk = _score_risk(tool_name, args)
        if risk >= 85:
            return self._audit_return(
                tool_name, args, Decision.PENDING_HUMAN, f"risk={risk}", risk
            )

        # 5. Judge para casos borderline o risk>50
        if self._judge and targets and risk > 50:
            jd = await self._judge.evaluate(
                test_id=tool_name,
                target_url=targets[0],
                test_description=f"{tool_name}({', '.join(str(k) for k in args.keys())})",
                environment=context.get("environment", "production"),
            )
            if jd.action == "block":
                return self._audit_return(tool_name, args, Decision.DENIED, jd.reason, risk)

        return self._audit_return(
            tool_name, args, Decision.APPROVED, "all-checks-passed", risk
        )

    def post_tool(self, tool_name: str, result_len: int, context: dict) -> None:
        logging.getLogger(__name__).debug(
            "post_tool %s result_len=%d", tool_name, result_len
        )

    def audit_log(self, limit: int = 50) -> list[dict]:
        return [
            {
                "ts": e.ts,
                "tool": e.tool_name,
                "decision": e.decision.value,
                "reason": e.reason,
                "risk": e.risk_score,
            }
            for e in list(self._audit)[-limit:]
        ]

    def _audit_return(
        self,
        tool_name: str,
        args: dict,
        decision: Decision,
        reason: str,
        risk: int = 0,
    ) -> tuple[Decision, str]:
        self._audit.append(
            AuditEntry(
                ts=time.time(),
                tool_name=tool_name,
                args_keys=list(args.keys())[:20],
                decision=decision,
                reason=reason[:300],
                risk_score=risk,
            )
        )
        return decision, reason


def _extract_targets(args: dict) -> list[str]:
    """Auto-detecta targets de red en los argumentos de cualquier tool."""
    targets = []
    URL_KEYS = {
        "url", "target", "host", "target_url", "endpoint",
        "base_url", "server", "address",
    }
    for k, v in args.items():
        if not isinstance(v, str):
            continue
        kl = k.lower()
        if kl in URL_KEYS or kl.endswith("_url") or kl.endswith("_host"):
            if v.startswith(("http://", "https://", "ws://", "wss://")) or (
                "." in v and "/" not in v.split(".")[0]
            ):
                targets.append(v)
    # También busca IPs/hostnames en comandos
    if "command" in args and isinstance(args["command"], str):
        for m in re.finditer(r'https?://[^\s"\']+', args["command"]):
            targets.append(m.group())
    return list(dict.fromkeys(targets))  # dedup preservando orden


def _score_risk(tool_name: str, args: dict) -> int:
    """Score determinístico 0-100 de cuán peligrosa es una llamada."""
    score = 0
    tl = tool_name.lower()
    HIGH = ["sqlmap", "dalfox", "exploit", "inject", "shell", "rce", "lfi", "rfi"]
    MED  = ["ffuf", "fuzz", "nuclei", "brute", "spray", "bypass"]
    LOW  = ["scan", "probe", "enum", "recon", "discover"]
    if any(x in tl for x in HIGH):
        score += 65
    elif any(x in tl for x in MED):
        score += 35
    elif any(x in tl for x in LOW):
        score += 15
    # Por args
    args_str = str(args).lower()
    if any(x in args_str for x in ["level=5", "risk=3", "--risk 3", "aggressive"]):
        score += 20
    if any(x in args_str for x in ["production", "prod", "live", "real"]):
        score += 15
    if "10.0.0" in args_str or "192.168" in args_str:
        score += 10  # redes internas
    return min(100, score)
