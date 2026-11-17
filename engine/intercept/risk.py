"""
Scoring determinístico 0-100 de cuán peligrosa es una llamada de herramienta
antes de ejecutarla. No usa LLM — es completamente determinístico.

NOTA: NO confundir con engine/core/risk.py (severidad de findings).
Este módulo evalúa el riesgo de una LLAMADA DE HERRAMIENTA pendiente de aprobación.

Puerto de ARTEX's intercept/risk.go.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import NamedTuple


class RiskFactor(NamedTuple):
    name: str
    score: int
    reason: str


@dataclass
class ToolRisk:
    score: int              # 0-100
    factors: list[RiskFactor]

    @property
    def level(self) -> str:
        if self.score >= 80:
            return "critical"
        if self.score >= 60:
            return "high"
        if self.score >= 40:
            return "medium"
        if self.score >= 20:
            return "low"
        return "info"

    @property
    def requires_human_approval(self) -> bool:
        return self.score >= 85


# Scores base por categoría de herramienta
TOOL_BASE_SCORES: dict[str, int] = {
    # Exploitation activa
    "sqlmap": 75, "dalfox": 70, "exploit": 80, "rce": 85,
    "lfi": 65, "rfi": 65, "xxe": 65, "ssti": 70,
    # Fuzzing
    "ffuf": 40, "fuzz": 40, "brute": 50, "spray": 45,
    # Scanning
    "nuclei": 35, "nmap": 30, "scan": 25, "recon": 20,
    # Safe
    "httpx": 15, "curl": 10, "read": 5, "get": 5,
}


def score_tool_call(
    tool_name: str,
    args: dict,
    context: dict | None = None,
) -> ToolRisk:
    """Calcula el score de riesgo de una llamada de herramienta.

    Args:
        tool_name: nombre de la herramienta
        args: argumentos de la llamada
        context: contexto del scan (environment, scope, etc.)

    Returns: ToolRisk con score 0-100 y factores detallados
    """
    factors: list[RiskFactor] = []
    total = 0

    # Score base por nombre de tool
    tl = tool_name.lower()
    base = 0
    for keyword, score in TOOL_BASE_SCORES.items():
        if keyword in tl:
            if score > base:
                base = score
                factors.append(
                    RiskFactor(
                        f"tool:{keyword}",
                        score,
                        f"Tool '{tool_name}' es de categoría '{keyword}'",
                    )
                )
    total += base

    # Incrementos por argumentos
    args_str = str(args).lower()

    if any(x in args_str for x in ("level=5", "--level 5", "risk=3", "--risk 3")):
        f = RiskFactor("high_intensity", 20, "Nivel de intensidad máximo detectado en args")
        factors.append(f)
        total += f.score

    if any(x in args_str for x in ("production", "prod.", "live.")):
        f = RiskFactor("prod_target", 20, "Target parece ser ambiente de producción")
        factors.append(f)
        total += f.score

    if any(x in args_str for x in ("--forms", "--crawl", "--all", "--level 4", "--level 5")):
        f = RiskFactor("broad_coverage", 10, "Cobertura amplia/agresiva detectada")
        factors.append(f)
        total += f.score

    # Contexto de ambiente
    env = (context or {}).get("environment", "production")
    if env in ("production", "prod"):
        f = RiskFactor("prod_env", 10, "Ambiente de producción declarado en contexto")
        factors.append(f)
        total += f.score

    return ToolRisk(score=min(100, total), factors=factors)
