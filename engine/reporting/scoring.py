"""
Score 0-100 y grade A-F a partir de los hallazgos confirmados de un scan.
Fórmula portada de cli/internal/scanner/score.go (mcpscanner CLI, Go):
100 - 40*critical - 15*high - 5*medium - 1*low, clamp a [0, 100].
"""
from __future__ import annotations
from engine.core.models import ScanReport

PENALTY = {"critical": 40, "high": 15, "medium": 5, "low": 1, "info": 0}


def _grade(score: int) -> str:
    if score >= 90:
        return "A"
    if score >= 80:
        return "B"
    if score >= 70:
        return "C"
    if score >= 50:
        return "D"
    return "F"


def calculate_score(report: ScanReport) -> dict:
    by_sev = report.summary()["by_severity"]
    penalty = sum(PENALTY[sev] * count for sev, count in by_sev.items())
    score = max(0, min(100, 100 - penalty))
    grade = _grade(score)

    if by_sev.get("critical", 0) > 0:
        verdict_text = f"EXPUESTO — {by_sev['critical']} hallazgo(s) crítico(s) confirmado(s)."
    elif by_sev.get("high", 0) > 0:
        verdict_text = f"RIESGO ALTO — {by_sev['high']} hallazgo(s) de severidad alta confirmado(s)."
    elif score >= 90:
        verdict_text = "ACEPTABLE — sin hallazgos críticos/altos en esta corrida."
    else:
        verdict_text = "REVISAR — hallazgos de severidad media/baja acumulados."

    return {"score": score, "grade": grade, "penalty": penalty, "verdict_text": verdict_text}
