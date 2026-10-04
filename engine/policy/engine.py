"""
Motor de policy: convierte los findings confirmados de un ScanReport en un
veredicto BLOCK / CONDITIONAL / ALLOW por ambiente, listo para gating de CI.

Inspirado en mcpscan/guard/mcp_guard/policy.py (mcp-guard): reglas por patrón
de test_id, veredicto = el más restrictivo entre todos los findings, con
fallback por severidad cuando no hay regla explícita para ese test_id.
"""
from __future__ import annotations
import os
from typing import Optional
import yaml

from engine.core.models import ScanReport

_RANK = {"ALLOW": 0, "CONDITIONAL": 1, "BLOCK": 2}
_DEFAULT_POLICY_PATH = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))), "policy.yaml")


class PolicyEngine:
    def __init__(self, policy_path: Optional[str] = None):
        path = policy_path or _DEFAULT_POLICY_PATH
        try:
            with open(path, "r", encoding="utf-8") as f:
                data = yaml.safe_load(f) or {}
        except FileNotFoundError:
            data = {}
        self.rules: list[dict] = data.get("rules", [])
        self.severity_fallback: dict = data.get("severity_fallback", {})

    def _verdict_for_finding(self, test_id: str, severity: str, environment: str) -> str:
        for rule in self.rules:
            pattern = rule.get("pattern", "")
            if test_id == pattern or (pattern.endswith("*") and test_id.startswith(pattern[:-1])):
                return rule.get(environment, "ALLOW")
        return self.severity_fallback.get(severity, {}).get(environment, "ALLOW")

    def evaluate(self, report: ScanReport, environment: str = "production") -> dict:
        by_finding = []
        overall = "ALLOW"
        for f in report.findings:
            if f.passed:
                continue
            if f.suppressed:
                # sigue listado (auditable, nunca se oculta) pero no gatea el veredicto agregado
                by_finding.append({
                    "finding_id": f.id, "test_id": f.test_id, "title": f.title,
                    "severity": f.severity.value, "verdict": "SUPPRESSED",
                })
                continue
            verdict = self._verdict_for_finding(f.test_id, f.severity.value, environment)
            by_finding.append({
                "finding_id": f.id, "test_id": f.test_id, "title": f.title,
                "severity": f.severity.value, "verdict": verdict,
            })
            if _RANK[verdict] > _RANK[overall]:
                overall = verdict

        return {
            "environment": environment,
            "overall": overall,
            "by_finding": by_finding,
        }
