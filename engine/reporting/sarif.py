"""
Export SARIF 2.1.0 mínimo, para integrar hallazgos confirmados a CI/CD
(GitHub code scanning, etc).
"""
from __future__ import annotations
import json
from engine.core.models import ScanReport, Severity

_SARIF_LEVEL = {
    Severity.CRITICAL: "error", Severity.HIGH: "error",
    Severity.MEDIUM: "warning", Severity.LOW: "note", Severity.INFO: "note",
}


def to_sarif(report: ScanReport) -> dict:
    rules = {}
    results = []

    for f in report.findings:
        if f.passed:
            continue
        risk = f.risk
        if f.test_id not in rules:
            tags = [f"{t['framework']}:{t['id']}" if t["id"] else t["framework"] for t in f.frameworks]
            rules[f.test_id] = {
                "id": f.test_id,
                "name": f.test_id,
                "shortDescription": {"text": f.title},
                "fullDescription": {"text": f.description},
                "help": {"text": f.remediation or f.description},
                "properties": {
                    "category": f.category.value, "tags": tags,
                    "security-severity": str(risk["cvss_score"]),  # convención GitHub code scanning
                },
            }
        result = {
            "ruleId": f.test_id,
            "level": _SARIF_LEVEL.get(f.severity, "warning"),
            "message": {"text": f.description},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": f"mcp-tool://{f.target}"},
                }
            }],
            "properties": {
                "severity": f.severity.value, "target": f.target, "finding_id": f.id, "confidence": f.confidence,
                "cvss_vector": risk["cvss_vector"], "cvss_score": risk["cvss_score"],
                "owasp_risk_rating": risk["risk_rating"], "business_impact": risk["business_impact"],
                "remediation_effort": risk["remediation_effort"],
                **({"aivss_score": risk["aivss"]["score"]} if risk.get("aivss") else {}),
            },
        }
        if f.suppressed:
            # mecanismo nativo SARIF -- el resultado sigue exportado (auditable en GitHub code
            # scanning como "dismissed"), pero no cuenta como alerta activa. Nunca se elimina.
            result["suppressions"] = [{"kind": "external", "justification": f.suppressed_reason or "suprimido por Ares"}]
        results.append(result)

    return {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {
                "name": "Ares",
                "informationUri": "https://modelcontextprotocol.io",
                "rules": list(rules.values()),
            }},
            "results": results,
        }],
    }


def save_sarif_report(report: ScanReport, path: str):
    with open(path, "w", encoding="utf-8") as f:
        json.dump(to_sarif(report), f, indent=2, ensure_ascii=False, default=str)
