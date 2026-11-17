"""
Finding deduplication — fingerprint-based dedup + retesting.
Inspirado en ARTEX db/finding_retests.go.

Genera un fingerprint canónico por finding para:
- Detectar duplicados dentro de un mismo scan
- Comparar hallazgos entre runs sucesivos (retesting)
- Marcar findings como "ya conocidos" vs "nuevos"
"""
from __future__ import annotations
import hashlib
import json
from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from engine.core.models import Finding, ScanReport


def fingerprint(finding: "Finding") -> str:
    """Hash canónico de un finding para deduplicación.

    Incluye: test_id, título normalizado, severidad, target (host only).
    Excluye: timestamps, UUIDs, detalles variables de exploit, evidencia larga.
    """
    from urllib.parse import urlparse
    target = finding.target or ""
    try:
        host = urlparse(target).netloc or target
    except Exception:
        host = target

    canonical = {
        "test_id": finding.test_id,
        "title": finding.title.strip().lower(),
        "severity": finding.severity.value if hasattr(finding.severity, "value") else str(finding.severity),
        "host": host,
        "category": finding.category.value if hasattr(finding.category, "value") else str(finding.category),
    }
    raw = json.dumps(canonical, sort_keys=True, ensure_ascii=False)
    return hashlib.sha256(raw.encode()).hexdigest()[:16]


def dedup_findings(findings: list["Finding"]) -> tuple[list["Finding"], int]:
    """Elimina duplicados exactos de una lista de findings.

    Returns:
        (deduplicated_list, removed_count)
    """
    seen: set[str] = set()
    result: list["Finding"] = []
    removed = 0
    for f in findings:
        fp = fingerprint(f)
        if fp in seen:
            removed += 1
        else:
            seen.add(fp)
            result.append(f)
    return result, removed


def dedup_report(report: "ScanReport") -> int:
    """Deduplication in-place sobre los findings de un reporte. Returns removed count."""
    deduped, removed = dedup_findings(report.findings)
    report.findings = deduped
    return removed


@dataclass
class RetestResult:
    fingerprint: str
    test_id: str
    title: str
    status: str  # "confirmed", "resolved", "new", "unchanged"
    previous_severity: str | None
    current_severity: str | None


def compare_findings(
    previous: list["Finding"],
    current: list["Finding"],
) -> list[RetestResult]:
    """Compara dos listas de findings para detectar new/resolved/confirmed.

    Returns lista de RetestResult con el estado de cada hallazgo.
    """
    prev_fps: dict[str, "Finding"] = {fingerprint(f): f for f in previous}
    curr_fps: dict[str, "Finding"] = {fingerprint(f): f for f in current}

    results: list[RetestResult] = []

    for fp, f in curr_fps.items():
        if fp not in prev_fps:
            results.append(RetestResult(
                fingerprint=fp, test_id=f.test_id, title=f.title,
                status="new",
                previous_severity=None,
                current_severity=f.severity.value if hasattr(f.severity, "value") else str(f.severity),
            ))
        else:
            prev_sev = prev_fps[fp].severity.value if hasattr(prev_fps[fp].severity, "value") else str(prev_fps[fp].severity)
            curr_sev = f.severity.value if hasattr(f.severity, "value") else str(f.severity)
            results.append(RetestResult(
                fingerprint=fp, test_id=f.test_id, title=f.title,
                status="confirmed",
                previous_severity=prev_sev,
                current_severity=curr_sev,
            ))

    for fp, f in prev_fps.items():
        if fp not in curr_fps:
            results.append(RetestResult(
                fingerprint=fp, test_id=f.test_id, title=f.title,
                status="resolved",
                previous_severity=f.severity.value if hasattr(f.severity, "value") else str(f.severity),
                current_severity=None,
            ))

    return results


def retest_summary(results: list[RetestResult]) -> dict:
    new = [r for r in results if r.status == "new"]
    resolved = [r for r in results if r.status == "resolved"]
    confirmed = [r for r in results if r.status == "confirmed"]
    return {
        "new": len(new),
        "resolved": len(resolved),
        "confirmed": len(confirmed),
        "regression": len(new) > 0,
        "new_findings": [{"test_id": r.test_id, "title": r.title, "severity": r.current_severity} for r in new],
        "resolved_findings": [{"test_id": r.test_id, "title": r.title, "severity": r.previous_severity} for r in resolved],
    }
