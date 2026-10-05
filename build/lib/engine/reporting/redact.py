"""
Redacta secretos que pudieran haber quedado en la evidencia cruda
(request/response/notes) de un reporte ANTES de persistirlo a disco -- el
reporte mismo no debe convertirse en un vector de leak (ej. si un tool
devuelve un token real en su respuesta durante el scan, ese token no debería
terminar legible en reporte.html/json/sarif).

Reusa el mismo banco de patrones que supplychain.secret_exposure (regex
propio + cache de gitleaks si corriste `update-rules`), así que solo hace
falta mantener un banco de patrones en un lugar.
"""
from __future__ import annotations
import copy
import re

from engine.core.models import ScanReport
from engine.supplychain.tests import SECRET_PATTERNS
from engine.supplychain.rule_sources import load_secret_patterns

PLACEHOLDER = "[REDACTED:{label}]"


def _all_patterns() -> list[tuple[str, str]]:
    return SECRET_PATTERNS + load_secret_patterns()


def _short_label(label: str) -> str:
    return label.split(" (")[0][:30].replace(" ", "_")


def _redact_text(text: str, patterns) -> str:
    for pattern, label in patterns:
        try:
            text = re.sub(pattern, PLACEHOLDER.format(label=_short_label(label)), text)
        except re.error:
            continue
    return text


def _redact_value(value, patterns):
    if isinstance(value, str):
        return _redact_text(value, patterns)
    if isinstance(value, dict):
        return {k: _redact_value(v, patterns) for k, v in value.items()}
    if isinstance(value, list):
        return [_redact_value(v, patterns) for v in value]
    return value


def redact_report(report: ScanReport) -> ScanReport:
    """Devuelve una COPIA del reporte con la evidencia redactada. No muta el
    original -- así el reporte en memoria sigue disponible intacto para lógica
    que lo siga usando (--compare-auth, baseline, etc.)."""
    patterns = _all_patterns()
    redacted = copy.deepcopy(report)
    for f in redacted.findings:
        f.evidence.request = _redact_value(f.evidence.request, patterns)
        f.evidence.response = _redact_value(f.evidence.response, patterns)
        f.evidence.notes = _redact_text(f.evidence.notes or "", patterns)
        if f.evidence.raw:
            f.evidence.raw = _redact_text(f.evidence.raw, patterns)
        f.description = _redact_text(f.description, patterns)
    return redacted
