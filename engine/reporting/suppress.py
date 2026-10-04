"""
Reducción de ruido: dos mecanismos, ninguno borra ni oculta un finding --
ambos lo marcan `suppressed=True` con una razón visible, y ESO es lo único
que lo excluye de score/policy_verdict/conteos. Ocultar findings de verdad
sería peligroso (un hallazgo real dejaría de verse); acá el objetivo es que
no cuenten para el veredicto automatizado sin dejar de ser auditables.

1) Allowlist (.ares_allowlist.yml): el equipo marca explícitamente un
   (test_id, target) como aceptado/con excepción documentada -- typo-squats
   intencionales, un secreto de ejemplo en un fixture, etc. Reduce el ruido
   de RE-escaneos repetidos del mismo target: sin esto, cada corrida vuelve
   a contar lo mismo que ya se revisó y se aceptó.

2) --min-confidence verified: sube el piso de lo que gatea CI. Las
   categorías más heurísticas (supplychain.tool_squatting,
   supplychain.malicious_patterns, adv.confused_deputy, etc.) son señal útil
   para revisión manual pero, sin este piso, son la fuente #1 de ruido en un
   pipeline automatizado -- con esto, solo lo 'verified' (hecho observado
   directamente) bloquea un build; lo heurístico sigue en el reporte, sin
   bloquear nada.
"""
from __future__ import annotations
import os
from typing import Optional
import yaml

from engine.core.models import ScanReport

_DEFAULT_ALLOWLIST_NAME = ".ares_allowlist.yml"


def default_allowlist_path(cwd: Optional[str] = None) -> Optional[str]:
    """Convención estilo .gitignore: si existe un '.ares_allowlist.yml' en el
    directorio actual y no se pasó --allowlist explícito, se usa solo."""
    path = os.path.join(cwd or os.getcwd(), _DEFAULT_ALLOWLIST_NAME)
    return path if os.path.isfile(path) else None


def load_allowlist(path: str) -> list[dict]:
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f) or {}
    except FileNotFoundError:
        return []
    entries = data.get("entries", [])
    return [e for e in entries if isinstance(e, dict) and e.get("test_id")]


def _pattern_matches(pattern: Optional[str], value: str) -> bool:
    """Mismo estilo de match que policy.yaml: exacto, wildcard 'prefijo.*', o
    None/'*' = cualquier valor (target omitido en la entry = aplica a todos
    los targets de ese test_id)."""
    if pattern in (None, "*"):
        return True
    if pattern.endswith("*"):
        return value.startswith(pattern[:-1])
    return value == pattern


def apply_noise_reduction(
    report: ScanReport,
    allowlist_path: Optional[str] = None,
    min_confidence: str = "heuristic",
) -> dict:
    """Muta report.findings in-place marcando suppressed/suppressed_reason.
    Devuelve stats para loggear/emitir por progress_cb."""
    entries = load_allowlist(allowlist_path) if allowlist_path else []
    stats = {"allowlisted": 0, "below_confidence_floor": 0, "allowlist_path": allowlist_path}

    for f in report.findings:
        if f.passed:
            continue

        matched_entry = None
        for entry in entries:
            if _pattern_matches(entry.get("test_id"), f.test_id) and _pattern_matches(entry.get("target"), f.target):
                matched_entry = entry
                break

        if matched_entry is not None:
            f.suppressed = True
            f.suppressed_reason = f"allowlist ({allowlist_path}): {matched_entry.get('reason', 'sin razón documentada')}"
            stats["allowlisted"] += 1
            continue

        if min_confidence == "verified" and f.confidence != "verified":
            f.suppressed = True
            f.suppressed_reason = "confidence 'heuristic', por debajo del piso --min-confidence verified"
            stats["below_confidence_floor"] += 1

    return stats
