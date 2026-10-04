"""
Compara un ScanReport contra el JSON de un scan anterior: sin esto, cada
corrida es una foto aislada -- no hay forma de saber si el server mejoró o
empeoró desde la última vez, ni de aceptar un riesgo conocido sin que
reaparezca como "nuevo" en cada scan.

La clave de identidad de un finding es (test_id, target) -- estable entre
corridas aunque cambien detalles de evidencia/timestamp/id.
"""
from __future__ import annotations
import json

from engine.core.models import ScanReport


def _key(test_id: str, target: str) -> tuple:
    return (test_id, target)


def load_baseline_tools(path: str) -> list[dict]:
    """Tools enumeradas en un reporte.json anterior -- usado por adv.rug_pull para
    detectar si la definición de un tool cambió desde esa corrida sin ninguna señal."""
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        return data.get("tools_enumerated", [])
    except (FileNotFoundError, json.JSONDecodeError):
        return []


def _load_baseline_findings(path: str) -> dict[tuple, dict]:
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)
    return {
        _key(f["test_id"], f["target"]): f
        for f in data.get("findings", [])
        if not f.get("passed", True)
    }


def diff_against_baseline(report: ScanReport, baseline_path: str) -> dict:
    baseline = _load_baseline_findings(baseline_path)
    current = {_key(f.test_id, f.target): f.to_dict() for f in report.findings if not f.passed}

    new = [f for key, f in current.items() if key not in baseline]
    persisting = [f for key, f in current.items() if key in baseline]
    resolved = [f for key, f in baseline.items() if key not in current]

    return {
        "baseline_source": baseline_path,
        "new": new,
        "resolved": resolved,
        "persisting": persisting,
        "summary": (
            f"{len(new)} hallazgo(s) nuevo(s) desde el baseline, "
            f"{len(resolved)} resuelto(s), {len(persisting)} persisten igual."
        ),
    }
