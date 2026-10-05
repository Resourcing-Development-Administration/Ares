"""
SAST del código fuente real del server (opt-in, requiere --source-path),
vía semgrep con un ruleset propio y chico (rules/semgrep_mcp.yml) -- cierra
la brecha #1 documentada en el roadmap: hasta acá Ares solo miraba la
superficie del protocolo (schemas/descripciones), nunca el código.

Nunca sale a red: se corre con --config <ruta local>, nunca --config auto/
p/ci (esas SÍ pegan al registro público de reglas de semgrep.dev). Si el
binario 'semgrep' no está instalado, el test se salta con un finding
informativo -- mismo patrón que supplychain.dependency_vulnerabilities sin
pip-audit o adv.live_agent_injection sin API key. 'semgrep' es un extra
opcional (pip install -e ".[sast]"), no una dependencia core: es un paquete
pesado y no todos los usuarios de Ares necesitan esta pieza.
"""
from __future__ import annotations
import asyncio
import json
import os
import shutil

_RULES_PATH = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
                            "rules", "semgrep_mcp.yml")


def semgrep_available() -> bool:
    return shutil.which("semgrep") is not None


async def run_semgrep(source_path: str, timeout: float = 60.0) -> dict:
    """Devuelve {"ok": True, "results": [...]} o {"ok": False, "error": "..."}.
    Nunca levanta excepción -- errores del proceso/timeout/json inválido se
    normalizan para que el test los convierta en un finding informativo."""
    if not semgrep_available():
        return {"ok": False, "error": "binario 'semgrep' no encontrado en PATH"}
    if not os.path.isdir(source_path) and not os.path.isfile(source_path):
        return {"ok": False, "error": f"'{source_path}' no existe"}

    try:
        proc = await asyncio.create_subprocess_exec(
            "semgrep", "--config", _RULES_PATH, "--json", "--quiet", "--no-git-ignore", source_path,
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)
    except asyncio.TimeoutError:
        return {"ok": False, "error": f"semgrep no terminó en {timeout}s (source_path muy grande?)"}
    except Exception as e:
        return {"ok": False, "error": f"no se pudo ejecutar semgrep: {e}"}

    try:
        data = json.loads(stdout or b"{}")
    except json.JSONDecodeError:
        return {"ok": False, "error": f"semgrep no devolvió JSON válido: {(stderr or b'').decode(errors='replace')[:300]}"}

    results = []
    for r in data.get("results", []):
        extra = r.get("extra", {})
        results.append({
            "rule_id": r.get("check_id", "?"),
            "path": r.get("path", "?"),
            "line": r.get("start", {}).get("line"),
            "end_line": r.get("end", {}).get("line"),
            "message": extra.get("message", ""),
            "severity": extra.get("severity", "WARNING"),
            "category": (extra.get("metadata") or {}).get("ares_category", "unknown"),
            "snippet": (extra.get("lines") or "")[:500],
        })
    return {"ok": True, "results": results, "errors": data.get("errors", [])}
