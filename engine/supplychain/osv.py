"""
Cliente para OSV.dev (Open Source Vulnerabilities, https://osv.dev) — base de
datos pública y gratuita de CVE/GHSA/PYSEC/RustSec/etc, operada por Google/OpenSSF,
sin API key. Deliberadamente NO se usa Cisco AI Defense ni Snyk (servicios pagos
de terceros que otras herramientas de la carpeta sí usan) — solo bases públicas.

Docs: https://osv.dev/docs/
"""
from __future__ import annotations
import httpx

OSV_BATCH_URL = "https://api.osv.dev/v1/querybatch"
OSV_VULN_URL = "https://api.osv.dev/v1/vulns/{id}"
_CHUNK = 100  # límite prudente por request batch


async def query_batch(packages: list[dict], timeout: float = 15.0) -> dict[str, list[str]]:
    """packages: [{"name": ..., "version": Optional[str], "ecosystem": "PyPI"|"npm"|...}]
    Devuelve {f"{ecosystem}:{name}:{version}": [vuln_id, ...]}."""
    out: dict[str, list[str]] = {}
    async with httpx.AsyncClient(timeout=timeout) as client:
        for i in range(0, len(packages), _CHUNK):
            chunk = packages[i:i + _CHUNK]
            queries = []
            for p in chunk:
                pkg = {"name": p["name"], "ecosystem": p["ecosystem"]}
                q = {"package": pkg}
                if p.get("version"):
                    q["version"] = p["version"]
                queries.append(q)
            resp = await client.post(OSV_BATCH_URL, json={"queries": queries})
            resp.raise_for_status()
            results = resp.json().get("results", [])
            for p, r in zip(chunk, results):
                key = f"{p['ecosystem']}:{p['name']}:{p.get('version') or '*'}"
                out[key] = [v["id"] for v in (r.get("vulns") or [])]
    return out


async def fetch_vuln_details(vuln_ids: list[str], timeout: float = 15.0) -> dict[str, dict]:
    """Trae el detalle completo (severity, summary, fixed versions) de cada vuln id único."""
    details = {}
    async with httpx.AsyncClient(timeout=timeout) as client:
        for vid in dict.fromkeys(vuln_ids):  # dedup preservando orden
            try:
                resp = await client.get(OSV_VULN_URL.format(id=vid))
                resp.raise_for_status()
                details[vid] = resp.json()
            except Exception as e:
                details[vid] = {"id": vid, "summary": f"(no se pudo obtener detalle: {e})"}
    return details


def fixed_versions_of(vuln: dict) -> list[str]:
    fixed = []
    for affected in vuln.get("affected", []):
        for rng in affected.get("ranges", []):
            for event in rng.get("events", []):
                if "fixed" in event:
                    fixed.append(event["fixed"])
    return sorted(set(fixed))


def cvss_of(vuln: dict) -> dict | None:
    """Vector/score CVSS REAL si OSV lo trae (viene de la fuente original -- GHSA/NVD/etc,
    nunca inventado por Ares). None si esta vulnerabilidad no tiene CVSS publicado."""
    for s in vuln.get("severity", []):
        vector = s.get("score", "")
        if vector.startswith("CVSS"):
            base_score = _cvss_base_score(vector)
            return {"vector": vector, "type": s.get("type", ""), "base_score": base_score}
    return None


def _cvss_base_score(vector: str) -> float | None:
    """Calcula el Base Score REAL con la fórmula oficial de CVSS v3.1 (engine/core/cvss.py).
    Antes esto parseaba mal el string y devolvía el NÚMERO DE VERSIÓN del vector ("3.1")
    como si fuera el score -- bug real encontrado al calibrar Ares contra un target vivo."""
    from engine.core.cvss import calculate_base_score
    try:
        return calculate_base_score(vector)
    except Exception:
        return None


def severity_of(vuln: dict) -> str:
    """OSV no siempre trae CVSS; si lo trae, se usa el score real. Si no, se cae a
    database_specific.severity, y como último recurso una heurística por disponibilidad
    de fix -- nunca se fabrica un CVSS donde no existe."""
    cvss = cvss_of(vuln)
    if cvss and cvss["base_score"] is not None:
        num = cvss["base_score"]
        if num >= 9.0:
            return "critical"
        if num >= 7.0:
            return "high"
        if num >= 4.0:
            return "medium"
        return "low"
    ds = (vuln.get("database_specific") or {}).get("severity", "").lower()
    if ds in ("critical", "high", "medium", "low"):
        return ds
    return "high" if fixed_versions_of(vuln) else "medium"
