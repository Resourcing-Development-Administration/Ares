"""
Detección de actualizaciones en los frameworks de seguridad externos que Ares
cita (engine/core/frameworks.py): OWASP MCP Top 10, OWASP LLM/GenAI Top 10,
OWASP API Security Top 10, y MITRE ATLAS. NO actualiza nada automáticamente
-- solo avisa cuando la fuente real cambió desde la última vez que alguien
corrió `ares check-frameworks`, para que un humano decida si hay que revisar
mapeos de test_id -> framework en frameworks.py/risk.py.

Por qué esto y no como update-rules (que SÍ descarga y aplica, para
secrets_patterns.json/gitleaks): los frameworks de arriba no son datos que
se puedan aplicar mecánicamente -- un "MCP11:2026" nuevo en el Top 10 oficial
puede implicar escribir un test nuevo, no solo refrescar un JSON. Automatizar
eso sería peor que no automatizarlo: parchearía el repo con un claim de
cobertura que nadie verificó.

Mecanismo: cada fuente es un repo público de GitHub con una señal de versión
verificable sin autenticación (release con tag, o el commit HEAD de la rama
default si el proyecto no tagea) -- confirmado contra las 4 fuentes de abajo
al momento de escribirse, ver notas por entrada. Se compara contra un cache
local (rules/framework_versions.json); la primera corrida establece baseline
SIN alertar (no hay "antes" contra qué comparar), corridas siguientes alertan
si la señal cambió, y el cache solo se actualiza con --ack explícito.

Fuente deliberadamente NO incluida: "OWASP Agentic AI Threats and
Mitigations" (genai.owasp.org/resource/agentic-ai-threats-and-mitigations/)
es una página/documento, no un repo con tags/commits verificables vía API
pública sin scraping HTML -- no hay una señal de versión confiable para
automatizar esto sin quebrar apenas cambie el layout de la página. Revisar
manualmente de tanto en tanto.
"""
from __future__ import annotations
import json
import os
from dataclasses import dataclass, field
from datetime import datetime, timezone

import httpx

_CACHE_PATH = os.path.join(
    os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
    "rules", "framework_versions.json",
)

_GH_API = "https://api.github.com"
_HEADERS = {"Accept": "application/vnd.github+json", "User-Agent": "ares-mcp-redteam-framework-watch"}


@dataclass
class FrameworkSource:
    key: str                 # estable, no cambiar sin migrar el cache
    label: str                # nombre humano, para el output
    repo: str                  # "owner/repo"
    method: str                 # "release" (releases/latest, tag real) | "commit" (HEAD del branch default)
                                  # el branch default se RESUELVE contra /repos/{repo} (_default_branch),
                                  # nunca se asume -- confirmado que varía entre repos (main vs master).
    tracked_as: str = ""          # qué versión asume hoy frameworks.py, para contexto en el aviso
    url: str = ""                  # link humano (no la API) para el aviso


# Verificado contra la API pública de GitHub (sin token, rate limit 60/h --
# de sobra para correr esto manualmente de tanto en tanto) al escribirse.
FRAMEWORK_SOURCES = [
    FrameworkSource(
        key="owasp_mcp_top10", label="OWASP MCP Top 10",
        repo="OWASP/www-project-mcp-top-10", method="commit",
        tracked_as="MCP01:2025..MCP10:2025 (ver engine/core/frameworks.py::OWASP_MCP)",
        url="https://owasp.org/www-project-mcp-top-10/",
    ),
    FrameworkSource(
        key="owasp_llm_top10", label="OWASP LLM / GenAI Top 10",
        repo="GenAI-Security-Project/GenAI-LLM-Top10", method="commit",
        tracked_as="OWASP LLM Top 10 2025 (ver OWASP_LLM) -- ya existe un '2026 GenAI LLM Top 10' "
                    "publicado por este mismo proyecto: revisar si reemplaza o complementa al 2025.",
        url="https://genai.owasp.org/llm-top-10/",
    ),
    FrameworkSource(
        key="owasp_api_top10", label="OWASP API Security Top 10",
        repo="OWASP/API-Security", method="release",
        tracked_as="edición 2023 (ver OWASP_API)",
        url="https://owasp.org/API-Security/editions/2023/en/0x11-t10/",
    ),
    FrameworkSource(
        key="mitre_atlas", label="MITRE ATLAS",
        repo="mitre-atlas/atlas-data", method="release",
        tracked_as="técnicas puntuales con ID confirmado (ver frameworks.py, sección ATLAS)",
        url="https://atlas.mitre.org/matrices/ATLAS",
    ),
]


def _load_cache() -> dict:
    if not os.path.exists(_CACHE_PATH):
        return {}
    try:
        with open(_CACHE_PATH) as f:
            return json.load(f)
    except Exception:
        return {}


def _save_cache(state: dict) -> None:
    os.makedirs(os.path.dirname(_CACHE_PATH), exist_ok=True)
    with open(_CACHE_PATH, "w") as f:
        json.dump(state, f, indent=2, sort_keys=True)


async def _default_branch(client: httpx.AsyncClient, repo: str) -> str:
    """El branch default declarado en el `src.branch` de FrameworkSource es solo un
    valor de arranque -- confirmado que no sirve para todos los repos (OWASP/API-Security
    usa 'master', no 'main'): se resuelve el real contra /repos/{repo} en vez de asumir."""
    r = await client.get(f"{_GH_API}/repos/{repo}", headers=_HEADERS, timeout=10)
    r.raise_for_status()
    return r.json().get("default_branch") or "main"


async def _fetch_ref(client: httpx.AsyncClient, src: FrameworkSource) -> dict:
    """Devuelve {"ref": str_corto, "published_at": iso|None, "html_url": str} o
    {"error": str} si la fuente no se pudo consultar (red, repo movido, rate limit)."""
    try:
        if src.method == "release":
            r = await client.get(f"{_GH_API}/repos/{src.repo}/releases/latest", headers=_HEADERS, timeout=10)
            if r.status_code == 404:
                # algunos repos no tagean releases -- degradar al commit HEAD del branch
                # default REAL (resuelto, no asumido -- ver _default_branch).
                branch = await _default_branch(client, src.repo)
                r2 = await client.get(f"{_GH_API}/repos/{src.repo}/commits/{branch}", headers=_HEADERS, timeout=10)
                r2.raise_for_status()
                d = r2.json()
                return {"ref": d["sha"][:12], "published_at": d["commit"]["committer"]["date"],
                        "html_url": d.get("html_url", "")}
            r.raise_for_status()
            d = r.json()
            return {"ref": d.get("tag_name", d.get("name", "?")), "published_at": d.get("published_at"),
                    "html_url": d.get("html_url", "")}
        else:  # "commit"
            branch = await _default_branch(client, src.repo)
            r = await client.get(f"{_GH_API}/repos/{src.repo}/commits/{branch}", headers=_HEADERS, timeout=10)
            r.raise_for_status()
            d = r.json()
            return {"ref": d["sha"][:12], "published_at": d["commit"]["committer"]["date"],
                    "html_url": d.get("html_url", "")}
    except Exception as e:
        return {"error": str(e)}


async def check_for_updates() -> list[dict]:
    """Consulta las 4 fuentes y devuelve un resultado por cada una:
    {key, label, status: "baseline_set"|"sin_cambios"|"POSIBLE_ACTUALIZACION"|"error",
     current_ref, cached_ref, published_at, url, tracked_as}
    Nunca escribe el cache -- eso es responsabilidad explícita de save_baseline()."""
    cache = _load_cache()
    results = []
    async with httpx.AsyncClient() as client:
        for src in FRAMEWORK_SOURCES:
            fetched = await _fetch_ref(client, src)
            cached = cache.get(src.key, {})
            if "error" in fetched:
                results.append({
                    "key": src.key, "label": src.label, "status": "error",
                    "error": fetched["error"], "url": src.url, "tracked_as": src.tracked_as,
                })
                continue

            current_ref = fetched["ref"]
            cached_ref = cached.get("ref")
            if cached_ref is None:
                status = "baseline_set"
            elif cached_ref != current_ref:
                status = "POSIBLE_ACTUALIZACION"
            else:
                status = "sin_cambios"

            results.append({
                "key": src.key, "label": src.label, "status": status,
                "current_ref": current_ref, "cached_ref": cached_ref,
                "published_at": fetched.get("published_at"),
                "html_url": fetched.get("html_url") or src.url,
                "url": src.url, "tracked_as": src.tracked_as,
            })
    return results


def save_baseline(results: list[dict]) -> None:
    """Acepta el estado actual como nuevo baseline -- SOLO se llama con --ack
    explícito desde la CLI, nunca automáticamente desde check_for_updates()."""
    cache = _load_cache()
    now = datetime.now(timezone.utc).isoformat()
    for r in results:
        if r["status"] == "error":
            continue
        cache[r["key"]] = {"ref": r["current_ref"], "checked_at": now}
    _save_cache(cache)


def oldest_baseline_age_days() -> float | None:
    """Antigüedad en días del --ack más viejo entre las fuentes trackeadas -- None si
    nunca se corrió --ack (sin baseline del todo) o si no hay ninguna fuente cacheada
    todavía. Pensado para --fail-if-stale en CI: "nadie revisó esto en los últimos N
    días" es una señal tan útil como "cambió" -- un pipeline que nunca corre este
    comando nunca se entera de nada, con o sin alertas."""
    cache = _load_cache()
    if not cache:
        return None
    now = datetime.now(timezone.utc)
    ages = []
    for entry in cache.values():
        checked_at = entry.get("checked_at")
        if not checked_at:
            continue
        try:
            dt = datetime.fromisoformat(checked_at)
        except ValueError:
            continue
        ages.append((now - dt).total_seconds() / 86400)
    return max(ages) if ages else None
