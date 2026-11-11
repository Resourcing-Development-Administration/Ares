"""
Vigilancia de las LISTAS CURADAS de Ares -- las que `check-frameworks` no cubre porque no son
frameworks externos sino datos mantenidos a mano dentro del repo:

  * static.known_cve_check          engine/static/known_cves.py::KNOWN_MCP_CVES
  * static.typosquatting_check      engine/static/typosquatting.py::KNOWN_LEGIT_MCP_PACKAGES
  * supplychain.secret_exposure     rules/secrets_patterns.json (cache de gitleaks)

Qué hace (y por qué es distinto de solo "acordate de revisarlo"): cada chequeo CONTRASTA la lista
contra su fuente pública real, no solo mide antigüedad --
  CVEs        cada CVE del feed se verifica en OSV.dev (existe, y el fix publicado coincide con
              `affected_before`); y se consulta OSV por los paquetes oficiales para listar CVEs
              NUEVOS que el feed no tiene.
  typosquat   la lista de paquetes legítimos se compara contra src/ del repo oficial
              modelcontextprotocol/servers (servers nuevos o desaparecidos).
  secretos    el cache se compara contra la cantidad de reglas que hoy tiene gitleaks.toml y se
              avisa si es viejo (el cache registra cuándo se generó).

Nunca modifica nada: solo informa. Aplicar el cambio (sumar un CVE, un paquete) es una decisión
humana -- mismo criterio que framework_watch.py.
"""
from __future__ import annotations
import json
import os
import re
from datetime import date, datetime, timezone

import httpx

_OSV = "https://api.osv.dev/v1"
_GH = "https://api.github.com"
_HDRS = {"Accept": "application/vnd.github+json", "User-Agent": "ares-mcp-redteam-list-watch"}

# estados: ok | stale | drift | missing | error
STATUS_BAD = ("stale", "drift", "missing")


def _age_days(iso_date: str) -> float | None:
    try:
        d = date.fromisoformat(iso_date[:10])
        return (date.today() - d).days
    except Exception:
        return None


def _row(list_name: str, check: str, status: str, detail: str) -> dict:
    return {"list": list_name, "check": check, "status": status, "detail": detail}


# ---------------------------------------------------------------------------------------------
# 1. feed de CVEs

def _osv_fixed_versions(vuln: dict) -> set[str]:
    out = set()
    for aff in vuln.get("affected", []) or []:
        for rng in aff.get("ranges", []) or []:
            if rng.get("type") not in ("ECOSYSTEM", "SEMVER"):
                continue  # los rangos tipo GIT traen hashes de commit, no versiones comparables
            for ev in rng.get("events", []) or []:
                if "fixed" in ev:
                    out.add(ev["fixed"])
    return out


async def check_known_cves(client: httpx.AsyncClient) -> list[dict]:
    from engine.static import known_cves as kc
    rows: list[dict] = []

    age = _age_days(kc.LAST_REVIEWED)
    if age is None:
        rows.append(_row("known_cves", "antigüedad", "error", f"LAST_REVIEWED inválido: {kc.LAST_REVIEWED!r}"))
    elif age > kc.MAX_AGE_DAYS:
        rows.append(_row("known_cves", "antigüedad", "stale",
                          f"última revisión {kc.LAST_REVIEWED} ({age} días; límite {kc.MAX_AGE_DAYS})"))
    else:
        rows.append(_row("known_cves", "antigüedad", "ok", f"revisado {kc.LAST_REVIEWED} ({age} días)"))

    known_ids = {e["cve"] for e in kc.KNOWN_MCP_CVES}
    # OSV indexa algunas vulns solo bajo su id GHSA/PYSEC y el CVE como ALIAS: /vulns/CVE-x da 404 aunque
    # exista (CVE-2025-68144). Por eso primero se juntan todos los alias que OSV tiene por paquete.
    osv_by_cve: dict[str, dict] = {}
    pkg_vulns: dict[str, list] = {}
    for fam, (eco, pkg) in kc.OSV_PACKAGES.items():
        try:
            qr = await client.post(f"{_OSV}/query", json={"package": {"ecosystem": eco, "name": pkg}}, timeout=20)
            qr.raise_for_status()
            pkg_vulns[pkg] = qr.json().get("vulns", []) or []
        except Exception as ex:
            rows.append(_row("known_cves", f"nuevos:{pkg}", "error", f"consulta OSV falló: {ex}"))
            continue
        for v in pkg_vulns[pkg]:
            for i in {v.get("id", "")} | set(v.get("aliases", []) or []):
                if i.startswith("CVE-"):
                    osv_by_cve.setdefault(i, v)

    for e in kc.KNOWN_MCP_CVES:
        if e["cve"] in osv_by_cve:
            fixed = _osv_fixed_versions(osv_by_cve[e["cve"]])
            if fixed and e["fixed_in"] not in fixed:
                rows.append(_row("known_cves", e["cve"], "drift",
                                  f"fixed_in del feed = {e['fixed_in']} pero OSV publica {sorted(fixed)}"))
            else:
                rows.append(_row("known_cves", e["cve"], "ok", "existe en OSV" + (" y el fix coincide" if fixed else "")))
            continue
        try:
            r = await client.get(f"{_OSV}/vulns/{e['cve']}", timeout=15)
        except Exception as ex:
            rows.append(_row("known_cves", e["cve"], "error", f"OSV no respondió: {ex}"))
            continue
        if r.status_code == 404:
            rows.append(_row("known_cves", e["cve"], "drift", "OSV.dev no conoce este id (¿typo o retirado?)"))
            continue
        if r.status_code != 200:
            rows.append(_row("known_cves", e["cve"], "error", f"OSV HTTP {r.status_code}"))
            continue
        fixed = _osv_fixed_versions(r.json())
        if fixed and e["fixed_in"] not in fixed:
            rows.append(_row("known_cves", e["cve"], "drift",
                              f"fixed_in del feed = {e['fixed_in']} pero OSV publica {sorted(fixed)}"))
        else:
            rows.append(_row("known_cves", e["cve"], "ok", "existe en OSV" + (" y el fix coincide" if fixed else "")))

    # CVEs nuevos en los paquetes oficiales que el feed no tiene (agrupados por CVE: OSV repite la misma
    # vuln bajo GHSA-* y PYSEC-*)
    for pkg, vulns in pkg_vulns.items():
        missing: dict[str, str] = {}
        for v in vulns:
            ids = {v.get("id", "")} | set(v.get("aliases", []) or [])
            if ids & known_ids:
                continue
            cve = next((i for i in sorted(ids) if i.startswith("CVE-")), v.get("id"))
            missing.setdefault(cve, (v.get("summary") or "")[:70])
        if missing:
            rows.append(_row("known_cves", f"nuevos:{pkg}", "missing",
                              f"{len(missing)} vuln(s) en OSV que el feed no tiene: "
                              + "; ".join(f"{c} ({t})" for c, t in list(missing.items())[:6])))
        else:
            rows.append(_row("known_cves", f"nuevos:{pkg}", "ok", f"el feed cubre las vulns de OSV ({len(vulns)} registros)"))
    return rows


# ---------------------------------------------------------------------------------------------
# 2. typosquatting: paquetes legítimos

async def check_typosquat(client: httpx.AsyncClient) -> list[dict]:
    from engine.static import typosquatting as ts
    rows: list[dict] = []
    age = _age_days(ts.LAST_REVIEWED)
    if age is None or age > ts.MAX_AGE_DAYS:
        rows.append(_row("typosquatting", "antigüedad", "stale",
                          f"última revisión {ts.LAST_REVIEWED} ({age} días; límite {ts.MAX_AGE_DAYS})"))
    else:
        rows.append(_row("typosquatting", "antigüedad", "ok", f"revisado {ts.LAST_REVIEWED} ({age} días)"))
    try:
        r = await client.get(f"{_GH}/repos/modelcontextprotocol/servers/contents/src", headers=_HDRS, timeout=15)
        r.raise_for_status()
        upstream = {x["name"] for x in r.json() if x.get("type") == "dir"}
    except Exception as ex:
        rows.append(_row("typosquatting", "servers oficiales", "error", f"GitHub API falló: {ex}"))
        return rows
    known = set(ts._ACTIVE) | set(ts._ARCHIVED)
    new = sorted(upstream - known)
    gone = sorted(set(ts._ACTIVE) - upstream)
    if new:
        rows.append(_row("typosquatting", "servers oficiales", "missing",
                          f"servers en modelcontextprotocol/servers/src que la lista no tiene: {', '.join(new)}"))
    if gone:
        rows.append(_row("typosquatting", "servers oficiales", "drift",
                          f"marcados como ACTIVOS pero ya no están en src/ (¿archivados?): {', '.join(gone)}"))
    if not new and not gone:
        rows.append(_row("typosquatting", "servers oficiales", "ok",
                          f"los {len(upstream)} servers de src/ coinciden con la lista"))
    return rows


# ---------------------------------------------------------------------------------------------
# 3. patrones de secretos (cache de gitleaks)

async def check_secrets(client: httpx.AsyncClient, max_age_days: int = 90) -> list[dict]:
    from engine.supplychain import rule_sources as rs
    rows: list[dict] = []
    info = rs.cache_info()
    if not info:
        return [_row("secrets_patterns", "cache", "missing", "no hay rules/secrets_patterns.json (correr `ares update-rules`)")]
    stamp = info.get("updated_at")
    if stamp:
        age = _age_days(stamp)
    else:  # caches viejos no registraban la fecha: usar el mtime del archivo
        age = (datetime.now(timezone.utc) - datetime.fromtimestamp(os.path.getmtime(info["path"]), timezone.utc)).days
    if age is not None and age > max_age_days:
        rows.append(_row("secrets_patterns", "antigüedad", "stale", f"cache de {age} días (límite {max_age_days}); correr `ares update-rules`"))
    else:
        rows.append(_row("secrets_patterns", "antigüedad", "ok", f"cache de {age} días"))
    try:
        upstream = await rs.fetch_gitleaks_patterns()
    except Exception as ex:
        rows.append(_row("secrets_patterns", "gitleaks upstream", "error", f"no se pudo bajar gitleaks.toml: {ex}"))
        return rows
    local_ids = set()
    try:
        with open(info["path"], encoding="utf-8") as f:
            local_ids = {p["id"] for p in json.load(f).get("patterns", [])}
    except Exception:
        pass
    up_ids = {p["id"] for p in upstream}
    new, gone = sorted(up_ids - local_ids), sorted(local_ids - up_ids)
    if new or gone:
        rows.append(_row("secrets_patterns", "gitleaks upstream", "drift",
                          f"{len(new)} regla(s) nueva(s) en gitleaks ({', '.join(new[:5])}{'...' if len(new) > 5 else ''}), "
                          f"{len(gone)} retirada(s); correr `ares update-rules`"))
    else:
        rows.append(_row("secrets_patterns", "gitleaks upstream", "ok", f"las {len(up_ids)} reglas coinciden"))
    return rows


async def check_all_lists() -> list[dict]:
    async with httpx.AsyncClient() as client:
        rows = []
        for fn in (check_known_cves, check_typosquat, check_secrets):
            try:
                rows.extend(await fn(client))
            except Exception as ex:  # un chequeo roto nunca debe tapar a los demás
                rows.append(_row(fn.__name__, "ejecución", "error", str(ex)))
        return rows
