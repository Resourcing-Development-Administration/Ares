"""
Feed curado de CVEs específicos de servers MCP oficiales/ampliamente
desplegados -- a diferencia de supplychain.dependency_vulnerabilities
(genérico, vía OSV.dev sobre requirements.txt/package.json de --source-path,
un archivo del USUARIO), esto compara el server_info.name/version que el
TARGET se autoreporta en `initialize` contra un feed mantenido a mano.

Confianza: heuristic, no verified -- server_info lo declara el propio
target bajo auditoría, que podría estar mintiendo (versión falsa para
ocultar el problema, o para generar una falsa alarma). Es una señal fuerte
para investigar, no una confirmación independiente como sí lo es OSV.dev
sobre un manifiesto que el usuario controla.

Cada entrada de acá fue verificada contra una fuente pública real al
momento de escribirse (ver 'source' de cada una) -- nunca un CVE
inventado. Mantenimiento manual: revisar periódicamente contra avisos de
seguridad de servers MCP oficiales/populares y sumar entradas nuevas.
"""
from __future__ import annotations


def _version_tuple(v: str) -> tuple[int, ...]:
    parts = []
    for p in v.strip().lstrip("v").split("."):
        num = ""
        for ch in p:
            if ch.isdigit():
                num += ch
            else:
                break
        parts.append(int(num) if num else 0)
    return tuple(parts)


def _version_lt(a: str, b: str) -> bool:
    ta, tb = _version_tuple(a), _version_tuple(b)
    n = max(len(ta), len(tb))
    ta = ta + (0,) * (n - len(ta))
    tb = tb + (0,) * (n - len(tb))
    return ta < tb


KNOWN_MCP_CVES = [
    {
        "name_hints": ["filesystem", "server-filesystem"],
        "cve": "CVE-2025-53109",
        "title": "EscapeRoute: symlink bypass a escritura fuera de sandbox (persistencia/RCE)",
        "affected_before": "2025.7.1",
        "cvss": 8.4,
        "summary": "El server seguía symlinks sin re-validar que el destino resuelto seguía dentro del "
                    "directorio permitido -- un symlink armado en un directorio escribible permite escribir "
                    "fuera del sandbox (PoC publicado: LaunchAgent malicioso para persistencia en macOS).",
        "fixed_in": "2025.7.1",
        "source": "https://cymulate.com/blog/cve-2025-53109-53110-escaperoute-anthropic/",
    },
    {
        "name_hints": ["filesystem", "server-filesystem"],
        "cve": "CVE-2025-53110",
        "title": "EscapeRoute: bypass de containment de directorio por prefix-matching ingenuo",
        "affected_before": "2025.7.1",
        "cvss": 7.3,
        "summary": "La validación de directorio permitido usaba prefix-matching ingenuo: un directorio "
                    "'/allow_dir_evil' pasaba como permitido si el allowlist tenía '/allow_dir' -- lectura/"
                    "escritura fuera del scope previsto.",
        "fixed_in": "2025.7.1",
        "source": "https://cymulate.com/blog/cve-2025-53109-53110-escaperoute-anthropic/",
    },
    {
        "name_hints": ["git", "server-git", "mcp-server-git"],
        "cve": "CVE-2025-68143",
        "title": "git_init sin restricción de path (path traversal a inicialización arbitraria de repo)",
        "affected_before": "2025.9.25",
        "cvss": 8.8,
        "summary": "git_init aceptaba cualquier path del filesystem sin validación -- permite inicializar un "
                    "repo git en un directorio sensible como paso de una cadena de explotación mayor.",
        "fixed_in": "2025.9.25",
        "source": "https://vulnerablemcp.info/vuln/cve-2025-68145-anthropic-git-mcp-rce-chain.html",
    },
    {
        "name_hints": ["git", "server-git", "mcp-server-git"],
        "cve": "CVE-2025-68144",
        "title": "Argument injection en git_diff/git_checkout (sobrescritura arbitraria de archivos)",
        "affected_before": "2025.12.18",
        "cvss": 8.1,
        "summary": "git_diff/git_checkout pasaban argumentos controlados por el cliente directo al CLI de git "
                    "sin sanitizar -- un valor tipo '--output=/ruta' se interpreta como flag en vez de ref, "
                    "permitiendo sobrescribir archivos arbitrarios.",
        "fixed_in": "2025.12.18",
        "source": "https://github.com/advisories/GHSA-9xwc-hfwc-8w59",
    },
    {
        "name_hints": ["git", "server-git", "mcp-server-git"],
        "cve": "CVE-2025-68145",
        "title": "Bypass de validación de path (acceso fuera del repo permitido)",
        "affected_before": "2025.12.18",
        "cvss": 7.1,
        "summary": "El mecanismo para restringir el server a un repo específico no aplicaba realmente la "
                    "restricción -- acceso a repos fuera del allowlist configurado.",
        "fixed_in": "2025.12.18",
        "source": "https://vulnerablemcp.info/vuln/cve-2025-68145-anthropic-git-mcp-rce-chain.html",
    },
]


def check_known_cves(server_name: str | None, server_version: str | None) -> list[dict]:
    """server_name/version: lo que el target autoreportó en `initialize`
    (serverInfo) -- ver engine/core/client.py::MCPTarget.server_info.
    Devuelve las entradas cuyo name_hint matchea Y (si hay versión) la
    reportada es anterior al fix. Sin versión reportada, se listan igual
    (mejor falso positivo a revisar manualmente que falso negativo)."""
    if not server_name:
        return []
    name_lower = server_name.lower()
    hits = []
    for entry in KNOWN_MCP_CVES:
        if not any(hint in name_lower for hint in entry["name_hints"]):
            continue
        if server_version:
            try:
                if not _version_lt(server_version, entry["affected_before"]):
                    continue  # versión reportada ya es >= al fix conocido
            except Exception:
                pass
        hits.append(entry)
    return hits
