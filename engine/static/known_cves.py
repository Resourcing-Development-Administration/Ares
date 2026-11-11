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


# Revisión manual de este feed: `ares check-lists` avisa si pasó MAX_AGE_DAYS y verifica cada CVE
# contra OSV.dev (existe, y el fix publicado coincide con `affected_before`).
LAST_REVIEWED = "2026-11-11"
MAX_AGE_DAYS = 90
# paquete publicado de cada familia, para consultar OSV.dev por CVEs nuevos que falten acá
OSV_PACKAGES = {
    "filesystem": ("npm", "@modelcontextprotocol/server-filesystem"),
    "git": ("PyPI", "mcp-server-git"),
}

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
    {
        # agregado por `ares check-lists` (2026-11-11): OSV.dev publica esta vuln en mcp-server-git
        # y el feed no la tenía. Fuente primaria: GHSA-vjqx-cfc4-9h6v (revisada por GitHub, 2026-02-26).
        "name_hints": ["git", "server-git", "mcp-server-git"],
        "cve": "CVE-2026-27735",
        "title": "Path traversal en git_add (stagea archivos fuera del repositorio)",
        "affected_before": "2026.1.14",
        "cvss": "MODERATE (severidad GitHub Advisory; OSV solo publica un vector CVSS v4 sin score numérico)",
        "summary": "git_add no validaba que las rutas de `files` quedaran dentro del repositorio: con `../` se "
                    "podían agregar al índice archivos externos y luego exfiltrarlos con commit + push.",
        "fixed_in": "2026.1.14",
        "source": "https://github.com/modelcontextprotocol/servers/security/advisories/GHSA-vjqx-cfc4-9h6v",
    },
]


# Nombres EXACTOS con los que estos servers oficiales se autoreportan en `initialize` o se publican.
# Antes se matcheaba por substring ("filesystem" in name): cualquier server propio que contuviera
# "filesystem" o "git" en el nombre ("github-tools", "vulnerable-...-filesystem-workspace-actions")
# se marcaba con el CVE del server oficial -- falso positivo confirmado en el lab. Ahora el nombre
# normalizado debe ser IGUAL a uno de estos.
_OFFICIAL_NAMES = {
    "filesystem": {"filesystem", "server-filesystem", "secure-filesystem-server", "mcp-server-filesystem",
                    "@modelcontextprotocol/server-filesystem"},
    "git": {"git", "server-git", "mcp-git", "mcp-server-git"},
}


def _is_calver(v: str) -> bool:
    """Los paquetes oficiales usan CalVer (2025.7.1). Muchos servers se autoreportan con su propia
    versión interna (0.2.0, 1.0.0), que NO es comparable con la del paquete: compararlas diría
    '0.2.0 < 2025.7.1 -> vulnerable' para un server ya parcheado."""
    t = _version_tuple(v)
    return bool(t) and t[0] >= 2024


def _official_family(server_name: str) -> str | None:
    n = server_name.strip().lower()
    for fam, names in _OFFICIAL_NAMES.items():
        if n in names:
            return fam
    return None


def check_known_cves_detailed(server_name: str | None, server_version: str | None) -> dict:
    """{"hits": [...CVEs que aplican con certeza razonable...],
        "indeterminate": [...CVEs de un server oficial cuyo versionado autoreportado no es comparable...]}"""
    out = {"hits": [], "indeterminate": []}
    if not server_name:
        return out
    fam = _official_family(server_name)
    if fam is None:
        return out
    for entry in KNOWN_MCP_CVES:
        if not any(h in _OFFICIAL_NAMES[fam] or h == fam for h in entry["name_hints"]):
            continue
        if not server_version or not _is_calver(server_version):
            out["indeterminate"].append(entry)
            continue
        if _version_lt(server_version, entry["affected_before"]):
            out["hits"].append(entry)
    return out


def check_known_cves(server_name: str | None, server_version: str | None) -> list[dict]:
    """Solo los hits con certeza razonable (nombre oficial exacto + versión CalVer comparable
    anterior al fix). Ver check_known_cves_detailed para los casos indeterminados."""
    return check_known_cves_detailed(server_name, server_version)["hits"]
