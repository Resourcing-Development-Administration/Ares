"""
Typosquatting de paquetes MCP: distinto de supplychain.tool_squatting (que
compara nombres de TOOLS entre sí, dentro del mismo server). Esto compara
el nombre de PAQUETE que el usuario cree estar instalando (--package-name,
ej. lo que puso en su mcpServers config o en package.json/requirements.txt)
contra una lista curada de paquetes MCP oficiales/ampliamente conocidos --
el vector real es "instalé 'mcp-server-fetchh' pensando que era el oficial
'mcp-server-fetch'".

Lista curada verificada contra el repo oficial modelcontextprotocol/servers
al momento de escribirse (incluye servers de referencia activos y
archivados -- los archivados siguen siendo blanco real de typosquatting
porque mucha documentación/tutoriales vieja todavía los referencia).
Mantenimiento manual, no exhaustivo -- no reemplaza revisar la fuente real
del paquete antes de instalar nada.
"""
from __future__ import annotations
from engine.supplychain.similarity import jaro_winkler

# Servers de referencia oficiales activos (modelcontextprotocol/servers, 2026)
_ACTIVE = ["everything", "fetch", "filesystem", "sequentialthinking", "memory", "git", "time"]
# Archivados -- ya no mantenidos, pero siguen siendo blanco real de typosquatting
_ARCHIVED = [
    "aws-kb-retrieval", "brave-search", "github", "gitlab", "gdrive",
    "google-maps", "postgres", "puppeteer", "redis", "sentry", "slack",
]

KNOWN_LEGIT_MCP_PACKAGES = sorted({
    *(f"@modelcontextprotocol/server-{n}" for n in _ACTIVE + _ARCHIVED),
    *(f"mcp-server-{n}" for n in _ACTIVE + _ARCHIVED),
    *_ACTIVE, *_ARCHIVED,
})

TYPOSQUAT_SIMILARITY_THRESHOLD = 0.88  # más alto que tool_squatting (0.82): acá comparamos contra un
                                        # paquete de TERCEROS de confianza declarada, no tools del mismo server


def check_typosquatting(package_name: str) -> dict | None:
    """Devuelve None si package_name ES uno de los conocidos (legítimo, exacto)
    o si no se parece a ninguno (nombre propio/custom, no hay nada sospechoso
    en no matchear). Devuelve un dict {matched_against, similarity} si es
    sospechosamente parecido a uno conocido SIN ser exacto -- el patrón
    clásico de typosquat."""
    name_lower = package_name.strip().lower()
    if not name_lower:
        return None
    if name_lower in KNOWN_LEGIT_MCP_PACKAGES:
        return None  # es el paquete legítimo real, exacto

    best_match, best_sim = None, 0.0
    for known in KNOWN_LEGIT_MCP_PACKAGES:
        sim = jaro_winkler(name_lower, known.lower())
        if sim > best_sim:
            best_match, best_sim = known, sim

    if best_match and best_sim >= TYPOSQUAT_SIMILARITY_THRESHOLD:
        return {"matched_against": best_match, "similarity": best_sim}
    return None
