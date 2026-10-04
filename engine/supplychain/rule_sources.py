"""
Mantiene actualizado el banco de patrones de secretos consultando fuentes
públicas y gratuitas — deliberadamente NO Cisco AI Defense ni Snyk (servicios
pagos de terceros).

Fuente usada: Gitleaks (https://github.com/gitleaks/gitleaks), proyecto OSS
público bajo licencia MIT, ampliamente usado como base de patrones de
detección de secretos. Se descarga su config TOML público (sin API key) y se
extraen los regex a un cache local versionado.

El fetch es un paso EXPLÍCITO (`python cli/main.py update-rules`), no ocurre
automáticamente durante un scan — así los scans siguen siendo 100% offline
por default, y el usuario decide cuándo tocar red para refrescar reglas.
"""
from __future__ import annotations
import json
import os
import re
import tomllib

import httpx

GITLEAKS_CONFIG_URL = "https://raw.githubusercontent.com/gitleaks/gitleaks/master/config/gitleaks.toml"
_CACHE_PATH = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))), "rules", "secrets_patterns.json")

# Gitleaks corre sobre el motor de regex de Rust/RE2, que soporta clases POSIX
# tipo [:alnum:] -- Python 're' NO las soporta: "[[:alnum:]]" compila sin error
# (solo emite FutureWarning) pero queda semánticamente roto, matchea los
# caracteres literales ':alnum:' en vez de alfanuméricos. Sin esta traducción,
# cualquier regla de gitleaks que use una clase POSIX pasa el filtro de
# "¿compila en Python?" pero NUNCA matchea nada real -- falso negativo
# silencioso en un detector de secretos, el peor tipo de bug para una
# herramienta de red team. Mapeo de clases comunes (POSIX -> rango Python):
_POSIX_CLASSES = {
    "alnum": "a-zA-Z0-9", "alpha": "a-zA-Z", "digit": "0-9", "xdigit": "0-9a-fA-F",
    "upper": "A-Z", "lower": "a-z", "space": " \\t\\n\\r\\f\\v", "blank": " \\t",
    "punct": "!-/:-@\\[-`{-~", "cntrl": "\\x00-\\x1f\\x7f", "print": "\\x20-\\x7e",
    "graph": "\\x21-\\x7e", "word": "a-zA-Z0-9_", "ascii": "\\x00-\\x7f",
}
_POSIX_CLASS_RE = re.compile(r"\[:(\w+):\]")


def _translate_posix_classes(pattern: str) -> str:
    """'[[:alnum:]_-]' -> '[a-zA-Z0-9_-]'. Si aparece una clase no mapeada, la
    dejamos intacta -- re.compile la va a rechazar con re.error más abajo y la
    regla se descarta explícitamente, en vez de quedar silenciosamente rota."""
    return _POSIX_CLASS_RE.sub(lambda m: _POSIX_CLASSES.get(m.group(1), m.group(0)), pattern)


async def fetch_gitleaks_patterns(timeout: float = 20.0) -> list[dict]:
    async with httpx.AsyncClient(timeout=timeout) as client:
        resp = await client.get(GITLEAKS_CONFIG_URL)
        resp.raise_for_status()
    data = tomllib.loads(resp.text)
    out = []
    for rule in data.get("rules", []):
        pattern = rule.get("regex")
        if not pattern:
            continue
        pattern = _translate_posix_classes(pattern)
        try:
            re.compile(pattern)
        except re.error:
            continue  # sintaxis de regex de Rust no compatible con Python re, se descarta
        out.append({
            "id": rule.get("id", "gitleaks-rule"),
            "label": rule.get("description") or rule.get("id") or "secreto (gitleaks)",
            "pattern": pattern,
        })
    return out


def save_cache(patterns: list[dict], source: str = "gitleaks"):
    os.makedirs(os.path.dirname(_CACHE_PATH), exist_ok=True)
    with open(_CACHE_PATH, "w", encoding="utf-8") as f:
        json.dump({"source": source, "count": len(patterns), "patterns": patterns}, f, indent=2, ensure_ascii=False)


def load_secret_patterns() -> list[tuple[str, str]]:
    """Devuelve [(regex, label), ...] desde el cache local, si existe. No hace red.
    Traduce clases POSIX al vuelo como red de seguridad adicional -- por si el
    cache en disco se generó con una versión anterior de fetch_gitleaks_patterns
    (antes de _translate_posix_classes) y nunca se volvió a correr update-rules."""
    if not os.path.isfile(_CACHE_PATH):
        return []
    try:
        with open(_CACHE_PATH, "r", encoding="utf-8") as f:
            data = json.load(f)
        out = []
        for p in data.get("patterns", []):
            pattern = _translate_posix_classes(p["pattern"])
            try:
                re.compile(pattern)
            except re.error:
                continue  # quedó irrecuperable incluso tras traducir -- descartar, no matchear roto
            out.append((pattern, f"{p['label']} (gitleaks:{p['id']})"))
        return out
    except Exception:
        return []


def cache_info() -> dict | None:
    if not os.path.isfile(_CACHE_PATH):
        return None
    with open(_CACHE_PATH, "r", encoding="utf-8") as f:
        data = json.load(f)
    return {"source": data.get("source"), "count": data.get("count"), "path": _CACHE_PATH}
