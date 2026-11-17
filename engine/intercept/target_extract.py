"""
Auto-detección de targets de red en parámetros de cualquier tool.
Puerto de ARTEX's intercept/target_extract.go.
"""
from __future__ import annotations

import re
from dataclasses import dataclass


@dataclass
class ExtractedTarget:
    param_name: str
    value: str
    kind: str  # "url" | "hostname" | "ip" | "command_url"


# Tools que por diseño NO tienen target de red (no chequear)
NO_TARGET_TOOLS: frozenset[str] = frozenset({
    "read_file", "write_file", "list_dir", "get_env", "get_time",
    "calculate", "format_json", "parse_json", "base64_encode", "base64_decode",
})

URL_PARAM_NAMES: frozenset[str] = frozenset({
    "url", "target", "host", "target_url", "endpoint", "base_url", "server",
    "address", "webhook_url", "callback", "redirect_uri", "origin", "source_url",
})

_HOSTNAME_RE = re.compile(r'^[\w.-]+\.[a-z]{2,}$')
_IP_RE = re.compile(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$')
_CMD_URL_RE = re.compile(r'https?://[^\s"\'<>]+')


def extract_targets(tool_name: str, args: dict) -> list[ExtractedTarget]:
    """Extrae todos los targets de red de los argumentos de una tool.

    Retorna lista vacía si tool_name está en NO_TARGET_TOOLS.
    Detecta: parámetros con nombres conocidos + URLs en valores de string + IPs en comandos.
    """
    if tool_name.lower() in NO_TARGET_TOOLS:
        return []

    results: list[ExtractedTarget] = []

    for k, v in args.items():
        if not isinstance(v, str):
            continue
        kl = k.lower()

        # Por nombre de parámetro conocido
        is_url_param = (
            kl in URL_PARAM_NAMES
            or kl.endswith("_url")
            or kl.endswith("_host")
            or kl.endswith("_endpoint")
        )
        if is_url_param:
            if v.startswith(("http://", "https://", "ws://", "wss://")):
                results.append(ExtractedTarget(k, v, "url"))
            elif _HOSTNAME_RE.match(v):
                results.append(ExtractedTarget(k, v, "hostname"))
            elif _IP_RE.match(v):
                results.append(ExtractedTarget(k, v, "ip"))
        elif len(v) < 2000:  # evitar strings enormes
            # URLs embebidas en cualquier string (p.ej. comandos)
            for m in _CMD_URL_RE.finditer(v):
                url = m.group().rstrip(".,;)")
                results.append(ExtractedTarget(k, url, "command_url"))

    # Dedup por value
    seen: set[str] = set()
    unique: list[ExtractedTarget] = []
    for t in results:
        if t.value not in seen:
            seen.add(t.value)
            unique.append(t)
    return unique
