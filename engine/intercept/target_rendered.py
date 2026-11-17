"""
Verificación de scope sobre el comando ya renderizado antes de ejecutar una tool custom.
Puerto de ARTEX's intercept/target_rendered.go.
"""
from __future__ import annotations

import re

from engine.intercept.gate import InterceptGate

_URL_RE = re.compile(r'https?://[^\s"\';]+')


async def check_rendered_target(
    gate: InterceptGate,
    rendered_command: str,
    level: int = 1,
) -> tuple[bool, str]:
    """Extrae URLs del comando ya renderizado y verifica scope de cada una.

    Retorna (ok: bool, reason: str).
    Se llama justo antes de ejecutar cualquier comando de tool custom.
    """
    urls = _URL_RE.findall(rendered_command)
    for url in urls:
        d = await gate.check_async(url, test_id="rendered", test_level=level)
        if d.action == "deny":
            return False, f"URL {url!r} en comando denegada: {d.reason}"
    return True, "ok"
