"""
Límites defensivos del propio motor de Ares contra un target MCP hostil que
intente agotar CPU/memoria del escáner en vez de (o además de) atacar a un
agente -- "atacar al atacante".

Confirmado empíricamente (no es teórico): una sola tool con una descripción
de ~10MB hizo que supplychain.secret_exposure (~200 regex de rules/secrets_
patterns.json corridas sobre esa descripción) tardara ~57s, contra ~0.2s de
baseline con un server normal -- ver evil_server.py usado para reproducirlo.
El motor no tiene otra defensa contra esto salvo el timeout global por test
(ScanConfig.test_timeout_s) -- que corta el test entero, no solo la parte
cara, y no evita el gasto de CPU hasta que dispara.

Única fuente de verdad para "cuánto texto no confiable de un target se
analiza con regex" -- ningún test debería definir su propio cap suelto.
"""
from __future__ import annotations

# Generoso para cualquier descripción/schema LEGÍTIMO (la mayoría son <2KB);
# un target que necesita más que esto para describir un tool está, como
# mínimo, siendo poco razonable -- y en la práctica es la señal misma de este
# tipo de ataque. Se aplica a texto que se analiza con regex (descripciones,
# params, blobs de secret_exposure/malicious_patterns).
MAX_TEXT_FOR_ANALYSIS = 200_000

# Contenido de una respuesta real de call_tool/read_resource -- más holgado
# porque ahí sí hay casos legítimos de respuestas grandes (dumps, archivos),
# pero sigue acotado para no permitir OOM ni inflar el costo de los checks
# de leak-pattern que corren sobre esto.
MAX_RESPONSE_CONTENT = 2_000_000

_TRUNC_SUFFIX = "\n…[truncado por Ares: excede {limit} chars -- posible intento de agotar recursos del escáner]"


def cap_text(text, limit: int = MAX_TEXT_FOR_ANALYSIS) -> str:
    """Trunca `text` a `limit` chars, dejando una marca explícita de que se
    truncó (nunca falla silenciosamente ni dict/None -> explota distinto)."""
    if text is None:
        return ""
    text = str(text)
    if len(text) <= limit:
        return text
    return text[:limit] + _TRUNC_SUFFIX.format(limit=limit)


def was_truncated(text) -> bool:
    return isinstance(text, str) and text.endswith("]") and "truncado por Ares" in text[-120:]
