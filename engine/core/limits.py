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

# Cantidad de tools que se procesan de un solo tools/list. A diferencia de
# MAX_TEXT_FOR_ANALYSIS (que acota cada descripción), esto acota cuántas
# entradas se construyen en memoria -- un server hostil puede declarar
# millones de tools con descripciones cortas (cada una pasa el cap de texto
# individual) para agotar RAM antes de que cualquier timeout por-test tenga
# chance de cortar algo, ya que list_tools corre una sola vez al conectar.
MAX_TOOLS_LISTED = 5_000

# supplychain.tool_squatting compara CADA PAR de nombres de tool (O(n^2), jaro_winkler puro
# Python sin aceleración en C) -- confirmado empíricamente: a 5000 tools (el tope de arriba)
# son ~12.5M pares, ~86s, más que test_timeout_s por defecto (60s). Antes de MAX_TOOLS_LISTED
# esto nunca se alcanzaba (el target se caía/colgaba en list_tools primero) -- ahora que ese
# límite deja pasar hasta 5000 tools reales, este test necesita su propio tope más chico.
MAX_TOOLS_FOR_PAIRWISE_SIMILARITY = 1_500

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
