"""
Ataque multi-step/stateful: a diferencia de TODOS los demás tests de Ares
(una sola llamada de tool por caso), esto ejecuta la cadena real que un
atacante ejecutaría -- llamar al tool "lector", tomar algo de su output, y
pasarlo como argumento al tool "emisor" -- para CONFIRMAR que el chaining es
posible, en vez de solo inferir (como supplychain.exfiltration_chain) que
"coexisten tools que podrían encadenarse".

Decisión de diseño clave: NO reenviamos el contenido REAL que devolvió el
tool lector (podría ser un secreto de verdad) -- confirmamos la cadena con
un canario sintético como "carga útil simulada". Esto prueba la
explotabilidad de la cadena sin arriesgar exfiltrar nada real del target
durante la auditoría.

Opt-in (default_enabled=False): llama tools de "envío" reales, que en un
target de producción podrían efectivamente mandar el canario a algún lado
(webhook, email). requires_network=False porque Ares mismo no sale a red --
pero el TOOL invocado sí podría, así que además de --allow-network no hace
falta (no es Ares quien abre la conexión), este test debe correrse con
criterio: --tests adv.stateful_chain_exfil explícito o vet (que audita todo
a propósito, ya con el disclaimer de que es intrusivo).
"""
from __future__ import annotations

from engine.core.models import Finding, Evidence, Category
from engine.core.registry import register_test
from payloads.canary import new_canary
from engine.supplychain.tests import READER_RE, SENDER_RE

MAX_READERS = 3
MAX_SENDERS = 3
DATA_MARKER = "[dato-leido-de-otro-tool]"


def _string_params(schema: dict) -> list[str]:
    props = schema.get("properties", {}) or {}
    return [p for p, s in props.items() if isinstance(s, dict) and s.get("type", "string") == "string"]


def _minimal_args(schema: dict) -> dict:
    """Mismo criterio que live_agent_tests: valores placeholder mínimos para
    los parámetros requeridos, sin apuntar a fuzzear -- acá solo necesitamos
    que la llamada sea sintácticamente válida para el server."""
    required = schema.get("required", []) or []
    props = schema.get("properties", {}) or {}

    def placeholder(pschema: dict):
        t = (pschema or {}).get("type", "string")
        if "enum" in (pschema or {}):
            return pschema["enum"][0]
        return {"string": "test", "number": 1, "integer": 1, "boolean": True, "array": [], "object": {}}.get(t, "test")

    return {r: placeholder(props.get(r, {})) for r in required}


@register_test(
    id="adv.stateful_chain_exfil",
    name="Cadena de exfiltración CONFIRMADA (multi-step: lector -> emisor)",
    category=Category.ADVERSARIAL,
    description="Llama al tool lector real, y pasa un canario sintético (no el dato real leído) como "
                 "argumento al tool emisor real -- si el emisor lo acepta sin rechazarlo, confirma "
                 "explotación real de la cadena en dos llamadas, no solo que 'coexisten tools que "
                 "podrían encadenarse' (eso ya lo cubre supplychain.exfiltration_chain, heurístico). "
                 "Simula el patrón de ataque multi-step real: un agente comprometido vía prompt "
                 "injection indirecta encadena un tool de lectura con uno de envío en el mismo turno.",
    default_enabled=False,
    requires_network=False,
)
async def stateful_chain_exfil(target, ctx) -> list[Finding]:
    tools = ctx.get("tools") or await target.list_tools()
    readers = [t for t in tools if READER_RE.search(t["name"] + " " + t.get("description", ""))]
    senders = [t for t in tools if SENDER_RE.search(t["name"] + " " + t.get("description", ""))]

    if not readers or not senders:
        return [Finding(
            test_id="adv.stateful_chain_exfil", title="Sin cadena lector->emisor para confirmar",
            category=Category.ADVERSARIAL, target="server",
            description=f"{'Sin tools lectoras. ' if not readers else ''}{'Sin tools emisoras. ' if not senders else ''}"
                         "No hay candidatos para intentar encadenar.",
            passed=True,
        )]

    findings = []
    attempts = []

    for reader in readers[:MAX_READERS]:
        reader_args = _minimal_args(reader.get("input_schema") or {})
        reader_result = await target.call_tool(reader["name"], reader_args)
        if not reader_result.get("ok"):
            continue

        canary = new_canary("ARES_CHAIN")
        for sender in senders[:MAX_SENDERS]:
            sender_schema = sender.get("input_schema") or {}
            str_params = _string_params(sender_schema)
            if not str_params:
                continue

            sender_args = _minimal_args(sender_schema)
            sender_args[str_params[0]] = f"{DATA_MARKER} {canary}"
            sender_result = await target.call_tool(sender["name"], sender_args)
            attempts.append((reader["name"], sender["name"]))
            accepted = sender_result.get("ok") and not sender_result.get("is_error")

            if accepted:
                findings.append(Finding(
                    test_id="adv.stateful_chain_exfil",
                    title=f"Cadena confirmada: '{reader['name']}' -> '{sender['name']}' encadenable sin validar procedencia del dato",
                    category=Category.ADVERSARIAL,
                    target=f"{reader['name']}->{sender['name']}",
                    description=(
                        f"Se llamó '{reader['name']}' (tool lector) y se pasó un canario sintético "
                        f"(que simula datos leídos de ahí) como argumento de '{sender['name']}' (tool "
                        f"emisor). El emisor aceptó el dato sin rechazarlo por procedencia -- confirma "
                        f"que un agente comprometido puede encadenar ambas llamadas en el mismo turno "
                        f"para exfiltrar datos reales, sin que ninguna tool individual sea 'maliciosa' "
                        f"por sí sola. No se envió ningún dato real del target durante esta prueba."
                    ),
                    evidence=Evidence(
                        request={"reader": reader["name"], "reader_args": reader_args,
                                 "sender": sender["name"], "sender_arg": str_params[0], "canary": canary},
                        response=sender_result,
                        notes="canario sintético, no se reenvió el output real del tool lector",
                    ),
                    passed=False,
                    confidence_override="verified",
                    remediation="Requerir confirmación humana explícita antes de pasar datos leídos de un tool "
                                 "a un tool de red/envío en el mismo flujo del agente; o segmentar 'contexto de "
                                 "lectura' de 'contexto de acción' explícitamente (el agente no debería poder "
                                 "encadenar ambos sin un punto de control en el medio).",
                    references=["https://genai.owasp.org/llm-top-10/"],
                ))

    if not findings:
        findings.append(Finding(
            test_id="adv.stateful_chain_exfil", title="Ninguna cadena lector->emisor se confirmó ejecutable",
            category=Category.ADVERSARIAL, target="server",
            description=f"Se probaron {len(attempts)} combinación(es) lector->emisor; en ninguna el tool "
                         f"emisor aceptó el canario sin rechazarlo.",
            passed=True,
        ))
    return findings
