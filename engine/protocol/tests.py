"""
Tests sobre PRIMITIVAS DEL PROTOCOLO MCP en sí -- sampling y elicitation -- no sobre
un tool particular. Hueco real documentado en la sección 12 del manual ("Protocolo:
JSON-RPC malformado, lotes, cancelaciones, sampling, elicitation -- Pendiente") y
confirmado vigente contra investigación 2026: sampling es, a la fecha, la superficie
de ataque "agentic" más citada y menos cubierta por escáneres existentes -- Unit 42
midió 78.3% de tasa de éxito de ataque encadenando 5 MCP servers contra un mismo
agente con sampling habilitado (marzo 2026).

Qué mide esto: engine/core/client.py declara soporte de sampling en el initialize
(sampling_capabilities=SamplingCapability()) y registra un callback para sampling Y
para elicitation -- ambos SIEMPRE rechazan el pedido (nunca le devuelven al server una
completion real ni un dato real del "usuario"), pero capturan el pedido completo
(mensajes, system prompt, qué contexto pide, qué le pregunta al humano) como evidencia.
Este test llama cada tool con argumentos mínimos válidos y mira qué dispara.

Qué NO mide (límite real, no descuido): si el server pide sampling/elicitation solo
bajo una condición puntual (un argumento específico, un estado previo), una sola
pasada con argumentos "válidos" genéricos puede no dispararlo -- un "sin hallazgos"
acá es "no lo pidió con ESTOS argumentos", no "nunca lo pide". Mismo techo que
cualquier prueba black-box de este motor.
"""
from __future__ import annotations
from engine.core.models import Finding, Evidence, Category
from engine.core.risk import build_vector, base_vector_for
from engine.core.registry import register_test
from engine.core.limits import cap_text

MAX_TOOLS_PROBED = 40  # tope -- "atacar al atacante", mismo criterio que el resto del motor


def _minimal_valid_args(schema: dict) -> dict:
    props = schema.get("properties", {}) or {}
    required = schema.get("required", []) or []

    def one(pschema: dict):
        if "enum" in pschema:
            return pschema["enum"][0]
        t = pschema.get("type", "string")
        return {"string": "ares-probe", "number": 1, "integer": 1, "boolean": True,
                 "array": [], "object": {}}.get(t, "ares-probe")

    return {p: one(s) for p, s in props.items() if p in required}


@register_test(
    id="protocol.sampling_elicitation_exposure",
    level=2,
    name="Sampling/elicitation: ¿el server le pide al cliente completar un prompt o sacarle un dato al usuario?",
    category=Category.PROTOCOL,
    description="Declara soporte de sampling en el handshake y llama cada tool con argumentos válidos "
                 "mínimos, observando si algún tool dispara un pedido de sampling/createMessage (el server "
                 "pide una completion de LLM real, con el prompt que ÉL define) o de elicitation/create "
                 "(el server le pide un dato al usuario en vivo). Ambos se rechazan siempre -- esto nunca "
                 "completa nada en nombre del server -- pero el pedido completo queda como evidencia.",
)
async def sampling_elicitation_exposure(target, ctx) -> list[Finding]:
    tools = ctx.get("tools") or await target.list_tools()
    findings = []

    for tool in tools[:MAX_TOOLS_PROBED]:
        name = tool["name"]
        args = _minimal_valid_args(tool.get("input_schema") or {})

        before_sampling = len(target.sampling_requests)
        before_elicit = len(target.elicitation_requests)
        await target.call_tool(name, args)

        for req in target.sampling_requests[before_sampling:]:
            messages_preview = cap_text(str(req.get("messages")), 500)
            findings.append(Finding(
                test_id="protocol.sampling_elicitation_exposure",
                title=f"Tool '{name}' solicitó sampling (el server dicta un prompt a completar)",
                category=Category.PROTOCOL,
                target=name,
                description=(
                    f"Al llamar '{name}' con argumentos válidos mínimos, el server emitió un pedido "
                    f"sampling/createMessage -- le pide al CLIENTE que haga completar, con un LLM real, "
                    f"un prompt que el SERVER define. includeContext='{req.get('include_context')}' "
                    f"(si es 'thisServer'/'allServers', el server pidió que se le adjunte contexto de "
                    f"OTRAS conversaciones/servers, no solo la suya). Mensajes: {messages_preview}"
                ),
                evidence=Evidence(request={"tool": name, "arguments": args}, response=req),
                passed=False,
                remediation="El riesgo real no está en que el server LO PIDA (es parte legítima del "
                             "protocolo) sino en si el CLIENTE que lo conecte hace cumplir aprobación "
                             "humana explícita y visibilidad completa del prompt antes de ejecutar "
                             "cualquier sampling -- verificar eso en el cliente MCP real que se vaya a "
                             "usar, no solo en este server.",
            ))

        for req in target.elicitation_requests[before_elicit:]:
            findings.append(Finding(
                test_id="protocol.sampling_elicitation_exposure",
                title=f"Tool '{name}' solicitó elicitation (le pide un dato al usuario en vivo)",
                category=Category.PROTOCOL,
                target=name,
                cvss_vector_override=build_vector(
                    base_vector_for("protocol.sampling_elicitation_exposure"),
                    S="U", UI="R", C="N", I="L",
                ),
                description=(
                    f"Al llamar '{name}' con argumentos válidos mínimos, el server emitió un pedido "
                    f"elicitation/create -- le pide directamente al USUARIO un dato en vivo, con este "
                    f"mensaje: '{cap_text(str(req.get('message')), 300)}'. Un server hostil puede usar "
                    f"esto como vector de ingeniería social dentro del propio cliente MCP (ej. pedir una "
                    f"credencial 'para continuar')."
                ),
                evidence=Evidence(request={"tool": name, "arguments": args}, response=req),
                passed=False,
                remediation="Tratar cualquier elicitation con la misma sospecha que un prompt de "
                             "phishing: el cliente MCP debería dejar clarísimo qué server está "
                             "preguntando qué, antes de que el usuario responda.",
            ))

    if not findings:
        findings.append(Finding(
            test_id="protocol.sampling_elicitation_exposure",
            title="Ningún tool solicitó sampling/elicitation con argumentos válidos mínimos",
            category=Category.PROTOCOL, target="server",
            description=f"Se llamó cada uno de los {min(len(tools), MAX_TOOLS_PROBED)} tool(s) con "
                         f"argumentos válidos mínimos; ninguno disparó sampling/createMessage ni "
                         f"elicitation/create. No descarta que lo haga bajo otra condición (otro "
                         f"argumento, otro estado previo) -- ver límite documentado arriba del archivo.",
            passed=True,
        ))
    return findings
