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
    level=3,
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


# =============================================================================================
# Cadenas de N tools (multi-step genérico) y roundtrip de inyección almacenada
# =============================================================================================
#
# adv.stateful_chain_exfil cubre UN patrón de dos llamadas (lector -> emisor). Esto lo generaliza:
#   fuente -> [propagador]* -> emisor, hasta MAX_PROPAGATORS propagadores en el medio.
#
# Cómo se evita inventar cadenas que no existen (el falso positivo clásico de "coexisten tools que
# podrían encadenarse"): cada eslabón intermedio se PRUEBA. Un "propagador" es un tool al que se le
# pasa un canario sintético y que lo devuelve en su salida (tal cual o codificado: base64/hex/url/
# mayúsculas) -- es decir, el dato tainteado realmente sobrevive el paso. Solo entonces se ensambla
# la cadena y se ejecuta de punta a punta pasando la SALIDA REAL de cada propagador como entrada del
# siguiente, hasta el emisor. Como lo único que circula es el canario (nunca la salida real del tool
# fuente, que podría ser un secreto), la prueba no exfiltra nada real.

import base64 as _b64
import re as _re
import urllib.parse as _urlparse

from engine.core.schema_utils import minimal_valid_args, normalize_schema
from payloads.prompt_injection import build_injection_payloads

MAX_PROPAGATORS = 2          # largo máximo de la cadena = fuente + 2 propagadores + emisor
MAX_PROPAGATOR_CANDIDATES = 12
MAX_CHAINS = 6

_SOURCE_NAME_RE = _re.compile(r"^(get|read|list|fetch|search|query|cat|dump|load|retrieve|find|show|view|describe)", _re.I)
_SINK_NAME_RE = _re.compile(r"send|post|email|mail|webhook|upload|notify|publish|transmit|exfil|forward|tweet|slack|sms", _re.I)
_UNSAFE_NAME_RE = _re.compile(
    r"delete|drop|remove|destroy|wipe|truncate|purge|kill|exec|shell|command|run_|install|deploy|reset|restart|"
    r"shutdown|commit|push|pay|transfer|charge|write|create|insert|update|set_|put", _re.I)
_DATA_PARAM_PREF = ("content", "text", "data", "body", "message", "input", "payload", "value", "query", "note", "prompt", "msg", "string")


def _str_params(tool: dict) -> list[str]:
    props = normalize_schema(tool.get("input_schema") or {}).get("properties", {}) or {}
    return [p for p, s in props.items() if isinstance(s, dict) and s.get("type", "string") in ("string", None)]


def _data_param(tool: dict) -> str | None:
    ps = _str_params(tool)
    for pref in _DATA_PARAM_PREF:
        for p in ps:
            if pref in p.lower():
                return p
    return ps[0] if ps else None


def _variants(canary: str) -> list[tuple[str, str]]:
    """Formas en que un tool puede devolver el canario 'procesado' (transformación reversible/trivial)."""
    raw = canary.encode()
    return [
        ("tal cual", canary), ("minúsculas", canary.lower()), ("mayúsculas", canary.upper()),
        ("base64", _b64.b64encode(raw).decode()), ("hex", raw.hex()),
        ("url-encoded", _urlparse.quote(canary, safe="")), ("invertido", canary[::-1]),
    ]


def _taint_form(text: str, canary: str) -> str | None:
    for label, v in _variants(canary):
        if v and v in text:
            return label
    return None


def _args_with(tool: dict, param: str, value: str) -> dict:
    args = minimal_valid_args(tool.get("input_schema") or {})
    args[param] = value
    return args


def _usable(result: dict) -> bool:
    return bool(result.get("ok")) and not result.get("is_error")


@register_test(
    id="adv.multistep_chain",
    level=3,
    name="Cadena multi-step CONFIRMADA de N tools (fuente -> propagadores -> emisor)",
    category=Category.ADVERSARIAL,
    description="Generaliza adv.stateful_chain_exfil a cadenas de hasta 4 tools. Prueba cada tool intermedio con un "
                 "canario sintético y solo usa como eslabón al que lo devuelve en su salida (tal cual o codificado); "
                 "ensambla fuente -> propagador(es) -> emisor y la ejecuta de punta a punta pasando la salida REAL de "
                 "cada paso como entrada del siguiente. Confirma explotación por ejecución, no por coexistencia de "
                 "tools; nunca reenvía datos reales del tool fuente (solo circula el canario). Opt-in: llama a tools "
                 "de envío reales.",
    default_enabled=False,
    requires_network=False,
)
async def multistep_chain(target, ctx) -> list[Finding]:
    tid = "adv.multistep_chain"
    tools = ctx.get("tools") or await target.list_tools()
    by_name = {t["name"]: t for t in tools}

    sinks = [t for t in tools if _SINK_NAME_RE.search(t["name"]) and _data_param(t)]
    sources = [t for t in tools if _SOURCE_NAME_RE.search(t["name"]) and t not in sinks]
    cands = [t for t in tools if t not in sinks and t not in sources and _data_param(t)
             and not _UNSAFE_NAME_RE.search(t["name"])]
    # los propios lectores con parámetro de entrada también pueden propagar (ej. search(query) que devuelve la query)
    cands += [t for t in sources if _data_param(t) and not _UNSAFE_NAME_RE.search(t["name"])]

    def ok(msg: str) -> list[Finding]:
        return [Finding(test_id=tid, title="Sin cadena multi-step confirmable", category=Category.ADVERSARIAL,
                        target="server", description=msg, passed=True)]

    if not sources or not sinks:
        return ok(f"{'Sin tools fuente (get/read/list/fetch/search...). ' if not sources else ''}"
                  f"{'Sin tools emisores (send/post/email/webhook/upload...). ' if not sinks else ''}"
                  f"No hay extremos para una cadena.")

    # 1. ¿qué tools PROPAGAN de verdad el dato?
    propagators: dict[str, dict] = {}
    probes = []
    for t in cands[:MAX_PROPAGATOR_CANDIDATES]:
        param = _data_param(t)
        canary = new_canary("ARES_HOP")
        res = await target.call_tool(t["name"], _args_with(t, param, canary))
        probes.append(t["name"])
        if not _usable(res):
            continue
        form = _taint_form(str(res.get("content", "")), canary)
        if form:
            propagators[t["name"]] = {"param": param, "form": form}

    # 2. ensamblar cadenas: fuente -> [1..MAX_PROPAGATORS propagadores] -> emisor
    prop_names = list(propagators)
    chains: list[list[str]] = []
    for s in sources:
        for k in sinks:
            for p1 in prop_names:
                if p1 in (s["name"], k["name"]):
                    continue
                chains.append([s["name"], p1, k["name"]])
                for p2 in prop_names:
                    if p2 not in (s["name"], k["name"], p1):
                        chains.append([s["name"], p1, p2, k["name"]])
    # preferir cadenas con propagadores distintos y más cortas primero
    chains.sort(key=lambda c: (len(c), c))
    seen_pairs, picked = set(), []
    for c in chains:
        key = (c[0], c[-1], tuple(c[1:-1]))
        if key not in seen_pairs:
            seen_pairs.add(key)
            picked.append(c)
        if len(picked) >= MAX_CHAINS:
            break

    if not picked:
        return ok(f"Se probaron {len(probes)} tool(s) intermedio(s) con un canario sintético y ninguno lo devolvió en "
                  f"su salida: no hay un eslabón por el que el dato fluya entre una fuente y un emisor, así que "
                  f"ninguna cadena de más de dos tools es ejecutable.")

    # 3. ejecutar de punta a punta
    findings: list[Finding] = []
    attempted = 0
    for chain in picked:
        attempted += 1
        src, props, sink = by_name[chain[0]], chain[1:-1], by_name[chain[-1]]
        src_res = await target.call_tool(src["name"], minimal_valid_args(src.get("input_schema") or {}))
        if not _usable(src_res):
            continue  # la fuente no es invocable tal cual: la cadena no es ejecutable

        canary = new_canary("ARES_MSC")
        data = canary
        hops = []
        broken = False
        for pname in props:
            pt = by_name[pname]
            res = await target.call_tool(pname, _args_with(pt, propagators[pname]["param"], data))
            form = _taint_form(str(res.get("content", "")), canary) if _usable(res) else None
            hops.append({"tool": pname, "ok": _usable(res), "canary_survived": form})
            if not form:
                broken = True
                break
            data = str(res.get("content", ""))[:1500]  # la salida REAL del paso es la entrada del siguiente
        if broken:
            continue
        sink_res = await target.call_tool(sink["name"], _args_with(sink, _data_param(sink), data))
        if not _usable(sink_res):
            continue
        reaches = bool(_taint_form(str(sink_res.get("content", "")), canary))
        hops_desc = ", ".join("%s [%s]" % (h["tool"], h["canary_survived"]) for h in hops)  # (3.11: sin comillas anidadas en f-string)
        findings.append(Finding(
            test_id=tid,
            title=f"Cadena de {len(chain)} tools confirmada: {' -> '.join(chain)}",
            category=Category.ADVERSARIAL, target="->".join(chain),
            description=(
                f"Se ejecutó la cadena completa. '{src['name']}' (fuente) es invocable; el canario sintético "
                f"sobrevivió {len(props)} paso(s) intermedio(s) ({hops_desc}) "
                f"y '{sink['name']}' (emisor) lo aceptó sin rechazarlo"
                f"{' y lo devolvió en su respuesta' if reaches else ''}. Un agente comprometido por prompt injection "
                f"indirecta puede encadenar estas {len(chain)} llamadas en un solo turno para sacar datos, aunque "
                f"ninguna tool individual sea 'maliciosa'. No se reenvió ningún dato real del tool fuente."),
            evidence=Evidence(
                request={"chain": chain, "canary": canary, "hops": hops, "sink_arg": _data_param(sink)},
                response=sink_res,
                notes="canario sintético: solo circuló el canario, no la salida real de la fuente"),
            passed=False,
            confidence_override="verified",
            remediation="Requerir confirmación humana antes de pasar a un tool emisor datos que vengan de otros "
                         "tools, o segmentar 'contexto de lectura' de 'contexto de acción'. Cortar cadenas largas "
                         "limitando qué tools puede invocar el agente en un mismo turno.",
            references=["https://genai.owasp.org/llm-top-10/"],
        ))

    if not findings:
        findings.append(Finding(
            test_id=tid, title="Ninguna cadena multi-step se confirmó ejecutable", category=Category.ADVERSARIAL,
            target="server",
            description=f"Se ensamblaron {len(picked)} cadena(s) candidata(s) a partir de {len(prop_names)} "
                         f"propagador(es) confirmado(s); en ninguna la fuente fue invocable, el canario sobrevivió "
                         f"todos los pasos y el emisor lo aceptó.",
            passed=True))
    return findings


_WRITER_NAME_RE = _re.compile(r"^(save|store|write|add|create|set|put|append|remember|record|log|insert|note|upload|post)", _re.I)
_WRITER_EXCLUDE_RE = _re.compile(r"delete|drop|remove|destroy|wipe|exec|shell|command|send|email|mail|webhook|notify|pay|transfer|"
                                   r"deploy|install|reset|restart|shutdown|commit|push|kill", _re.I)


@register_test(
    id="adv.stored_injection_roundtrip",
    level=3,
    name="Inyección almacenada: lo escrito por un tool vuelve intacto por otro (second-order)",
    category=Category.ADVERSARIAL,
    description="Escribe un payload de prompt injection (con marcador único) mediante tools de escritura "
                 "(save/store/add/note...) y verifica si algún tool de lectura lo devuelve INTACTO. Cierra el ciclo "
                 "multi-step que adv.injection_passthrough solo infiere ('save_note -> read_note'): acá se ejecuta "
                 "de verdad. Opt-in: ESCRIBE un dato inocuo (un texto con marcador) en el estado del target.",
    default_enabled=False,
    requires_network=False,
)
async def stored_injection_roundtrip(target, ctx) -> list[Finding]:
    tid = "adv.stored_injection_roundtrip"
    tools = ctx.get("tools") or await target.list_tools()
    writers = [t for t in tools if _WRITER_NAME_RE.search(t["name"]) and not _WRITER_EXCLUDE_RE.search(t["name"])
               and _str_params(t)]
    readers = [t for t in tools if _SOURCE_NAME_RE.search(t["name"]) and not _SINK_NAME_RE.search(t["name"])]

    def ok(msg: str) -> list[Finding]:
        return [Finding(test_id=tid, title="Sin roundtrip de inyección almacenada", category=Category.ADVERSARIAL,
                        target="server", description=msg, passed=True)]

    if not writers or not readers:
        return ok(f"{'Sin tools de escritura (save/store/add/note...). ' if not writers else ''}"
                  f"{'Sin tools de lectura (get/read/list/search...). ' if not readers else ''}")

    inj = build_injection_payloads()[0]
    findings: list[Finding] = []
    for w in writers[:4]:
        params = _str_params(w)[:3]
        args = minimal_valid_args(w.get("input_schema") or {})
        for p in params:
            args[p] = inj["payload"]
        wres = await target.call_tool(w["name"], args)
        if not _usable(wres):
            continue
        for r in readers[:4]:
            if r["name"] == w["name"]:
                continue
            rargs = minimal_valid_args(r.get("input_schema") or {})
            # si el lector necesita una clave/consulta, ofrecer el marcador (no el payload entero)
            for p in _str_params(r):
                if p in (r.get("input_schema", {}).get("required") or []) or p.lower() in ("query", "q", "search", "key", "name", "title"):
                    rargs.setdefault(p, inj["marker"])
            rres = await target.call_tool(r["name"], rargs)
            body = str(rres.get("content", ""))
            if _usable(rres) and inj["payload"] in body:
                findings.append(Finding(
                    test_id=tid,
                    title=f"Inyección almacenada: '{w['name']}' -> '{r['name']}' devuelve el payload intacto",
                    category=Category.ADVERSARIAL, target=f"{w['name']}->{r['name']}",
                    description=(f"Se escribió con '{w['name']}' un texto con instrucciones dirigidas a un LLM "
                                  f"(marcador {inj['marker']}) y '{r['name']}' lo devolvió completo y sin escapar ni "
                                  f"delimitar. Todo lo que un tercero logre escribir en este almacén (otro usuario, un "
                                  f"documento, un email) llegará al contexto del agente como si fuera una instrucción."),
                    evidence=Evidence(request={"writer": w["name"], "reader": r["name"], "payload": inj["payload"]},
                                      response=rres),
                    passed=False, confidence_override="verified",
                    remediation="Delimitar/escapar el contenido almacenado al devolverlo al modelo y marcarlo "
                                 "explícitamente como DATO no confiable (never mix instructions and data).",
                    references=["https://embracethered.com/blog/posts/2023/chatgpt-plugin-vulns-chat-with-code/"],
                ))
                break  # un lector alcanza por escritor
    if not findings:
        findings.append(Finding(
            test_id=tid, title="Ningún roundtrip de inyección almacenada", category=Category.ADVERSARIAL, target="server",
            description="Los datos escritos con los tools de escritura probados no volvieron intactos por ningún "
                         "tool de lectura probado (o la escritura fue rechazada).",
            passed=True))
    return findings
