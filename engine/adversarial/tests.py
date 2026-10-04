"""
Tests adversariales: simulan intenciones reales de un atacante, no solo
robustez técnica. Aquí es donde se cubre lo que las herramientas sueltas
(mcp-scan, etc.) suelen dejar afuera o hacer de forma superficial.
"""
from __future__ import annotations
import asyncio
import re

from engine.core.models import Finding, Evidence, Category
from engine.core.registry import register_test
from engine.core.risk import build_vector, base_vector_for
from payloads.prompt_injection import build_injection_payloads

SSRF_TARGETS = [
    "http://169.254.169.254/latest/meta-data/",       # AWS IMDSv1
    "http://169.254.169.254/latest/api/token",        # AWS IMDSv2 (requiere PUT normalmente, pero un GET ya confirma alcance)
    "http://metadata.google.internal/computeMetadata/v1/",  # GCP
    "http://169.254.169.254/metadata/instance?api-version=2021-02-01",  # Azure IMDS
    "http://169.254.169.254/opc/v2/instance/",        # Oracle Cloud (OCI)
    "http://100.100.100.200/latest/meta-data/",       # Alibaba Cloud
    "http://169.254.169.254/metadata/v1/",            # DigitalOcean
    "https://kubernetes.default.svc/api/v1/namespaces/default/secrets",  # K8s API server (si corre en un pod)
    "http://localhost:22",
    "http://127.0.0.1:6379",                          # redis local típico
    "file:///etc/passwd",
]


def _string_params(schema: dict) -> list[str]:
    props = schema.get("properties", {}) or {}
    return [p for p, s in props.items() if isinstance(s, dict) and s.get("type", "string") == "string"]


@register_test(
    id="adv.injection_passthrough",
    name="Passthrough de prompt injection sin sanitizar",
    category=Category.ADVERSARIAL,
    description="Envía payloads de prompt injection como argumento y verifica si el tool los almacena/refleja "
                 "intactos (indicando que no hay sanitización antes de que ese contenido pueda ser re-consumido "
                 "por un LLM en un flujo posterior, ej. save_note -> read_note).",
)
async def injection_passthrough(target, ctx) -> list[Finding]:
    tools = ctx.get("tools") or await target.list_tools()
    findings = []
    payloads = build_injection_payloads()

    for tool in tools:
        schema = tool.get("input_schema") or {}
        str_params = _string_params(schema)
        if not str_params:
            continue

        for param in str_params[:2]:  # limitar para no explotar la cantidad de llamadas
            for p in payloads[:3]:  # muestra representativa
                required = schema.get("required", [])
                args = {r: "test" for r in required}
                args[param] = p["payload"]
                result = await target.call_tool(tool["name"], args)
                content = str(result.get("content", ""))

                # el marker vive DENTRO del payload -- no se puede "stripear el eco" acá como en
                # los tests de canario (eso lo mataría siempre, tautológicamente). En cambio,
                # is_error distingue "el server rechazó el payload y lo citó en un mensaje de
                # validación" (señal más débil: el error en sí podría igual ser reconsumido por
                # un agente, pero no hay evidencia de almacenamiento) de "el server aceptó el
                # payload como éxito y lo devolvió/guardó tal cual" (señal fuerte).
                if p["marker"] in content and result.get("ok"):
                    is_error = bool(result.get("is_error"))
                    findings.append(Finding(
                        test_id="adv.injection_passthrough",
                        title=(f"Payload de injection citado en un error de '{tool['name']}'" if is_error else
                               f"Payload de injection reflejado intacto por '{tool['name']}'"),
                        category=Category.ADVERSARIAL,
                        target=tool["name"],
                        # is_error=true -> solo citado en un rechazo, baja el impacto de integridad (I:L) Y
                        # el impacto reputacional (no hay evidencia de que se almacene/reconsuma de verdad).
                        cvss_vector_override=(build_vector(base_vector_for("adv.injection_passthrough"), I="L")
                                                if is_error else None),
                        business_impact_override=({"reputational": "low"} if is_error else None),
                        description=(
                            f"El parámetro '{param}' fue RECHAZADO (is_error=true), pero el mensaje de validación "
                            f"cita el payload sin sanitizar. Señal débil: no hay evidencia de que se almacene, pero "
                            f"si ese mensaje de error también vuelve al agente, igual podría reconsumirse."
                            if is_error else
                            f"El parámetro '{param}' acepta y refleja/almacena contenido con instrucciones "
                            f"dirigidas a un LLM sin ningún tipo de sanitización o escapado -- la llamada fue "
                            f"exitosa (is_error=false), no un rechazo. Si este dato vuelve a ser leído por el "
                            f"agente (ej. vía otro tool de lectura), puede resultar en secuestro del contexto."
                        ),
                        evidence=Evidence(request={"tool": tool["name"], "arguments": args}, response=result),
                        passed=False,
                        remediation="Sanitizar o marcar explícitamente (delimitadores, encoding) cualquier contenido "
                                     "externo antes de que pueda volver a integrarse al contexto del modelo. "
                                     "Aplicar el principio de 'never mix instructions and data'.",
                        references=["https://embracethered.com/blog/posts/2023/chatgpt-plugin-vulns-chat-with-code/"],
                    ))

    if not findings:
        findings.append(Finding(
            test_id="adv.injection_passthrough", title="Sin passthrough detectado",
            category=Category.ADVERSARIAL, target="server",
            description="Los payloads de prompt injection probados no se reflejaron intactos en las respuestas.",
            passed=True,
        ))
    return findings


@register_test(
    id="adv.ssrf_exfil",
    name="SSRF / exfiltración vía parámetros tipo URL",
    category=Category.ADVERSARIAL,
    description="Identifica parámetros que parecen aceptar URLs/paths y prueba si el server hace requests a "
                 "endpoints internos o de metadata cloud (SSRF), lo que habilitaría exfiltración real.",
    requires_network=True,
    default_enabled=False,  # apunta a targets externos (metadata endpoints); requiere opt-in explícito
)
async def ssrf_exfil(target, ctx) -> list[Finding]:
    tools = ctx.get("tools") or await target.list_tools()
    findings = []

    url_like_names = {"url", "uri", "endpoint", "link", "href", "path", "src", "source", "target", "webhook"}

    oob_host = ctx.get("oob_callback_host")
    oob_listener = None
    oob_ctx = None
    if oob_host:
        from engine.adversarial.oob import OOBListener
        bind_port = int(oob_host.split(":")[1]) if ":" in oob_host else 0
        oob_ctx = OOBListener(bind_host="0.0.0.0", port=bind_port)
        oob_listener = oob_ctx.__enter__()

    try:
        for tool in tools:
            schema = tool.get("input_schema") or {}
            props = schema.get("properties", {}) or {}
            candidate_params = [p for p in props if p.lower() in url_like_names]
            if not candidate_params:
                continue

            targets_to_try = list(SSRF_TARGETS)
            oob_token_by_url: dict[str, str] = {}
            if oob_listener:
                token = oob_listener.new_token()
                callback_url = oob_listener.callback_url(oob_host, token)
                targets_to_try.append(callback_url)
                oob_token_by_url[callback_url] = token

            for param in candidate_params:
                for ssrf_url in targets_to_try:
                    required = schema.get("required", [])
                    args = {r: "test" for r in required}
                    args[param] = ssrf_url
                    result = await target.call_tool(tool["name"], args)
                    content = str(result.get("content", "")) + str(result.get("raw_error", "") or "")

                    oob_confirmed = False
                    if ssrf_url in oob_token_by_url and oob_listener:
                        await asyncio.sleep(0.3)  # darle un instante a la conexión saliente del target
                        oob_confirmed = bool(oob_listener.hits_for(oob_token_by_url[ssrf_url]))

                    # señales de que el request salió: contenido tipo metadata, o error de conexión específico
                    # (que confirma que SÍ intentó conectar, distinto de "parámetro inválido")
                    connection_attempted = any(k in content.lower() for k in
                                                ["connection refused", "timed out", "econnrefused", "instance-id",
                                                 "computemetadata", "root:x:0:0"])
                    if connection_attempted or oob_confirmed:
                        findings.append(Finding(
                            test_id="adv.ssrf_exfil",
                            title=f"{'SSRF CONFIRMADO (callback OOB real)' if oob_confirmed else 'Posible SSRF'} "
                                  f"en '{tool['name']}' vía parámetro '{param}'",
                            category=Category.ADVERSARIAL,
                            target=tool["name"],
                            # confirmado por callback OOB real -> AC:L (probado, no hay incertidumbre);
                            # solo heurístico (patrón en la respuesta) -> baseline AC:H se mantiene.
                            cvss_vector_override=(build_vector(base_vector_for("adv.ssrf_exfil"), AC="L")
                                                    if oob_confirmed else None),
                            description=(
                                f"El servidor recibió una conexión real de vuelta en el listener OOB al pasar "
                                f"'{ssrf_url}' como '{param}' -- explotación confirmada, no inferida."
                                if oob_confirmed else
                                f"El servidor intentó conectarse a '{ssrf_url}' cuando se le pasó como valor "
                                f"de '{param}'. Esto puede permitir a un atacante (vía prompt injection "
                                f"indirecta que controle este parámetro) acceder a metadata de cloud, "
                                f"servicios internos, o el filesystem del host."
                            ),
                            evidence=Evidence(request={"tool": tool["name"], "arguments": args}, response=result),
                            passed=False,
                            confidence_override="verified" if oob_confirmed else None,
                            remediation="Implementar allowlist de dominios/esquemas permitidos, bloquear rangos de IP "
                                         "privados/link-local (169.254.0.0/16, 127.0.0.0/8, etc.) y esquemas file://.",
                            references=["https://owasp.org/www-community/attacks/Server_Side_Request_Forgery"],
                        ))
    finally:
        if oob_ctx:
            oob_ctx.__exit__(None, None, None)

    if not findings:
        findings.append(Finding(
            test_id="adv.ssrf_exfil", title="Sin SSRF detectado",
            category=Category.ADVERSARIAL, target="server",
            description="No se confirmaron intentos de conexión a endpoints internos/metadata con los parámetros probados.",
            passed=True,
        ))
    return findings


@register_test(
    id="adv.confused_deputy",
    name="Confused deputy / escalación de alcance",
    category=Category.ADVERSARIAL,
    description="Prueba si tools 'de lectura' aceptan parámetros que en realidad permiten escritura/acción "
                 "(ej. un parámetro 'id' que en realidad acepta paths arbitrarios fuera del alcance esperado).",
)
async def confused_deputy(target, ctx) -> list[Finding]:
    tools = ctx.get("tools") or await target.list_tools()
    findings = []
    read_like = [t for t in tools if any(k in t["name"].lower() for k in ["get", "read", "list", "fetch", "search"])]

    escalation_payloads = ["../config.json", "../../.env", "*", "admin", "0", "-1", "true"]

    for tool in read_like:
        schema = tool.get("input_schema") or {}
        props = schema.get("properties", {}) or {}
        for pname in props:
            for payload in escalation_payloads:
                required = schema.get("required", [])
                args = {r: "test" for r in required}
                args[pname] = payload
                result = await target.call_tool(tool["name"], args)
                content = str(result.get("content", ""))

                if result.get("ok") and not result.get("is_error") and len(content) > 200:
                    # heurística: una respuesta "grande" a un payload de escalación en un tool
                    # nominalmente de solo-lectura acotado amerita revisión manual
                    findings.append(Finding(
                        test_id="adv.confused_deputy",
                        title=f"Posible escalación de alcance en '{tool['name']}' vía '{pname}'",
                        category=Category.ADVERSARIAL,
                        target=tool["name"],
                        description=f"Al pasar '{payload}' en '{pname}', el tool devolvió una respuesta extensa "
                                     f"({len(content)} chars) sin marcar error. Revisar manualmente si esto excede "
                                     f"el alcance esperado del tool (ej. lectura fuera del sandbox declarado).",
                        evidence=Evidence(request={"tool": tool["name"], "arguments": args}, response=result),
                        passed=False,
                        remediation="Validar que los parámetros de identificación/paths estén acotados a un "
                                     "namespace o sandbox explícito, no solo 'lo que exista'.",
                    ))
                    break  # un hit por parámetro alcanza, no saturar de findings

    if not findings:
        findings.append(Finding(
            test_id="adv.confused_deputy", title="Sin escalación de alcance detectada",
            category=Category.ADVERSARIAL, target="server",
            description="Los tools de lectura probados no mostraron señales de escalación de alcance evidente.",
            passed=True,
        ))
    return findings


@register_test(
    id="adv.destructive_no_confirmation",
    name="Ejecución de acciones destructivas sin confirmación",
    category=Category.ADVERSARIAL,
    description="Identifica tools de nombre/semántica destructiva (delete/drop/remove) y verifica si ejecutan "
                 "inmediatamente sin ningún mecanismo aparente de confirmación (dry_run, confirm=true, etc. no soportado).",
)
async def destructive_no_confirmation(target, ctx) -> list[Finding]:
    tools = ctx.get("tools") or await target.list_tools()
    findings = []
    destructive_kw = ["delete", "drop", "remove", "destroy", "wipe", "truncate", "purge"]

    for tool in tools:
        name_l = tool["name"].lower()
        if not any(k in name_l for k in destructive_kw):
            continue
        schema = tool.get("input_schema") or {}
        props = schema.get("properties", {}) or {}
        has_confirm_param = any(k in props for k in ["confirm", "dry_run", "force", "are_you_sure"])

        findings.append(Finding(
            test_id="adv.destructive_no_confirmation",
            title=f"Tool destructivo sin parámetro de confirmación: '{tool['name']}'",
            category=Category.ADVERSARIAL,
            target=tool["name"],
            description="No se detectó parámetro de confirmación/dry_run en el schema."
                        if not has_confirm_param else
                        "El tool declara un parámetro de confirmación en su schema (revisar que el server lo "
                        "haga cumplir realmente, no solo que exista).",
            evidence=Evidence(response=schema),
            passed=has_confirm_param,
            remediation="Requerir un parámetro explícito de confirmación (y hacerlo cumplir server-side), y/o "
                         "depender de human-in-the-loop del cliente MCP para acciones destructivas.",
        ))

    if not findings:
        findings.append(Finding(
            test_id="adv.destructive_no_confirmation", title="Sin tools destructivos detectados",
            category=Category.ADVERSARIAL, target="server",
            description="Ningún tool coincide con palabras clave destructivas.",
            passed=True,
        ))
    return findings


def _tool_fingerprint(tool: dict) -> str:
    import hashlib
    import json as _json
    blob = (tool.get("description", "") or "") + "|" + _json.dumps(tool.get("input_schema", {}), sort_keys=True)
    return hashlib.sha256(blob.encode("utf-8", errors="ignore")).hexdigest()


@register_test(
    id="adv.rug_pull",
    name="Rug pull: la definición de un tool cambió desde el baseline",
    category=Category.ADVERSARIAL,
    description="Compara la descripción + input_schema de cada tool contra un --baseline anterior (por "
                 "hash). Un server puede ser revisado y aprobado en su versión inicial, y luego cambiar la "
                 "definición de un tool para volverlo malicioso sin que nadie lo note -- la aprobación "
                 "original queda inválida en el momento exacto en que el server cambia. Requiere --baseline "
                 "(un reporte.json de una corrida anterior contra el mismo server).",
)
async def rug_pull(target, ctx) -> list[Finding]:
    baseline_tools = ctx.get("baseline_tools") or []
    if not baseline_tools:
        return [Finding(
            test_id="adv.rug_pull", title="Sin --baseline: nada que comparar",
            category=Category.ADVERSARIAL, target="server",
            description="Este test necesita un reporte.json de una corrida anterior contra este mismo "
                         "server (--baseline) para detectar cambios de definición entre corridas.",
            passed=True,
        )]

    current_tools = ctx.get("tools") or await target.list_tools()
    baseline_by_name = {t["name"]: t for t in baseline_tools if t.get("name")}
    findings = []

    for tool in current_tools:
        baseline_tool = baseline_by_name.get(tool["name"])
        if not baseline_tool:
            continue  # tool nuevo, no es un rug pull -- lo cubre baseline_diff a nivel de findings
        if _tool_fingerprint(tool) == _tool_fingerprint(baseline_tool):
            continue

        findings.append(Finding(
            test_id="adv.rug_pull",
            title=f"La definición de '{tool['name']}' cambió desde el baseline",
            category=Category.ADVERSARIAL,
            target=tool["name"],
            confidence_override="verified",  # comparación factual de hash, no heurística
            description=f"Descripción y/o input_schema de '{tool['name']}' no coinciden con la versión "
                         f"del baseline. Si este server ya estaba aprobado para tu operación, esa "
                         f"aprobación quedó inválida en el momento en que cambió -- revisar manualmente "
                         f"qué cambió antes de seguir confiando en este tool.",
            evidence=Evidence(
                request={"baseline_description": baseline_tool.get("description"), "baseline_schema": baseline_tool.get("input_schema")},
                response={"current_description": tool.get("description"), "current_schema": tool.get("input_schema")},
            ),
            passed=False,
            remediation="Pinnear definiciones de tools por hash criptográfico y alertar/bloquear ante "
                         "cualquier cambio no revisado explícitamente -- no volver a confiar en 'el mismo "
                         "server de siempre' solo porque el nombre del tool no cambió.",
        ))

    if not findings:
        findings.append(Finding(
            test_id="adv.rug_pull", title="Sin cambios de definición desde el baseline",
            category=Category.ADVERSARIAL, target="server",
            description=f"Los {len(current_tools)} tool(s) actuales coinciden por hash con el baseline.",
            passed=True,
        ))
    return findings
