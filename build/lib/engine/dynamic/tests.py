"""
Tests dinámicos (caja negra): ejecutan llamadas reales contra el servidor
con inputs adversariales y analizan el comportamiento observado.
"""
from __future__ import annotations
import asyncio
import re
import time

from engine.core.models import Finding, Evidence, Category
from engine.core.registry import register_test
from engine.dynamic.payload_gen import build_fuzz_cases
from payloads.canary import (
    new_canary, strip_reflections, command_injection_payloads,
    path_traversal_payloads, PASSWD_CONTENT_SIGNATURES,
    credential_harvest_traversal_payloads, CREDENTIAL_CONTENT_SIGNATURES,
)

# patrones que sugieren leak de información interna en el error/respuesta
LEAK_PATTERNS = [
    (r"Traceback \(most recent call last\)", "stack trace de Python filtrado"),
    (r"/(home|usr|var|etc)/[a-zA-Z0-9_./-]+", "path absoluto del filesystem filtrado"),
    (r"(AWS_SECRET|API_KEY|PRIVATE_KEY|BEGIN RSA)", "posible secreto/credencial filtrada"),
    (r"at [\w.$]+\(.*\.(js|ts):\d+", "stack trace de Node.js filtrado"),
    (r"line \d+, in ", "detalle interno de ejecución filtrado"),
]


@register_test(
    id="dynamic.fuzz_tools",
    name="Fuzzing black-box de parámetros por tool",
    category=Category.DYNAMIC,
    description="Envía inputs edge-case/malformados a cada tool y detecta crashes, leaks de info o falta de validación.",
)
async def fuzz_tools(target, ctx) -> list[Finding]:
    tools = ctx.get("tools") or await target.list_tools()
    max_cases = ctx.get("max_fuzz_cases_per_tool", 25)
    findings = []

    for tool in tools:
        name = tool["name"]
        schema = tool.get("input_schema") or {}
        cases = build_fuzz_cases(schema, max_cases=max_cases)

        crash_count = 0
        leak_findings = 0
        accepted_invalid = 0

        for args in cases:
            result = await target.call_tool(name, args)
            raw_content = str(result.get("content", "")) + str(result.get("raw_error", "") or "")
            # sin esto, un server que RECHAZA el payload y lo cita en su propio mensaje de
            # validación ("Invalid repoName: '<payload>'") se marca como "leak" solo por
            # haber hecho bien su trabajo -- mismo problema que ya se resolvió para los
            # tests de canario, aplicado acá de forma genérica a cualquier valor enviado.
            sent_values = [str(v) for v in args.values() if isinstance(v, str) and v]
            content = strip_reflections(raw_content, *sent_values)

            # 1. leak de información interna -- regex sobre texto libre, MISMA clase de señal
            # que supplychain.secret_exposure/malicious_patterns (ambos HEURISTIC): puede haber
            # falso positivo (ej. un path legítimo mencionado en un mensaje de error normal que
            # matchea el patrón de "path absoluto filtrado" sin ser un leak real). El default de
            # confidence.py para este test_id es VERIFIED (correcto para el finding de "fallos no
            # controlados" de más abajo, que es un conteo empírico real) -- por eso esta instancia
            # puntual se pisa a heuristic explícitamente, para no sobre-prometer certeza bajo
            # --min-confidence verified.
            for pattern, label in LEAK_PATTERNS:
                if re.search(pattern, content):
                    leak_findings += 1
                    findings.append(Finding(
                        test_id="dynamic.fuzz_tools",
                        title=f"Leak de información interna en '{name}'",
                        category=Category.DYNAMIC,
                        target=name,
                        description=f"{label}. Detectado al enviar payload adversarial.",
                        evidence=Evidence(request={"tool": name, "arguments": args}, response=result),
                        passed=False,
                        confidence_override="heuristic",
                        remediation="Capturar excepciones y devolver mensajes de error genéricos al cliente; "
                                     "loguear el detalle solo server-side.",
                    ))
                    break  # un leak por caso alcanza

            # 2. server no manejó el error explícitamente pero tampoco crasheó -> ok
            if not result.get("ok") and not result.get("is_error"):
                crash_count += 1

            # 3. tipos claramente inválidos que fueron aceptados sin error (posible falta de validación)
            if result.get("ok") and not result.get("is_error"):
                if any(v is None or isinstance(v, (list, dict)) and not isinstance(v, str) for v in [] ):
                    pass  # placeholder, la heurística fuerte ya está en leak/crash

        if crash_count > 0:
            findings.append(Finding(
                test_id="dynamic.fuzz_tools",
                title=f"Fallos no controlados en '{name}'",
                category=Category.DYNAMIC,
                target=name,
                description=f"{crash_count}/{len(cases)} casos de fuzzing produjeron una excepción de transporte "
                             f"no manejada explícitamente por el tool (posible falta de validación/try-catch).",
                evidence=Evidence(notes=f"{crash_count} fallos de {len(cases)} casos enviados"),
                passed=False,
                remediation="Validar inputs explícitamente contra el schema antes de procesarlos; "
                             "capturar excepciones y devolver isError=true con mensaje controlado.",
            ))

    if not findings:
        findings.append(Finding(
            test_id="dynamic.fuzz_tools", title="Fuzzing sin hallazgos",
            category=Category.DYNAMIC, target="server",
            description="Ningún tool mostró leaks de información ni fallos no controlados con los casos probados.",
            passed=True,
        ))
    return findings


@register_test(
    id="dynamic.rate_limit",
    name="Prueba de rate limiting / DoS básico",
    category=Category.DYNAMIC,
    description="Envía ráfagas de llamadas concurrentes al primer tool disponible para verificar si hay throttling.",
    default_enabled=False,  # puede ser intrusivo, off por default
)
async def rate_limit_test(target, ctx) -> list[Finding]:
    tools = ctx.get("tools") or await target.list_tools()
    if not tools:
        return []
    tool = tools[0]
    schema = tool.get("input_schema") or {}
    args = {p: "test" for p in (schema.get("required") or [])}

    N = 50
    t0 = time.monotonic()
    results = await asyncio.gather(*[target.call_tool(tool["name"], args) for _ in range(N)], return_exceptions=True)
    elapsed = time.monotonic() - t0

    errors = sum(1 for r in results if isinstance(r, Exception) or (isinstance(r, dict) and not r.get("ok")))
    throttled = any(
        isinstance(r, dict) and "rate" in str(r.get("raw_error", "")).lower()
        for r in results
    )

    finding = Finding(
        test_id="dynamic.rate_limit",
        title=f"Rate limiting {'detectado' if throttled else 'NO detectado'} en '{tool['name']}'",
        category=Category.DYNAMIC,
        target=tool["name"],
        description=f"{N} llamadas concurrentes en {elapsed:.2f}s, {errors} fallaron. "
                     f"{'El servidor aplicó throttling.' if throttled else 'No se observó throttling explícito — posible vector de DoS.'}",
        evidence=Evidence(notes=f"{N} requests, {errors} errores, {elapsed:.2f}s totales"),
        passed=throttled,
        remediation="Implementar rate limiting por sesión/cliente en el servidor MCP.",
    )
    return [finding]


def _string_params(schema: dict) -> list[str]:
    props = schema.get("properties", {}) or {}
    return [p for p, s in props.items() if isinstance(s, dict) and s.get("type", "string") == "string"]


@register_test(
    id="dynamic.command_injection_confirmed",
    name="Command injection confirmado por canario",
    category=Category.DYNAMIC,
    description="Inyecta payloads de command injection con un canario único aleatorio y busca que el "
                 "canario sobreviva DESPUÉS de eliminar cualquier eco literal del payload (stripReflections). "
                 "A diferencia de dynamic.fuzz_tools, esto confirma ejecución real, no solo falta de sanitización.",
)
async def command_injection_confirmed(target, ctx) -> list[Finding]:
    tools = ctx.get("tools") or await target.list_tools()
    findings = []

    for tool in tools:
        schema = tool.get("input_schema") or {}
        str_params = _string_params(schema)
        if not str_params:
            continue
        required = schema.get("required", [])

        for param in str_params[:2]:
            canary = new_canary()
            for payload in command_injection_payloads(canary):
                args = {r: "test" for r in required}
                args[param] = payload
                result = await target.call_tool(tool["name"], args)
                content = str(result.get("content", "")) + str(result.get("raw_error", "") or "")
                cleaned = strip_reflections(content, payload)

                if canary in cleaned:
                    findings.append(Finding(
                        test_id="dynamic.command_injection_confirmed",
                        title=f"Command injection CONFIRMADO en '{tool['name']}' vía '{param}'",
                        category=Category.DYNAMIC,
                        target=tool["name"],
                        description=f"El canario '{canary}' apareció en la respuesta tras eliminar cualquier "
                                     f"eco literal del payload — el comando inyectado se ejecutó realmente "
                                     f"en el host, no fue solo reflejado como texto.",
                        evidence=Evidence(request={"tool": tool["name"], "arguments": args}, response=result),
                        passed=False,
                        remediation="Nunca pasar input de usuario a un shell (subprocess con shell=True, "
                                     "execSync, os.system). Usar APIs que reciban argumentos como lista, "
                                     "sin interpretación de shell.",
                        references=["https://owasp.org/www-community/attacks/Command_Injection"],
                    ))
                    break  # un hit confirmado por parámetro alcanza

    if not findings:
        findings.append(Finding(
            test_id="dynamic.command_injection_confirmed", title="Sin command injection confirmado",
            category=Category.DYNAMIC, target="server",
            description="Ningún canario sobrevivió al strip de reflexiones tras los payloads probados.",
            passed=True,
        ))
    return findings


@register_test(
    id="dynamic.path_traversal_confirmed",
    name="Path traversal confirmado por contenido de /etc/passwd",
    category=Category.DYNAMIC,
    description="Envía payloads de path traversal y confirma explotación real buscando firmas de contenido "
                 "de /etc/passwd en la respuesta (no solo que el request 'pasó' sin error).",
)
async def path_traversal_confirmed(target, ctx) -> list[Finding]:
    tools = ctx.get("tools") or await target.list_tools()
    findings = []

    for tool in tools:
        schema = tool.get("input_schema") or {}
        str_params = _string_params(schema)
        if not str_params:
            continue
        required = schema.get("required", [])
        path_like = [p for p in str_params if any(k in p.lower() for k in ["path", "file", "name", "uri"])] or str_params[:1]

        for param in path_like[:2]:
            for payload in path_traversal_payloads():
                args = {r: "test" for r in required}
                args[param] = payload
                result = await target.call_tool(tool["name"], args)
                content = str(result.get("content", ""))

                if any(sig in content for sig in PASSWD_CONTENT_SIGNATURES):
                    findings.append(Finding(
                        test_id="dynamic.path_traversal_confirmed",
                        title=f"Path traversal CONFIRMADO en '{tool['name']}' vía '{param}'",
                        category=Category.DYNAMIC,
                        target=tool["name"],
                        description=f"La respuesta contiene contenido real de /etc/passwd tras enviar "
                                     f"'{payload}' como '{param}'.",
                        evidence=Evidence(request={"tool": tool["name"], "arguments": args}, response=result),
                        passed=False,
                        remediation="Resolver y validar la ruta contra un directorio base permitido "
                                     "(allowlist), rechazando cualquier ruta que escape de ese directorio.",
                        references=["https://owasp.org/www-community/attacks/Path_Traversal"],
                    ))
                    break

    if not findings:
        findings.append(Finding(
            test_id="dynamic.path_traversal_confirmed", title="Sin path traversal confirmado",
            category=Category.DYNAMIC, target="server",
            description="Ninguna respuesta contuvo firmas de contenido real de /etc/passwd.",
            passed=True,
        ))
    return findings


@register_test(
    id="dynamic.credential_harvest_paths",
    name="Path traversal dirigido a credenciales conocidas (SSH, cloud, configs MCP)",
    category=Category.DYNAMIC,
    description="A diferencia de dynamic.path_traversal_confirmed (que prueba SI hay traversal, apuntando "
                 "a /etc/passwd como prueba de concepto), esto apunta directo a los archivos que un "
                 "atacante real quiere -- claves SSH, credenciales AWS/GCP/Azure, .netrc, y configs de "
                 "clientes MCP (que a su vez pueden contener tokens de OTROS servers conectados). Confirma "
                 "por firma de contenido real, nunca por inferencia.",
)
async def credential_harvest_paths(target, ctx) -> list[Finding]:
    tools = ctx.get("tools") or await target.list_tools()
    findings = []

    for tool in tools:
        schema = tool.get("input_schema") or {}
        str_params = _string_params(schema)
        if not str_params:
            continue
        required = schema.get("required", [])
        path_like = [p for p in str_params if any(k in p.lower() for k in ["path", "file", "name", "uri"])] or str_params[:1]

        for param in path_like[:2]:
            hit_for_tool = False
            for payload in credential_harvest_traversal_payloads():
                args = {r: "test" for r in required}
                args[param] = payload
                result = await target.call_tool(tool["name"], args)
                content = str(result.get("content", ""))

                for sig, label in CREDENTIAL_CONTENT_SIGNATURES:
                    if sig in content:
                        findings.append(Finding(
                            test_id="dynamic.credential_harvest_paths",
                            title=f"Credencial real expuesta en '{tool['name']}' vía '{param}': {label}",
                            category=Category.DYNAMIC,
                            target=tool["name"],
                            description=f"La respuesta contiene {label} real tras enviar '{payload}' como "
                                         f"'{param}' -- no una inferencia, la firma de contenido matcheó.",
                            evidence=Evidence(request={"tool": tool["name"], "arguments": args}, notes=f"firma: {label}"),
                            passed=False,
                            remediation="Resolver y validar la ruta contra un directorio base permitido "
                                         "(allowlist); nunca permitir que un parámetro de tool alcance "
                                         "directorios de configuración/credenciales del usuario o del sistema.",
                            references=["https://owasp.org/www-community/attacks/Path_Traversal"],
                        ))
                        hit_for_tool = True
                        break
                if hit_for_tool:
                    break

    if not findings:
        findings.append(Finding(
            test_id="dynamic.credential_harvest_paths", title="Sin credenciales reales expuestas por path traversal",
            category=Category.DYNAMIC, target="server",
            description="Ninguna respuesta contuvo firmas de contenido real de claves SSH, credenciales "
                         "cloud, o configs de clientes MCP.",
            passed=True,
        ))
    return findings


def _resource_uri_mutations(uri: str) -> list[str]:
    base = uri.rsplit("/", 1)[0] if "/" in uri else uri
    return [
        uri + "/../../../../etc/passwd",
        base + "/../../../../etc/passwd",
        uri + "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
        uri + "\x00.txt",
        "file:///etc/passwd",
    ]


@register_test(
    id="dynamic.fuzz_resources",
    name="Fuzzing de URIs de resources (estáticos y templates)",
    category=Category.DYNAMIC,
    description="Prueba variantes mutadas (path traversal, encoding, null byte) de las URIs de resources "
                 "declaradas -- estáticos y resource templates (ej. 'file:///{path}', instanciados con un "
                 "valor benigno antes de mutar) -- y confirma acceso fuera de alcance buscando firmas reales "
                 "de /etc/passwd u otros leaks en la respuesta. Los templates son el vector real: la mayoría "
                 "de los servers vulnerables a esto exponen un template tipo 'file:///{path}', no un resource "
                 "estático suelto.",
)
async def fuzz_resources(target, ctx) -> list[Finding]:
    resources = ctx.get("resources") or await target.list_resources()
    templates = await target.list_resource_templates()
    findings = []

    targets: list[tuple[str, str]] = [(r.get("uri", ""), r.get("uri", "")) for r in resources if r.get("uri")]
    for t in templates:
        instantiated = re.sub(r"\{[^}]+\}", "test", t.get("uri_template", ""))
        if instantiated:
            targets.append((t["uri_template"], instantiated))

    if not targets:
        return [Finding(
            test_id="dynamic.fuzz_resources", title="Sin resources ni resource templates declarados",
            category=Category.DYNAMIC, target="server",
            description="El server no expone ningún resource ni resource template; nada que fuzzear acá.",
            passed=True,
        )]

    for source_label, uri in targets:
        for variant in _resource_uri_mutations(uri):
            result = await target.read_resource(variant)
            content = str(result.get("content", "")) + str(result.get("raw_error", "") or "")

            # firma exacta de contenido real (/etc/passwd) -> verified (mismo criterio que
            # dynamic.path_traversal_confirmed). El fallback a LEAK_PATTERNS es regex genérica
            # sobre texto libre -- misma clase de señal débil que en dynamic.fuzz_tools, amerita
            # el mismo downgrade a heuristic para esta instancia puntual.
            hit = None
            hit_verified = False
            if any(sig in content for sig in PASSWD_CONTENT_SIGNATURES):
                hit = "contenido real de /etc/passwd"
                hit_verified = True
            else:
                for pattern, leak_label in LEAK_PATTERNS:
                    if re.search(pattern, content):
                        hit = leak_label
                        break

            if hit:
                findings.append(Finding(
                    test_id="dynamic.fuzz_resources",
                    title=f"Acceso fuera de alcance o leak en resource '{source_label}'",
                    category=Category.DYNAMIC,
                    target=source_label,
                    description=f"{hit} al leer la variante mutada '{variant}' (instanciada desde '{source_label}').",
                    evidence=Evidence(request={"uri": variant}, response=result),
                    passed=False,
                    confidence_override=None if hit_verified else "heuristic",
                    remediation="Validar y normalizar URIs de resources contra un allowlist explícito antes "
                                 "de resolverlas a un path/recurso real; nunca concatenar el URI recibido "
                                 "directamente a una ruta de filesystem.",
                    references=["https://owasp.org/www-community/attacks/Path_Traversal"],
                ))
                break  # un hit por resource alcanza

    if not findings:
        findings.append(Finding(
            test_id="dynamic.fuzz_resources", title="Fuzzing de resources sin hallazgos",
            category=Category.DYNAMIC, target="server",
            description=f"Ninguna variante mutada de las {len(resources)} URI(s) probadas mostró leaks ni "
                         f"acceso fuera de alcance.",
            passed=True,
        ))
    return findings
