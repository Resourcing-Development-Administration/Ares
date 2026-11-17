"""
Tests de autenticación: ¿el servidor requiere credenciales para operar, y si
las requiere, son triviales de adivinar? Solo aplica a transporte http/sse
(stdio es un proceso local, no hay "autenticación de red" que probar).

Idea portada de cli/internal/scanner/probes.go::testAuth() (mcpscanner Go CLI):
conexión sin credenciales como baseline + wordlist chica de tokens comunes.
"""
from __future__ import annotations
import re
import uuid
from urllib.parse import urljoin, urlparse

import httpx

from engine.core.models import Finding, Evidence, Category
from engine.core.registry import register_test
from engine.core.client import MCPTarget
from payloads.canary import new_canary

WEAK_TOKENS = ["test", "default", "mcp", "admin", "password", "changeme", "demo", "secret", ""]


@register_test(
    id="auth.unauthenticated_access",
    name="Acceso sin autenticación",
    category=Category.AUTH,
    description="Verifica si el servidor MCP permite listar tools/resources sin ninguna credencial. "
                 "Solo aplica a transporte http/sse; en stdio el proceso ya corre localmente bajo el "
                 "usuario que lo lanzó y este concepto no aplica.",
)
async def unauthenticated_access(target, ctx) -> list[Finding]:
    transport = ctx.get("transport")
    connection = ctx.get("connection") or {}
    if transport not in ("http", "sse"):
        return [Finding(
            test_id="auth.unauthenticated_access", title="No aplica (transporte stdio)",
            category=Category.AUTH, target="server",
            description="El servidor corre vía stdio; no hay una capa de red/auth que evaluar aquí.",
            passed=True,
        )]

    auth_configured = bool(connection.get("auth") and getattr(connection["auth"], "type", "none") != "none")

    connection_error = ctx.get("connection_error")
    if not auth_configured and connection_error:
        from engine.core.conn_errors import classify_connection_error
        kind = classify_connection_error(connection_error)
        if kind == "auth":
            # la conexión SIN credenciales fue rechazada A NIVEL HTTP (401/403) -- esto es
            # exactamente lo que se espera de un server bien asegurado. Antes, esto tumbaba el
            # scan entero antes de llegar acá; ahora el orchestrator deja correr los tests igual
            # y esta es la señal positiva real.
            return [Finding(
                test_id="auth.unauthenticated_access",
                title="Conexión sin credenciales RECHAZADA",
                category=Category.AUTH, target="server",
                description=f"Intentar conectar sin Authorization/API-Key fue rechazado por el server "
                             f"({connection_error[:200]}). Buena señal: la autenticación parece "
                             f"exigirse antes de aceptar la sesión.",
                passed=True,
            )]
        # OJO: la conexión falló, pero NO por un 401 -- fue un fallo de TLS/red. Eso NO prueba
        # que el server exija auth; prueba que ni siquiera llegamos a hablar MCP con él. No lo
        # reportamos como señal positiva (sería un falso "auth exigida"). El orquestador ya
        # emite orchestrator.connection_failed marcando la corrida como incompleta.
        return [Finding(
            test_id="auth.unauthenticated_access",
            title="No se pudo evaluar acceso sin credenciales (la conexión falló antes)",
            category=Category.AUTH, target="server",
            description=f"La conexión no llegó a establecerse por un motivo de tipo '{kind}' "
                         f"({connection_error[:200]}), no por un rechazo de autenticación. No se puede "
                         f"concluir si el server exige credenciales -- ver orchestrator.connection_failed.",
            passed=True,
        )]

    if target is None:
        return [Finding(
            test_id="auth.unauthenticated_access", title="No se pudo evaluar (sin sesión ni error claro)",
            category=Category.AUTH, target="server",
            description="No hay sesión activa y no se registró un error de conexión específico.",
            passed=True,
        )]

    tools = ctx.get("tools") or await target.list_tools()

    if auth_configured:
        # esta corrida SÍ usó credenciales; no podemos concluir nada sobre acceso sin auth
        # desde esta única conexión (para eso está --compare-auth, que corre ambas variantes).
        return [Finding(
            test_id="auth.unauthenticated_access", title="Corrida autenticada",
            category=Category.AUTH, target="server",
            description="Este scan se ejecutó con credenciales explícitas. Usa --compare-auth para "
                         "confirmar si el servidor también responde SIN credenciales.",
            passed=True,
        )]

    # No se configuró auth y la conexión igual funcionó y enumeró superficie de ataque
    if tools:
        return [Finding(
            test_id="auth.unauthenticated_access",
            title="El servidor responde sin ninguna credencial",
            category=Category.AUTH,
            target="server",
            description=f"Se conectó sin Authorization/API-Key y el servidor listó {len(tools)} tool(s) "
                         f"sin exigir credenciales. Cualquiera con acceso de red al endpoint puede "
                         f"enumerar y ejecutar la superficie completa del servidor.",
            evidence=Evidence(response={"tools_count": len(tools)}),
            passed=False,
            remediation="Exigir autenticación (bearer token, API key, o mTLS) antes de aceptar "
                         "initialize/tools-list, incluso para servidores 'internos'.",
            references=["https://modelcontextprotocol.io/docs/concepts/transports"],
        )]

    return [Finding(
        test_id="auth.unauthenticated_access", title="Sin acceso sin autenticación detectado",
        category=Category.AUTH, target="server",
        description="La conexión sin credenciales no devolvió tools (probablemente rechazada antes, "
                     "o el servidor no expone tools).",
        passed=True,
    )]


@register_test(
    id="auth.weak_credentials",
    name="Credenciales por defecto / débiles",
    category=Category.AUTH,
    description="Prueba una wordlist chica de tokens comunes (test, admin, password, etc.) como Bearer "
                 "token contra el endpoint http/sse. Intrusivo (abre conexiones nuevas) — opt-in.",
    default_enabled=False,
)
async def weak_credentials(target, ctx) -> list[Finding]:
    transport = ctx.get("transport")
    connection = ctx.get("connection") or {}
    if transport not in ("http", "sse"):
        return []

    base_connection = {k: v for k, v in connection.items() if k not in ("auth", "headers")}

    # si el server ya acepta conexiones SIN ningún header de auth, "acepta estos tokens
    # también" no aporta información nueva -- es un corolario trivial de "no hay auth",
    # no evidencia de que exista una credencial débil que alguien pueda "romper".
    try:
        async with MCPTarget(transport, base_connection) as baseline_target:
            baseline_tools = await baseline_target.list_tools()
    except Exception:
        baseline_tools = []

    if baseline_tools:
        return [Finding(
            test_id="auth.weak_credentials",
            title="No aplica: el server no exige autenticación en absoluto",
            category=Category.AUTH, target="server",
            description="La conexión SIN ningún header de auth ya devuelve tools (ver "
                         "auth.unauthenticated_access) -- probar una wordlist de tokens no aporta "
                         "información nueva porque no hay ninguna verificación de credenciales que "
                         "'romper': cualquier valor, incluso ausente, es aceptado igual.",
            passed=True,
        )]

    findings = []
    accepted = []

    for token in WEAK_TOKENS:
        if not token:
            continue
        probe_connection = dict(base_connection)
        probe_connection["headers"] = {"Authorization": f"Bearer {token}"}
        try:
            async with MCPTarget(transport, probe_connection) as probe_target:
                tools = await probe_target.list_tools()
                if tools:
                    accepted.append(token)
        except Exception:
            continue  # rechazado, esperado

    if accepted:
        findings.append(Finding(
            test_id="auth.weak_credentials",
            title="El servidor acepta credenciales débiles/por defecto",
            category=Category.AUTH,
            target="server",
            description=f"Token(s) aceptado(s) como Bearer válido: {accepted}.",
            evidence=Evidence(notes=f"probados: {WEAK_TOKENS}"),
            passed=False,
            remediation="Nunca usar tokens estáticos/adivinables. Rotar credenciales y usar secretos "
                         "generados criptográficamente con expiración.",
        ))
    else:
        findings.append(Finding(
            test_id="auth.weak_credentials", title="Sin credenciales débiles aceptadas",
            category=Category.AUTH, target="server",
            description=f"Ninguno de los {len([t for t in WEAK_TOKENS if t])} tokens de la wordlist fue aceptado.",
            passed=True,
        ))
    return findings


ID_PARAM_PATTERNS = ("id", "_id", "userid", "user_id", "accountid", "account_id", "ownerid",
                     "owner_id", "customerid", "customer_id", "recordid", "record_id",
                     "documentid", "document_id", "fileid", "file_id", "orderid", "order_id")


def _id_like_params(schema: dict) -> list[str]:
    props = schema.get("properties", {}) or {}
    out = []
    for pname, pschema in props.items():
        if not isinstance(pschema, dict) or pschema.get("type", "string") not in ("string", "integer", "number"):
            continue
        low = pname.lower()
        if low == "id" or any(low.endswith(suffix) or low == suffix for suffix in ID_PARAM_PATTERNS):
            out.append(pname)
    return out


@register_test(
    id="auth.authz_object_level",
    name="Autorización a nivel de objeto (BOLA) con la sesión actual",
    category=Category.AUTH,
    description="Con LA SESIÓN ACTUAL (autenticada o no, la que se haya configurado para el scan), busca "
                 "parámetros tipo id (user_id, file_id, order_id, etc.) en los tools y prueba valores "
                 "adyacentes/aleatorios distintos al que devolvió una respuesta inicial. Si el server "
                 "devuelve datos DIFERENTES y con contenido real para un id que nadie 'te dio', es señal de "
                 "que no valida que el llamador tenga permiso sobre ESE objeto puntual -- Broken Object "
                 "Level Authorization (OWASP API1:2023 / MCP02:2025). Intrusivo (llama tools reales con "
                 "IDs variados) y heurístico (una respuesta distinta no prueba por sí sola una fuga real, "
                 "amerita revisión manual) -- opt-in.",
    default_enabled=False,
)
async def authz_object_level(target, ctx) -> list[Finding]:
    tools = ctx.get("tools") or await target.list_tools()
    findings = []

    for tool in tools:
        schema = tool.get("input_schema") or {}
        id_params = _id_like_params(schema)
        if not id_params:
            continue
        required = schema.get("required", [])

        for param in id_params:
            baseline_args = {r: "1" for r in required}
            baseline_args[param] = "1"
            base_result = await target.call_tool(tool["name"], baseline_args)
            base_content = str(base_result.get("content", "")).strip()

            if not base_result.get("ok") or base_result.get("is_error") or len(base_content) < 20:
                continue  # el tool ni siquiera responde con datos reales a este patrón -- no aporta señal

            probes = ["2", "3", "0", "-1", "999999", str(uuid.uuid4())]
            distinct_hits = []
            for probe_val in probes:
                args = dict(baseline_args)
                args[param] = probe_val
                result = await target.call_tool(tool["name"], args)
                content = str(result.get("content", "")).strip()
                if (result.get("ok") and not result.get("is_error")
                        and content and content != base_content and len(content) > 20):
                    distinct_hits.append(probe_val)

            if distinct_hits:
                findings.append(Finding(
                    test_id="auth.authz_object_level",
                    title=f"Posible BOLA en '{tool['name']}' vía '{param}'",
                    category=Category.AUTH,
                    target=tool["name"],
                    description=f"Al variar '{param}' a valores no solicitados explícitamente ({distinct_hits}), "
                                 f"el server devolvió contenido real y DISTINTO cada vez, sin ningún error de "
                                 f"autorización. Esto sugiere que no valida si el llamador tiene permiso sobre "
                                 f"el objeto identificado por ese id específico -- reviaar manualmente si esos "
                                 f"ids pertenecen a otros usuarios/cuentas.",
                    evidence=Evidence(request={"tool": tool["name"], "param": param, "baseline": baseline_args},
                                       response={"ids_con_datos_distintos": distinct_hits}),
                    passed=False,
                    remediation="Validar en cada llamada que el id solicitado pertenece al alcance del "
                                 "llamador autenticado (no solo que el id 'existe'). Nunca confiar en que un "
                                 "id sea difícil de adivinar como único control de acceso.",
                    references=["https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/"],
                ))

    if not findings:
        findings.append(Finding(
            test_id="auth.authz_object_level", title="Sin BOLA detectado",
            category=Category.AUTH, target="server",
            description="Ningún parámetro tipo id probado devolvió datos distintos y válidos para valores "
                         "no solicitados explícitamente.",
            passed=True,
        ))
    return findings


_TEMPLATE_PARAM_RE = re.compile(r"\{([^}/]+)\}")


def _id_like_template_params(uri_template: str) -> list[str]:
    """Mismo criterio que _id_like_params() pero sobre los placeholders '{xxx}' de un
    resource template (ej. 'file:///{user_id}/notes'), no sobre propiedades de JSON Schema."""
    out = []
    for name in _TEMPLATE_PARAM_RE.findall(uri_template):
        low = name.lower()
        if low == "id" or any(low.endswith(suffix) or low == suffix for suffix in ID_PARAM_PATTERNS):
            out.append(name)
    return out


def _instantiate_template(uri_template: str, values: dict[str, str]) -> str:
    return _TEMPLATE_PARAM_RE.sub(lambda m: values.get(m.group(1), "test"), uri_template)


@register_test(
    id="auth.resource_object_level",
    name="Autorización a nivel de objeto (BOLA) en resource templates",
    category=Category.AUTH,
    description="Mismo patrón que auth.authz_object_level (BOLA) pero sobre RESOURCE TEMPLATES en vez "
                 "de tools: instancia el template variando un placeholder tipo id/user_id/account_id y "
                 "busca que el contenido devuelto sea real y DISTINTO cada vez, sin ningún error de "
                 "autorización -- auth.authz_object_level solo mira tools, este es el equivalente para "
                 "'resources/read'. Cubre parcialmente MCP10:2025 (Context Injection & Over-Sharing): si "
                 "el contenido de un resource es alcanzable variando un id sin aislar por sesión/alcance "
                 "del llamador, es la misma clase de fuga de contexto entre límites que deberían existir. "
                 "Mismo criterio que auth.authz_object_level: intrusivo y heurístico -- opt-in.",
    default_enabled=False,
)
async def resource_object_level(target, ctx) -> list[Finding]:
    templates = ctx.get("resource_templates")
    if templates is None:
        templates = await target.list_resource_templates()
        ctx["resource_templates"] = templates
    findings = []

    for tmpl in templates:
        uri_template = tmpl.get("uri_template", "")
        id_params = _id_like_template_params(uri_template)
        if not id_params:
            continue

        for param in id_params:
            base_uri = _instantiate_template(uri_template, {param: "1"})
            base_result = await target.read_resource(base_uri)
            base_content = str(base_result.get("content", "")).strip()

            if not base_result.get("ok") or len(base_content) < 20:
                continue  # el template ni siquiera responde con datos reales a este patrón -- sin señal

            probes = ["2", "3", "0", "-1", "999999", str(uuid.uuid4())]
            distinct_hits = []
            for probe_val in probes:
                uri = _instantiate_template(uri_template, {param: probe_val})
                result = await target.read_resource(uri)
                content = str(result.get("content", "")).strip()
                if result.get("ok") and content and content != base_content and len(content) > 20:
                    distinct_hits.append(probe_val)

            if distinct_hits:
                findings.append(Finding(
                    test_id="auth.resource_object_level",
                    title=f"Posible BOLA en resource '{uri_template}' vía '{param}'",
                    category=Category.AUTH,
                    target=uri_template,
                    description=f"Al variar '{param}' a valores no solicitados explícitamente ({distinct_hits}), "
                                 f"el resource devolvió contenido real y DISTINTO cada vez, sin ningún error de "
                                 f"autorización. Sugiere que 'resources/read' no valida si el llamador tiene "
                                 f"permiso sobre el objeto identificado por ese id -- revisar manualmente si "
                                 f"esos ids pertenecen a otros usuarios/cuentas/tenants.",
                    evidence=Evidence(request={"uri_template": uri_template, "param": param},
                                       response={"ids_con_datos_distintos": distinct_hits}),
                    passed=False,
                    remediation="Validar en 'resources/read' que el id solicitado pertenece al alcance del "
                                 "llamador autenticado, igual que en una tool -- un resource template no es "
                                 "menos sensible que una tool solo porque se lee distinto.",
                    references=["https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/"],
                ))

    if not findings:
        findings.append(Finding(
            test_id="auth.resource_object_level", title="Sin BOLA detectado en resource templates",
            category=Category.AUTH, target="server",
            description="Ningún placeholder tipo id en los resource templates probados devolvió datos "
                         "distintos y válidos para valores no solicitados explícitamente.",
            passed=True,
        ))
    return findings


@register_test(
    id="auth.oauth_metadata_security",
    name="Seguridad de metadata OAuth 2.1 (RFC 9728 / MCP authorization spec)",
    category=Category.AUTH,
    description="El spec de MCP (2025-03-26+) exige que un server HTTP protegido devuelva 401 con un header "
                 "WWW-Authenticate que incluya 'resource_metadata' (RFC 9728), apuntando al authorization "
                 "server correspondiente. Este test verifica esa cadena de descubrimiento y, si llega a un "
                 "authorization server, chequea que anuncie soporte de PKCE (code_challenge_methods_supported "
                 "incluyendo S256) -- sin PKCE, el authorization code es robable por un cliente malicioso en "
                 "el mismo dispositivo.",
)
async def oauth_metadata_security(target, ctx) -> list[Finding]:
    transport = ctx.get("transport")
    connection = ctx.get("connection") or {}
    url = connection.get("url")
    if transport not in ("http", "sse") or not url:
        return []

    try:
        from engine.core.tls import verify_source
        async with httpx.AsyncClient(timeout=6.0, follow_redirects=False,
                                     verify=verify_source(connection)) as client:
            resp = await client.post(
                url, json={"jsonrpc": "2.0", "id": 1, "method": "initialize",
                           "params": {"protocolVersion": "2025-03-26", "capabilities": {}, "clientInfo": {"name": "ares", "version": "0"}}},
                headers={"Accept": "application/json, text/event-stream", "Content-Type": "application/json"},
            )

            if resp.status_code != 401:
                return [Finding(
                    test_id="auth.oauth_metadata_security", title="No aplica: el server no devolvió 401 sin credenciales",
                    category=Category.AUTH, target="server",
                    description=f"Respondió {resp.status_code} sin Authorization -- ver auth.unauthenticated_access "
                                 f"para el análisis de esto. Sin un 401, no hay nada de descubrimiento OAuth que evaluar.",
                    passed=True,
                )]

            www_auth = resp.headers.get("www-authenticate", "")
            m = re.search(r'resource_metadata="([^"]+)"', www_auth)
            if not m:
                return [Finding(
                    test_id="auth.oauth_metadata_security",
                    title="Sin 'resource_metadata' en WWW-Authenticate (RFC 9728)",
                    category=Category.AUTH,
                    target="server",
                    description=f"El server devolvió 401 pero su header WWW-Authenticate ('{www_auth}') no "
                                 f"incluye el parámetro 'resource_metadata' que exige RFC 9728 / el spec de "
                                 f"autorización de MCP. Un cliente MCP compliant no puede descubrir "
                                 f"automáticamente el authorization server correspondiente.",
                    evidence=Evidence(response={"www_authenticate": www_auth, "status": resp.status_code}),
                    passed=False,
                    remediation="Implementar OAuth 2.0 Protected Resource Metadata (RFC 9728): incluir "
                                 "'resource_metadata=\"<url>\"' en el header WWW-Authenticate del 401.",
                    references=["https://modelcontextprotocol.io/specification/draft/basic/authorization",
                                "https://www.rfc-editor.org/rfc/rfc9728"],
                )]

            metadata_url = m.group(1)
            meta_resp = await client.get(metadata_url)
            metadata = meta_resp.json()
            auth_servers = metadata.get("authorization_servers") or []
            if not auth_servers:
                return [Finding(
                    test_id="auth.oauth_metadata_security", title="Protected Resource Metadata sin authorization_servers",
                    category=Category.AUTH, target="server",
                    description=f"'{metadata_url}' respondió pero no declara ningún 'authorization_servers'.",
                    evidence=Evidence(response=metadata),
                    passed=False,
                    remediation="Declarar al menos un authorization server válido en el Protected Resource Metadata.",
                )]

            as_issuer = auth_servers[0]
            as_metadata = None
            for suffix in ("/.well-known/oauth-authorization-server", "/.well-known/openid-configuration"):
                try:
                    as_url = urljoin(as_issuer.rstrip("/") + "/", suffix.lstrip("/"))
                    as_resp = await client.get(as_url)
                    if as_resp.status_code == 200:
                        as_metadata = as_resp.json()
                        break
                except Exception:
                    continue

            if not as_metadata:
                return [Finding(
                    test_id="auth.oauth_metadata_security", title="No se pudo obtener metadata del authorization server",
                    category=Category.AUTH, target="server",
                    description=f"authorization_servers apunta a '{as_issuer}' pero no se pudo descubrir su "
                                 f"metadata (RFC 8414) para chequear soporte de PKCE.",
                    passed=True,
                )]

            pkce_methods = as_metadata.get("code_challenge_methods_supported") or []
            if "S256" not in pkce_methods:
                return [Finding(
                    test_id="auth.oauth_metadata_security",
                    title="El authorization server no anuncia soporte de PKCE (S256)",
                    category=Category.AUTH,
                    target=as_issuer,
                    description=f"'code_challenge_methods_supported' = {pkce_methods}. OAuth 2.1 (que el spec "
                                 f"de MCP adopta) requiere PKCE obligatorio; sin S256 anunciado, un cliente "
                                 f"legítimo no puede confirmar que el authorization server lo va a exigir, y "
                                 f"el authorization code queda expuesto a interceptación por otra app en el "
                                 f"mismo dispositivo.",
                    evidence=Evidence(response=as_metadata),
                    passed=False,
                    remediation="Exigir PKCE (S256) en el authorization server para todos los clientes MCP.",
                    references=["https://oauth.net/2.1/"],
                )]

            return [Finding(
                test_id="auth.oauth_metadata_security", title="Descubrimiento OAuth (RFC 9728) y PKCE OK",
                category=Category.AUTH, target="server",
                description="WWW-Authenticate incluye resource_metadata, el authorization server se pudo "
                             "descubrir, y anuncia soporte de PKCE S256.",
                passed=True,
            )]
    except Exception as e:
        return [Finding(
            test_id="auth.oauth_metadata_security", title="No se pudo evaluar metadata OAuth",
            category=Category.AUTH, target="server",
            description=f"Error de red/parseo durante el chequeo: {e}", passed=True,
        )]


_WRITE_RE = re.compile(r"save|store|write|set|create|add|put|upload|update|insert|remember", re.IGNORECASE)
_READ_RE = re.compile(r"read|get|fetch|list|show|view|retrieve|recall", re.IGNORECASE)


def _required_string_params(schema: dict) -> list[str]:
    props = schema.get("properties", {}) or {}
    required = set(schema.get("required", []) or [])
    return [p for p, s in props.items()
            if isinstance(s, dict) and s.get("type", "string") == "string" and p in required]


@register_test(
    id="auth.cross_session_context_bleed",
    name="Fuga de contexto entre sesiones/tenants (canario cross-session)",
    category=Category.AUTH,
    description="Requiere una SEGUNDA credencial válida contra el mismo server (--auth-token-b): planta un "
                 "canario único llamando tools de escritura con la sesión PRIMARIA, abre una sesión NUEVA con "
                 "la credencial secundaria, y busca que el canario aparezca SIN que esa segunda sesión lo haya "
                 "plantado -- confirma que el contexto/datos NO está aislado entre sesiones/tenants distintos "
                 "(MCP10:2025 Context Injection & Over-Sharing), con evidencia de ejecución real vía canario, "
                 "no heurística. Es la pieza de MCP10 que ninguna otra parte de Ares cubre: "
                 "auth.resource_object_level varía un ID DENTRO de una sesión; esto varía la SESIÓN/identidad "
                 "misma. Solo aplica a transporte http/sse (stdio no tiene noción de sesión separable). "
                 "Intrusivo (escribe datos reales) y opt-in.",
    default_enabled=False,
)
async def cross_session_context_bleed(target, ctx) -> list[Finding]:
    transport = ctx.get("transport")
    if transport not in ("http", "sse"):
        return [Finding(
            test_id="auth.cross_session_context_bleed", title="No aplica (transporte stdio)",
            category=Category.AUTH, target="server",
            description="stdio no tiene noción de sesión separable entre 'identidades' -- este test solo "
                         "tiene sentido contra transporte http/sse.",
            passed=True,
        )]

    secondary_auth = ctx.get("secondary_auth")
    if secondary_auth is None or not getattr(secondary_auth, "token", None):
        return [Finding(
            test_id="auth.cross_session_context_bleed", title="No se pudo evaluar (sin segunda credencial)",
            category=Category.AUTH, target="server",
            description="Requiere --auth-token-b (una segunda credencial/tenant válido) para abrir una "
                         "segunda sesión y buscar fuga de contexto -- no se pasó, test salteado.",
            passed=True,
        )]

    if target is None:
        return [Finding(
            test_id="auth.cross_session_context_bleed", title="No se pudo evaluar (sin sesión primaria)",
            category=Category.AUTH, target="server",
            description="No hay sesión primaria activa.", passed=True,
        )]

    tools = ctx.get("tools") or await target.list_tools()
    # DOS canarios, no uno -- confirmado el motivo con un falso positivo real probando esto:
    # con un solo canario usado como clave Y como contenido, un simple ECO del argumento
    # (ej. read_file(path=canario) fallando con "no existe el archivo '<canario>'") es
    # indistinguible de una fuga real. canary_id solo se usa para IDENTIFICAR (se manda
    # en llamadas de lectura); canary_secret es lo que se busca en la respuesta y NUNCA
    # se manda como argumento en ninguna llamada de lectura -- cualquier aparición es
    # inequívoca, sin falsos positivos por reflejo posibles (no hace falta strip_reflections).
    canary_id = new_canary("ARES_CTXBLEED_ID")
    canary_secret = new_canary("ARES_CTXBLEED_SECRET")

    # 1) plantar con la sesión PRIMARIA: primer parámetro string requerido = identificador
    # (canary_id), el resto = contenido (canary_secret) -- asume el orden de declaración del
    # schema como "identificador primero" (patrón común: name+content, key+value, id+data).
    planted_in = []
    for tool in tools:
        if not _WRITE_RE.search(tool["name"] + " " + (tool.get("description") or "")):
            continue
        schema = tool.get("input_schema") or {}
        str_params = _required_string_params(schema)
        if len(str_params) < 2:
            continue  # sin separación clara id/contenido, no se puede confirmar sin ambigüedad
        args = {str_params[0]: canary_id}
        args.update({p: canary_secret for p in str_params[1:]})
        result = await target.call_tool(tool["name"], args)
        if result.get("ok") and not result.get("is_error"):
            planted_in.append(tool["name"])

    if not planted_in:
        return [Finding(
            test_id="auth.cross_session_context_bleed",
            title="Sin tools de escritura aptas para plantar el canario",
            category=Category.AUTH, target="server",
            description="Ningún tool con nombre tipo save/store/write/set/create y al menos un parámetro "
                         "string requerido aceptó el canario -- no se pudo plantar nada que buscar después.",
            passed=True,
        )]

    # 2) abrir una sesión NUEVA con la credencial SECUNDARIA y buscar el canario SIN haberlo
    # plantado desde ahí -- si aparece, el contexto cruzó la frontera de sesión/tenant.
    connection_b = dict(ctx.get("connection") or {})
    connection_b["auth"] = secondary_auth
    findings = []
    try:
        async with MCPTarget(ctx["transport"], connection_b) as target_b:
            tools_b = await target_b.list_tools()

            for tool in tools_b:
                if not _READ_RE.search(tool["name"] + " " + (tool.get("description") or "")):
                    continue
                schema = tool.get("input_schema") or {}
                required = schema.get("required", []) or []
                # dos intentos: "test" genérico (tools tipo 'listar todo', que leakean sin
                # necesitar saber ninguna clave) y canary_id en cada parámetro requerido
                # (para los que hacen lookup por id/clave) -- en NINGUNO de los dos casos se
                # manda canary_secret como argumento, así que buscarlo en la respuesta nunca
                # puede ser un eco del propio request, solo un hallazgo real.
                found_content = ""
                for probe in ({r: "test" for r in required}, {r: canary_id for r in required}):
                    result = await target_b.call_tool(tool["name"], probe)
                    content = str(result.get("content", ""))
                    if canary_secret in content:
                        found_content = content
                        break
                if found_content:
                    findings.append(Finding(
                        test_id="auth.cross_session_context_bleed",
                        title=f"Fuga de contexto CONFIRMADA: canario plantado con otra sesión visible en '{tool['name']}'",
                        category=Category.AUTH,
                        target=tool["name"],
                        description=f"Se plantó un canario único ({canary_secret}) llamando a {planted_in} con la "
                                     f"sesión primaria. Una sesión NUEVA, autenticada con una credencial "
                                     f"distinta, pudo leerlo de vuelta vía '{tool['name']}' sin que nadie se "
                                     f"lo haya dado -- el contexto/datos NO está aislado entre sesiones/"
                                     f"tenants. Ejecución real confirmada por canario, no heurística.",
                        evidence=Evidence(request={"planted_via": planted_in, "canary_id": canary_id, "canary_secret": canary_secret},
                                           response={"leaked_via": tool["name"]}),
                        passed=False,
                        remediation="Aislar el estado/contexto por sesión/tenant autenticado -- nunca "
                                     "compartir un almacén global entre credenciales distintas.",
                        references=["https://owasp.org/www-project-mcp-top-10/"],
                    ))

            # resources estáticos también -- el canario puede quedar visible ahí sin llamar tool alguno
            resources_b = await target_b.list_resources()
            for r in resources_b:
                result = await target_b.read_resource(r["uri"])
                if canary_secret in str(result.get("content", "")):
                    findings.append(Finding(
                        test_id="auth.cross_session_context_bleed",
                        title=f"Fuga de contexto CONFIRMADA: canario visible en resource '{r['uri']}'",
                        category=Category.AUTH,
                        target=r["uri"],
                        description=f"El canario plantado con la sesión primaria ({canary_secret}) apareció en el "
                                     f"resource '{r['uri']}' leído con una sesión distinta.",
                        evidence=Evidence(request={"planted_via": planted_in, "canary_id": canary_id, "canary_secret": canary_secret},
                                           response={"leaked_via": r["uri"]}),
                        passed=False,
                        remediation="Aislar resources por sesión/tenant -- nunca servir el mismo estado a "
                                     "credenciales distintas.",
                        references=["https://owasp.org/www-project-mcp-top-10/"],
                    ))
    except Exception as e:
        return [Finding(
            test_id="auth.cross_session_context_bleed", title="No se pudo abrir la sesión secundaria",
            category=Category.AUTH, target="server",
            description=f"Falló la conexión con la credencial secundaria: {e}", passed=True,
        )]

    if not findings:
        findings.append(Finding(
            test_id="auth.cross_session_context_bleed", title="Sin fuga de contexto cross-session detectada",
            category=Category.AUTH, target="server",
            description=f"El canario plantado con la sesión primaria ({canary_secret}) no apareció en ningún tool "
                         f"de lectura ni resource accedido con la sesión secundaria.",
            passed=True,
        ))
    return findings
