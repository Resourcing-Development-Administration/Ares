"""
Tests de exposición de red: TLS, CORS, y si el host resuelve a una IP
privada (alcance interno) o pública (alcance desde Internet). Solo aplica a
transporte http/sse; usan httpx directo (no la sesión MCP) porque son sondas
HTTP crudas fuera del protocolo MCP.

Ideas portadas de:
- cli/internal/scanner/probes.go::testTransport() (TLS + CORS)
- mcpscan/exposure/{proxy-internal,proxy-public} (clasificación interno/público)
"""
from __future__ import annotations
import ipaddress
import socket
from urllib.parse import urlparse

import httpx

from engine.core.models import Finding, Evidence, Category
from engine.core.risk import build_vector, base_vector_for
from engine.core.registry import register_test

HOSTILE_ORIGIN = "https://evil.example.com"


def _url_from_ctx(ctx) -> str | None:
    connection = ctx.get("connection") or {}
    return connection.get("url")


@register_test(
    id="exposure.transport_security",
    name="Transporte sin TLS",
    category=Category.EXPOSURE,
    description="Marca si el endpoint http/sse corre en texto plano (http://) en vez de https://.",
)
async def transport_security(target, ctx) -> list[Finding]:
    url = _url_from_ctx(ctx)
    if not url:
        return []
    scheme = urlparse(url).scheme
    if scheme == "http":
        return [Finding(
            test_id="exposure.transport_security",
            title="Endpoint MCP servido sin TLS",
            category=Category.EXPOSURE,
            target="server",
            description=f"'{url}' usa http:// en vez de https://. Todo el tráfico (incluyendo tokens de "
                         f"auth en headers) viaja en texto plano.",
            passed=False,
            remediation="Servir el endpoint MCP exclusivamente sobre TLS (https/wss), incluso en redes internas.",
        )]
    return [Finding(
        test_id="exposure.transport_security", title="Transporte con TLS",
        category=Category.EXPOSURE, target="server",
        description=f"'{url}' usa {scheme}://.", passed=True,
    )]


@register_test(
    id="exposure.cors_misconfig",
    name="Configuración CORS insegura",
    category=Category.EXPOSURE,
    description="Envía un preflight OPTIONS con un Origin hostil y evalúa si el servidor responde con "
                 "wildcard (*) o con reflejo dinámico del origin (peor: indica que no valida allowlist).",
)
async def cors_misconfig(target, ctx) -> list[Finding]:
    url = _url_from_ctx(ctx)
    if not url or urlparse(url).scheme not in ("http", "https"):
        return []

    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            resp = await client.options(url, headers={
                "Origin": HOSTILE_ORIGIN,
                "Access-Control-Request-Method": "POST",
            })
    except Exception as e:
        return [Finding(
            test_id="exposure.cors_misconfig", title="No se pudo evaluar CORS",
            category=Category.EXPOSURE, target="server",
            description=f"OPTIONS falló: {e}", passed=True,
        )]

    acao = resp.headers.get("access-control-allow-origin", "")
    acac = resp.headers.get("access-control-allow-credentials", "")

    if acao == HOSTILE_ORIGIN:
        return [Finding(
            test_id="exposure.cors_misconfig",
            title="CORS refleja dinámicamente cualquier Origin",
            category=Category.EXPOSURE,
            target="server",
            # reflejo dinámico + posible credentials=true -> lectura/escritura cross-origin autenticada real.
            cvss_vector_override=build_vector(base_vector_for("exposure.cors_misconfig"), C="H", I="H"),
            description=f"El servidor devolvió Access-Control-Allow-Origin: {acao} para un Origin "
                         f"arbitrario ('{HOSTILE_ORIGIN}'){' junto con Allow-Credentials: true' if acac.lower() == 'true' else ''}. "
                         f"Esto permite a cualquier sitio web hacer requests autenticados desde el navegador de la víctima.",
            evidence=Evidence(response=dict(resp.headers)),
            passed=False,
            remediation="Usar una allowlist explícita de orígenes confiables; nunca reflejar el header Origin recibido.",
        )]
    if acao == "*":
        creds = acac.lower() == "true"
        return [Finding(
            test_id="exposure.cors_misconfig",
            title="CORS wildcard (Access-Control-Allow-Origin: *)",
            category=Category.EXPOSURE,
            target="server",
            # wildcard + Allow-Credentials:true es mucho peor que wildcard solo (que ni siquiera
            # debería combinarse con credentials según el propio spec de CORS).
            cvss_vector_override=(build_vector(base_vector_for("exposure.cors_misconfig"), C="H") if creds else None),
            description="El servidor permite requests cross-origin desde cualquier dominio.",
            evidence=Evidence(response=dict(resp.headers)),
            passed=False,
            remediation="Restringir Access-Control-Allow-Origin a una allowlist explícita.",
        )]
    return [Finding(
        test_id="exposure.cors_misconfig", title="CORS no refleja origin hostil",
        category=Category.EXPOSURE, target="server",
        description="El servidor no devolvió wildcard ni reflejo dinámico del Origin de prueba.",
        passed=True,
    )]


@register_test(
    id="exposure.network_reachability",
    name="Clasificación de alcance de red (interno vs público)",
    category=Category.EXPOSURE,
    description="Resuelve el host del endpoint y clasifica si es una IP privada/loopback (alcance interno) "
                 "o pública (alcanzable desde Internet), para dimensionar el blast radius real.",
)
async def network_reachability(target, ctx) -> list[Finding]:
    url = _url_from_ctx(ctx)
    if not url:
        return []
    host = urlparse(url).hostname
    if not host:
        return []
    try:
        ip_str = socket.gethostbyname(host)
        ip = ipaddress.ip_address(ip_str)
    except Exception as e:
        return [Finding(
            test_id="exposure.network_reachability", title="No se pudo resolver el host",
            category=Category.EXPOSURE, target="server",
            description=f"gethostbyname('{host}') falló: {e}", passed=True,
        )]

    is_internal = ip.is_private or ip.is_loopback or ip.is_link_local
    return [Finding(
        test_id="exposure.network_reachability",
        title=f"Alcance {'interno' if is_internal else 'público'}: {host} -> {ip}",
        category=Category.EXPOSURE,
        target="server",
        description=(
            f"'{host}' resuelve a {ip}, una IP {'privada/loopback' if is_internal else 'pública'}. "
            + ("El blast radius de cualquier hallazgo confirmado se limita a quien tenga acceso a esta red."
               if is_internal else
               "Cualquier hallazgo confirmado (auth débil, SSRF, etc.) es explotable desde Internet.")
        ),
        passed=is_internal,
        remediation="" if is_internal else "Evaluar si este servidor necesita estar expuesto públicamente; "
                                             "si no, moverlo detrás de VPN/allowlist de IPs.",
    )]


def _shannon_entropy_bits(s: str) -> float:
    import math
    if not s:
        return 0.0
    counts = {}
    for c in s:
        counts[c] = counts.get(c, 0) + 1
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


@register_test(
    id="exposure.session_id_entropy",
    name="Entropía y longitud del Mcp-Session-Id (transporte http)",
    category=Category.EXPOSURE,
    description="Analiza el Mcp-Session-Id que el server asignó a esta sesión: longitud, entropía (bits/char "
                 "x longitud) y patrones obvios (todo numérico, muy corto). Un session ID corto o de baja "
                 "entropía es adivinable/fuerza-bruteable, permitiendo secuestro de sesión sin credenciales.",
)
async def session_id_entropy(target, ctx) -> list[Finding]:
    if ctx.get("transport") != "http" or target is None:
        return []

    session_id = target.get_session_id() if hasattr(target, "get_session_id") else None
    if not session_id:
        return [Finding(
            test_id="exposure.session_id_entropy", title="El server no asignó Mcp-Session-Id",
            category=Category.EXPOSURE, target="server",
            description="No se pudo leer un Mcp-Session-Id de esta conexión (puede que el server no use "
                         "sesiones stateful, lo cual no es en sí un problema).",
            passed=True,
        )]

    entropy_bits_per_char = _shannon_entropy_bits(session_id)
    total_entropy_bits = entropy_bits_per_char * len(session_id)
    is_numeric_only = session_id.isdigit()

    weak = len(session_id) < 16 or total_entropy_bits < 64 or is_numeric_only
    return [Finding(
        test_id="exposure.session_id_entropy",
        title=f"Session ID {'débil' if weak else 'con entropía razonable'} ({len(session_id)} chars, ~{total_entropy_bits:.0f} bits)",
        category=Category.EXPOSURE,
        target="server",
        description=(
            f"Mcp-Session-Id de {len(session_id)} caracteres, ~{total_entropy_bits:.0f} bits de entropía "
            f"estimada{' (solo dígitos -- muy adivinable)' if is_numeric_only else ''}. "
            + ("Por debajo del mínimo recomendado (128+ bits de un CSPRNG) -- un atacante podría fuerza-bruta "
               "o predecir session IDs válidos y secuestrar sesiones ajenas sin ninguna credencial."
               if weak else
               "Longitud y entropía razonables para un identificador de sesión.")
        ),
        evidence=Evidence(notes=f"session_id (primeros 8 chars): {session_id[:8]}..."),
        passed=not weak,
        remediation="Generar el session ID con un CSPRNG, con al menos 128 bits de entropía, y nunca "
                     "derivarlo de un contador o timestamp.",
        references=["https://cheatsheetseries.owasp.org/cheatsheets/MCP_Security_Cheat_Sheet.html"],
    )]
