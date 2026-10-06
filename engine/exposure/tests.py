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
import asyncio
import ipaddress
import socket
from urllib.parse import urlparse

import httpx

from engine.core.models import Finding, Evidence, Category
from engine.core.risk import build_vector, base_vector_for
from engine.core.registry import register_test
from engine.core.tls import inspect_certificate, verify_source

HOSTILE_ORIGIN = "https://evil.example.com"


def _url_from_ctx(ctx) -> str | None:
    connection = ctx.get("connection") or {}
    return connection.get("url")


def _ca_bundle_from_ctx(ctx) -> str | None:
    connection = ctx.get("connection") or {}
    return connection.get("ca_bundle")


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
        async with httpx.AsyncClient(timeout=5.0, verify=verify_source(ctx.get("connection") or {})) as client:
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


@register_test(
    id="exposure.certificate_type",
    name="Tipo de certificado TLS del server",
    category=Category.EXPOSURE,
    description="Inspecciona el certificado TLS que presenta el endpoint https/wss y lo clasifica "
                 "(CA pública, CA interna/privada, self-signed, expirado), anotando emisor, sujeto, "
                 "validez y fingerprint SHA-256 en el reporte. Valida la cadena contra el trust store "
                 "por defecto y, si se pasó --ca-bundle (o SSL_CERT_FILE), también contra esa CA.",
)
async def certificate_type(target, ctx) -> list[Finding]:
    url = _url_from_ctx(ctx)
    if not url or urlparse(url).scheme not in ("https", "wss"):
        # endpoint sin TLS (o stdio): exposure.transport_security ya cubre ese caso.
        return []

    ca_bundle = _ca_bundle_from_ctx(ctx)
    info = await asyncio.to_thread(inspect_certificate, url, ca_bundle)

    if info is None:
        return []
    if "error" in info:
        return [Finding(
            test_id="exposure.certificate_type", title="No se pudo inspeccionar el certificado TLS",
            category=Category.EXPOSURE, target="server",
            description=info["error"], passed=True,
            evidence=Evidence(notes=info["error"]),
        )]

    cert_type = info.get("type", "desconocido")
    expired = info.get("expired")
    trusted_default = info.get("trusted_by_default")
    trusted_custom = info.get("trusted_by_custom_ca")  # None si no se pasó CA custom

    # Dictamen minucioso y graduado (ver engine/core/tls.py::assess_certificate): no es
    # pass/fail binario -- pondera cadena de confianza, vigencia, hostname, firma/clave y
    # alcance de red para separar riesgo REAL vs NO-riesgo vs autofirmado-interno manejable.
    verdict = info.get("assessment") or {}
    is_problem = not verdict.get("passed", True)

    # Línea sobre la validación contra la CA custom, solo si se pasó una.
    if trusted_custom is None:
        ca_line = ""
    elif trusted_custom:
        ca_line = f" Valida contra la CA provista ('{ca_bundle}')."
    else:
        ca_line = f" NO valida ni siquiera contra la CA provista ('{ca_bundle}')."

    parts = [
        f"DICTAMEN: {verdict.get('headline', '')}",
        f"Clasificación: {cert_type}.",
        f"Emisor: {info.get('issuer') or 'desconocido'}.",
        f"Sujeto: {info.get('subject') or 'desconocido'}.",
        f"Validez: {info.get('not_before') or '?'} → {info.get('not_after') or '?'}"
        + (" (EXPIRADO)" if expired else "") + ".",
        f"Host conectado: {info.get('host')}"
        + (f" ({info.get('peer_ip')}, {'interno' if info.get('is_internal') else 'público'})"
           if info.get("is_internal") is not None else "") + ".",
        f"TLS: {info.get('tls_version') or '?'}.",
        f"Fingerprint SHA-256: {info.get('fingerprint_sha256')}.",
        f"Valida contra el trust store público: {'sí' if trusted_default else 'no'}." + ca_line,
    ]
    if info.get("signature_algorithm"):
        parts.append(f"Algoritmo de firma: {info['signature_algorithm']}.")
    if info.get("key_type"):
        parts.append(f"Clave: {info['key_type']}.")

    # Enumerar cada factor evaluado con su signo, para que el reporte explique el PORQUÉ.
    _MARK = {"ok": "[OK]", "caution": "[~]", "bad": "[X]", "info": "[i]"}
    for fac in verdict.get("factors", []):
        parts.append(f"{_MARK.get(fac['status'], '-')} {fac['text']}")

    # Si la conexión se completó fijando este mismo cert (--trust-presented-cert), dejarlo
    # explícito: el scan pudo correr, pero la confianza fue TOFU, no una CA real.
    if (ctx.get("connection") or {}).get("pinned_cert_file"):
        parts.append("[~] La conexión se completó FIJANDO este certificado (--trust-presented-cert, pinning TOFU): "
                     "el scan pudo ejecutarse, pero eso NO valida la identidad del server contra una CA de confianza.")

    references: list[str] = []
    if is_problem:
        # Por qué un certificado no confiable ES un riesgo, según frameworks reconocidos:
        # OWASP MCP Top 10 MCP07:2025 (Transport Security), OWASP API Security Top 10
        # API8:2023 (Security Misconfiguration) y CWE-295 (Improper Certificate Validation).
        references = [
            "https://cwe.mitre.org/data/definitions/295.html",
            "https://owasp.org/API-Security/editions/2023/en/0xa8-security-misconfiguration/",
            "https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Security_Cheat_Sheet.html",
        ]
        parts.append(
            "Marco de riesgo: OWASP MCP Top 10 MCP07:2025 (Transport Security), OWASP API Security "
            "Top 10 API8:2023 (Security Misconfiguration), CWE-295 (Improper Certificate Validation). "
            "TLS cifra pero no autentica la identidad del server cuando el certificado no se puede "
            "verificar contra una raíz de confianza -- esa es la condición que habilita el MITM."
        )
        if verdict.get("verdict") == "riesgo-manejable":
            remediation = ("Riesgo acotado por ser interno, pero no lo dejes como confianza implícita: "
                           "formalizalo con una CA interna (y audita con --ca-bundle) o con pinning del "
                           "fingerprint SHA-256. Si el endpoint pasara a ser alcanzable desde fuera, sube "
                           "a riesgo real de inmediato.")
        elif expired:
            remediation = "El certificado está fuera de vigencia -- renovarlo ya; los clientes que validan lo rechazan."
        elif cert_type == "self-signed":
            remediation = ("Reemplazar el self-signed por uno emitido por una CA (pública o interna). Si es un "
                           "entorno interno con CA propia, auditar pasando --ca-bundle con esa CA para validar "
                           "la cadena en vez de ignorar la verificación.")
        else:
            remediation = ("La cadena no valida contra ningún trust store conocido. Si el server usa una CA "
                           "interna, pasá --ca-bundle con esa CA; si no, emitir el certificado desde una CA de confianza.")
    else:
        remediation = ""

    title_map = {
        "sin-riesgo": f"Certificado TLS OK ({cert_type}) -- no es un riesgo",
        "riesgo-manejable": f"Certificado TLS {cert_type} -- riesgo posible pero MANEJABLE (interno)",
        "riesgo": f"Certificado TLS {cert_type} -- RIESGO (man-in-the-middle)",
    }
    return [Finding(
        test_id="exposure.certificate_type",
        title=title_map.get(verdict.get("verdict"), f"Certificado TLS: {cert_type}"),
        category=Category.EXPOSURE,
        target="server",
        description="  ".join(parts),
        passed=not is_problem,
        remediation=remediation,
        references=references,
        cvss_vector_override=verdict.get("cvss_override"),
        business_impact_override=verdict.get("business_override"),
        evidence=Evidence(response={
            **{k: v for k, v in info.items() if k not in ("ca_bundle", "assessment")},
            # dictamen recortado (sin los overrides internos de CVSS) para el JSON y el dashboard
            "assessment": {
                "verdict": verdict.get("verdict"),
                "headline": verdict.get("headline"),
                "factors": verdict.get("factors", []),
            },
        }),
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
