"""
Soporte de TLS / CA custom para transporte http/sse.

Dos cosas:

1. Resolver QUÉ bundle de CA usar para validar el certificado del server
   (flag `--ca-bundle`, con fallback a la variable de entorno estándar
   `SSL_CERT_FILE`) y exponerlo en la forma que espera httpx (`verify=`).
   Esto permite auditar un server MCP interno servido con una CA corporativa
   o un certificado emitido por una CA privada, SIN desactivar la verificación
   TLS -- confiar en una CA interna no es lo mismo que `verify=False`.

2. Inspeccionar el certificado que el server realmente presenta, para anotar
   en el reporte QUÉ TIPO de certificado es (CA pública, CA interna/privada,
   self-signed, expirado...), su emisor, su validez y su fingerprint. Es una
   observación directa del certificado servido, no una heurística.

Notas sobre variables de entorno: `REQUESTS_CA_BUNDLE` (de la librería
`requests`) y `NODE_EXTRA_CA_CERTS` (de Node) NO aplican acá -- Ares es
Python/httpx. La variable estándar que httpx/OpenSSL sí honran, y la que
usamos como fallback, es `SSL_CERT_FILE`.
"""
from __future__ import annotations
import hashlib
import os
import socket
import ssl
from datetime import datetime, timezone
from typing import Optional, Union
from urllib.parse import urlparse

# Puertos por defecto cuando la URL no lo especifica.
_DEFAULT_TLS_PORT = 443


def resolve_ca_bundle(explicit: Optional[str]) -> Optional[str]:
    """Ruta al bundle de CA a usar para validar el server: el flag explícito si
    se dio, si no la env var estándar `SSL_CERT_FILE`, si no `None` (trust store
    por defecto de httpx: certifi).

    Lanza `ValueError` si la ruta resuelta no existe -- fallar ruidoso es mejor
    que caer en silencio al trust store por defecto y reportar un falso "TLS
    roto" que confunde al operador.
    """
    candidate = explicit or os.environ.get("SSL_CERT_FILE")
    if candidate and not os.path.isfile(candidate):
        raise ValueError(
            f"CA bundle no encontrado: {candidate!r} "
            f"({'--ca-bundle' if explicit else 'variable SSL_CERT_FILE'})."
        )
    return candidate or None


def ca_bundle_source(explicit: Optional[str]) -> Optional[str]:
    """De dónde salió el bundle resuelto (para anotarlo/loguear): 'flag',
    'SSL_CERT_FILE', o None si no hay bundle custom."""
    if explicit:
        return "flag"
    if os.environ.get("SSL_CERT_FILE"):
        return "SSL_CERT_FILE"
    return None


def httpx_verify(ca_bundle: Optional[str]) -> Union[str, bool]:
    """Valor a pasar como `verify=` a httpx.AsyncClient: la ruta al bundle de CA
    si hay uno custom, o `True` (verificación con el trust store por defecto).
    Nunca devuelve `False`: Ares no desactiva la verificación TLS."""
    return ca_bundle if ca_bundle else True


def _host_port(url: str) -> Optional[tuple[str, int]]:
    parsed = urlparse(url)
    if parsed.scheme not in ("https", "wss"):
        return None
    host = parsed.hostname
    if not host:
        return None
    return host, parsed.port or _DEFAULT_TLS_PORT


def _verifies(host: str, port: int, ca_bundle: Optional[str], timeout: float) -> bool:
    """¿El certificado del server valida (cadena + hostname) contra este trust
    store? ca_bundle=None usa el default del sistema/certifi."""
    try:
        ctx = ssl.create_default_context(cafile=ca_bundle) if ca_bundle else ssl.create_default_context()
    except Exception:
        return False
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host):
                return True
    except Exception:
        return False


# Algoritmos de firma rotos/obsoletos -- un cert firmado con esto es forjable aun si
# "valida" contra una CA que todavía los acepta.
_WEAK_SIG_ALGOS = ("md5", "md2", "md4", "sha1")


def _decode_cert(der: bytes) -> dict:
    """Extrae subject/issuer/validez/algoritmo/SANs/fortaleza de clave del DER crudo,
    best-effort y sin exigir dependencias: usa `cryptography` si está instalada (da
    también algoritmo de firma, tipo/tamaño de clave y SANs estructurados), si no cae
    al decoder de la stdlib (que igual trae subject/issuer/validez/SANs)."""
    # 1) cryptography (mejor detalle, si está disponible)
    try:
        from cryptography import x509
        from cryptography.hazmat.primitives.asymmetric import rsa, ec, dsa

        cert = x509.load_der_x509_certificate(der)
        subject = cert.subject.rfc4514_string()
        issuer = cert.issuer.rfc4514_string()
        pub = cert.public_key()
        weak_key = None
        if isinstance(pub, rsa.RSAPublicKey):
            key_type = f"RSA {pub.key_size} bits"
            weak_key = pub.key_size < 2048
        elif isinstance(pub, dsa.DSAPublicKey):
            key_type = f"DSA {pub.key_size} bits"
            weak_key = pub.key_size < 2048
        elif isinstance(pub, ec.EllipticCurvePublicKey):
            key_type = f"EC {pub.curve.name}"
            weak_key = pub.curve.key_size < 224
        else:
            key_type = type(pub).__name__
        try:
            sig_algo = cert.signature_hash_algorithm.name if cert.signature_hash_algorithm else None
        except Exception:
            sig_algo = None
        weak_sig = (sig_algo.lower() in _WEAK_SIG_ALGOS) if sig_algo else None
        sans: list[str] = []
        try:
            ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
            sans = [str(n.value) for n in ext.value]
        except Exception:
            sans = []
        return {
            "subject": subject, "issuer": issuer,
            "self_signed": subject == issuer,
            "not_before": cert.not_valid_before_utc.isoformat(),
            "not_after": cert.not_valid_after_utc.isoformat(),
            "signature_algorithm": sig_algo, "weak_signature": weak_sig,
            "key_type": key_type, "weak_key": weak_key,
            "sans": sans, "serial": format(cert.serial_number, "x"),
        }
    except ImportError:
        pass
    except Exception:
        pass

    # 2) stdlib: DER -> PEM -> decode. Usa el mismo decoder que getpeercert() -- trae
    # subject/issuer/validez/SANs, pero NO algoritmo de firma ni tamaño de clave.
    try:
        import tempfile

        pem = ssl.DER_cert_to_PEM_cert(der)
        tmp = tempfile.NamedTemporaryFile("w", suffix=".pem", delete=False)
        try:
            tmp.write(pem)
            tmp.close()
            decoded = ssl._ssl._test_decode_cert(tmp.name)  # type: ignore[attr-defined]
        finally:
            os.unlink(tmp.name)
        subject = _rdn_to_str(decoded.get("subject"))
        issuer = _rdn_to_str(decoded.get("issuer"))
        sans = [v for (t, v) in decoded.get("subjectAltName", ()) if t.lower() == "dns"]
        return {
            "subject": subject, "issuer": issuer,
            "self_signed": (subject == issuer) if (subject and issuer) else None,
            "not_before": decoded.get("notBefore"), "not_after": decoded.get("notAfter"),
            "signature_algorithm": None, "weak_signature": None,
            "key_type": None, "weak_key": None,
            "sans": sans, "serial": decoded.get("serialNumber"),
        }
    except Exception:
        return {
            "subject": None, "issuer": None, "self_signed": None,
            "not_before": None, "not_after": None,
            "signature_algorithm": None, "weak_signature": None,
            "key_type": None, "weak_key": None, "sans": [], "serial": None,
        }


def _host_matches(host: str, names: list[str]) -> bool:
    """Match de hostname estilo RFC 6125 simplificado: exacto o wildcard de UN solo
    label (*.dominio.com). Suficiente para decir si el cert cubre el host al que
    efectivamente nos conectamos."""
    host = (host or "").lower().rstrip(".")
    for n in names:
        n = (n or "").lower().rstrip(".")
        if not n:
            continue
        if n == host:
            return True
        if n.startswith("*.") and "." in host:
            if host.split(".", 1)[1] == n[2:]:
                return True
    return False


def _days_to_expiry(not_after: str | None) -> int | None:
    if not not_after:
        return None
    for parse in (_parse_iso, _parse_openssl):
        dt = parse(not_after)
        if dt is not None:
            return (dt - datetime.now(timezone.utc)).days
    return None


def _is_internal_ip(ip_str: str | None) -> bool | None:
    if not ip_str:
        return None
    try:
        import ipaddress
        ip = ipaddress.ip_address(ip_str)
        return ip.is_private or ip.is_loopback or ip.is_link_local
    except Exception:
        return None


def _rdn_to_str(rdn_seq) -> Optional[str]:
    """Convierte el subject/issuer que devuelve getpeercert() -- una tupla de
    tuplas de pares (oid, valor) -- a un string legible 'CN=.., O=..'."""
    if not rdn_seq:
        return None
    parts = []
    for rdn in rdn_seq:
        for key, value in rdn:
            parts.append(f"{key}={value}")
    return ", ".join(parts) or None


def _is_expired(not_after: Optional[str]) -> Optional[bool]:
    if not not_after:
        return None
    # ISO (cryptography) o formato OpenSSL 'Jun  1 00:00:00 2030 GMT' (stdlib)
    for parse in (_parse_iso, _parse_openssl):
        dt = parse(not_after)
        if dt is not None:
            return datetime.now(timezone.utc) > dt
    return None


def _parse_iso(s: str) -> Optional[datetime]:
    try:
        dt = datetime.fromisoformat(s)
        return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
    except Exception:
        return None


def _parse_openssl(s: str) -> Optional[datetime]:
    try:
        return datetime.strptime(s, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
    except Exception:
        return None


def _classify(info: dict) -> str:
    """Etiqueta de tipo de certificado para el reporte."""
    if info.get("trusted_by_default"):
        return "ca-signed (publicly trusted)"
    if info.get("trusted_by_custom_ca"):
        return "ca-signed (internal/private CA)"
    if info.get("self_signed") is True:
        return "self-signed"
    return "untrusted / unknown chain"


def inspect_certificate(url: str, ca_bundle: Optional[str] = None, timeout: float = 8.0) -> Optional[dict]:
    """Inspecciona el certificado TLS que presenta `url`. Devuelve un dict con el
    tipo clasificado, emisor/sujeto, validez, fingerprint SHA-256, versión de TLS
    y el resultado de validación contra el trust store por defecto y (si se dio)
    contra el `ca_bundle` custom. Devuelve None si la URL no es TLS, o un dict con
    'error' si el handshake no se pudo completar.
    """
    hp = _host_port(url)
    if hp is None:
        return None
    host, port = hp

    # 1) tomar el certificado servido SIN validar, para poder inspeccionarlo aunque
    #    la cadena no valide (self-signed, CA desconocida, expirado).
    raw_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    raw_ctx.check_hostname = False
    raw_ctx.verify_mode = ssl.CERT_NONE
    peer_ip = None
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            try:
                peer_ip = sock.getpeername()[0]
            except Exception:
                peer_ip = None
            with raw_ctx.wrap_socket(sock, server_hostname=host) as ssock:
                der = ssock.getpeercert(binary_form=True)
                tls_version = ssock.version()
    except Exception as e:
        return {"error": f"no se pudo completar el handshake TLS con {host}:{port}: {e}",
                "host": host, "port": port}

    if not der:
        return {"error": f"{host}:{port} no presentó certificado en el handshake",
                "host": host, "port": port}

    info = _decode_cert(der)
    info["host"] = host
    info["port"] = port
    info["peer_ip"] = peer_ip
    info["tls_version"] = tls_version
    info["fingerprint_sha256"] = hashlib.sha256(der).hexdigest()
    info["expired"] = _is_expired(info.get("not_after"))
    info["days_to_expiry"] = _days_to_expiry(info.get("not_after"))
    info["is_internal"] = _is_internal_ip(peer_ip)

    # 2) validación real contra cada trust store
    info["trusted_by_default"] = _verifies(host, port, None, timeout)
    info["trusted_by_custom_ca"] = _verifies(host, port, ca_bundle, timeout) if ca_bundle else None
    info["ca_bundle"] = ca_bundle

    # 3) ¿el hostname al que nos conectamos está cubierto por el cert (CN/SAN)? Si validó
    # contra algún trust store, el handshake ya lo chequeó (check_hostname=True). Si no,
    # lo evaluamos a mano con los SANs/CN disponibles.
    if info["trusted_by_default"] or info["trusted_by_custom_ca"]:
        info["hostname_match"] = True
    else:
        names = list(info.get("sans") or [])
        subj = info.get("subject") or ""
        for part in subj.split(","):
            part = part.strip()
            if part.upper().startswith("CN="):
                names.append(part[3:])
        info["hostname_match"] = _host_matches(host, names) if names else None

    info["type"] = _classify(info)
    info["assessment"] = assess_certificate(info)
    return info


# --- Dictamen minucioso del certificado --------------------------------------
# No es un pass/fail binario: pondera cadena de confianza, vigencia, coincidencia
# de hostname, fortaleza de firma/clave y ALCANCE de red (interno vs público =
# blast radius del MITM) para separar lo que ES un riesgo real, lo que NO lo es, y
# el caso intermedio (autofirmado en un endpoint interno = posible pero manejable).

_V_NONE = "sin-riesgo"          # cadena de confianza + sano -> no es un riesgo
_V_MANAGEABLE = "riesgo-manejable"  # autofirmado interno, por lo demás sano -> posible pero acotado
_V_RISK = "riesgo"              # MITM real (autofirmado público / cadena desconocida / defecto de cripto o vigencia)


def _f(status: str, text: str) -> dict:
    return {"status": status, "text": text}


def assess_certificate(info: dict) -> dict:
    """Dictamen graduado y minucioso sobre el certificado presentado.

    Devuelve {verdict, headline, factors[], passed, cvss_override, business_override}.
    `factors` enumera cada señal evaluada con su signo (ok/caution/bad/info), para que
    el reporte explique POR QUÉ el veredicto es el que es -- no solo la conclusión.
    """
    from engine.core.risk import build_vector, base_vector_for

    trusted_default = info.get("trusted_by_default")
    trusted_custom = info.get("trusted_by_custom_ca")
    self_signed = info.get("self_signed")
    expired = info.get("expired")
    days = info.get("days_to_expiry")
    is_internal = info.get("is_internal")
    hostname_match = info.get("hostname_match")
    weak_sig = info.get("weak_signature")
    weak_key = info.get("weak_key")

    trusts = bool(trusted_default) or bool(trusted_custom)
    hostname_bad = hostname_match is False
    broken_crypto = bool(weak_sig) or bool(weak_key)
    hygiene_problem = bool(expired) or broken_crypto or hostname_bad

    factors: list[dict] = []

    # 1) Cadena de confianza
    if trusted_default:
        factors.append(_f("ok", "Cadena validada contra una CA pública de confianza: la identidad del server está verificada."))
    elif trusted_custom:
        factors.append(_f("ok", "Cadena validada contra la CA interna provista con --ca-bundle: identidad verificada bajo tu raíz de confianza."))
    elif self_signed:
        factors.append(_f("bad", "Autofirmado (emisor == sujeto): ninguna autoridad respalda la identidad; por sí solo no distingue al server real de un impostor."))
    else:
        factors.append(_f("bad", "La cadena no valida contra ningún trust store conocido (CA desconocida): la identidad del server no se puede verificar."))

    # 2) Vigencia
    if expired:
        factors.append(_f("bad", "Fuera de vigencia (expirado o aún no válido): los clientes que validan lo rechazan; los que igual lo aceptan quedan expuestos."))
    elif isinstance(days, int) and 0 <= days < 30:
        factors.append(_f("caution", f"Vigente pero vence pronto (~{days} día(s)): renovar antes de que expire."))
    elif days is not None:
        factors.append(_f("ok", "Dentro del período de validez."))

    # 3) Hostname
    if hostname_bad:
        factors.append(_f("bad", "El hostname al que nos conectamos NO está cubierto por el certificado (CN/SAN): aunque la cadena fuera válida, no ata la identidad a este host."))
    elif hostname_match is True:
        factors.append(_f("ok", "El hostname coincide con el certificado (CN/SAN)."))

    # 4) Firma
    if weak_sig:
        factors.append(_f("bad", f"Algoritmo de firma débil/roto ({info.get('signature_algorithm')}): el certificado es forjable."))
    elif weak_sig is False:
        factors.append(_f("ok", f"Algoritmo de firma moderno ({info.get('signature_algorithm')})."))

    # 5) Clave
    if weak_key:
        factors.append(_f("bad", f"Clave débil ({info.get('key_type')}): por debajo del mínimo recomendado."))
    elif weak_key is False:
        factors.append(_f("ok", f"Fortaleza de clave adecuada ({info.get('key_type')})."))

    # 6) Alcance de red (blast radius del MITM)
    if is_internal is True:
        factors.append(_f("info", "Endpoint interno (IP privada/loopback): un MITM requiere estar DENTRO de esa red, y vos controlás ambos extremos -- acota el riesgo."))
    elif is_internal is False:
        factors.append(_f("caution", "Endpoint público (IP alcanzable desde Internet): un MITM es explotable por cualquiera en la ruta."))

    # --- veredicto ---
    if trusts and not hygiene_problem:
        verdict = _V_NONE
        headline = "Certificado de confianza, vigente y con criptografía sana: NO representa un riesgo."
        passed = True
        cvss_override = None
        business_override = None
    elif trusts and hygiene_problem:
        # La cadena es de confianza, pero hay un defecto real (expirado / firma o clave débil /
        # hostname que no matchea). Eso SÍ es un riesgo, independientemente de interno/público.
        verdict = _V_RISK
        headline = "Certificado respaldado por una CA pero con un defecto real (vigencia/criptografía/hostname): es un RIESGO."
        passed = False
        cvss_override = build_vector(base_vector_for("exposure.certificate_type"), C="H", I="H")
        business_override = None
    elif self_signed and is_internal is True and not hygiene_problem:
        # El caso intermedio que pediste: autofirmado en un endpoint interno, por lo demás sano.
        verdict = _V_MANAGEABLE
        headline = ("Certificado autofirmado en un endpoint INTERNO, por lo demás sano: riesgo POSIBLE pero "
                    "MANEJABLE -- el MITM requiere posición dentro de esa red controlada. Formalizalo con una "
                    "CA interna (--ca-bundle) o pinning del fingerprint; no lo dejes como confianza implícita.")
        passed = False
        # impacto acotado por el alcance interno -> Medium, no High.
        cvss_override = build_vector(base_vector_for("exposure.certificate_type"), C="L", I="L", UI="R")
        business_override = {"financial": "low", "reputational": "low", "compliance": "low", "privacy": "low"}
    else:
        # Autofirmado público / cadena desconocida / autofirmado interno pero además defectuoso.
        verdict = _V_RISK
        if self_signed:
            headline = "Certificado autofirmado expuesto (público o con defectos): RIESGO real de man-in-the-middle."
        else:
            headline = "Certificado de cadena desconocida (podría ser ya el de un atacante): RIESGO real de man-in-the-middle."
        passed = False
        cvss_override = build_vector(base_vector_for("exposure.certificate_type"), C="H", I="H")
        business_override = None

    return {
        "verdict": verdict,
        "headline": headline,
        "factors": factors,
        "passed": passed,
        "cvss_override": cvss_override,
        "business_override": business_override,
    }
