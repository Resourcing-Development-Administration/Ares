"""
Clasificación de un error de conexión inicial contra el target.

El orquestador deja correr el scan aunque la conexión inicial falle, porque
algunos tests analizan justamente ese escenario (ej. un server que exige auth
y rechaza la sesión sin credenciales). Pero NO todo rechazo es equivalente:

- Un **401/403** sin credenciales es la señal ESPERADA de un server bien
  asegurado -- lo evalúa `auth.unauthenticated_access` como algo positivo.
- Un **certificado TLS rechazado** (self-signed, CA desconocida, hostname que
  no matchea) significa que el cliente ni siquiera completó el handshake: NO se
  probó nada, y tratar eso como "limpio" o "auth exigida" sería un falso
  positivo peligroso. Se resuelve confiando en la CA correcta (`--ca-bundle`).
- Un **fallo de red** (DNS, conexión rechazada, timeout) también significa que
  no se probó nada.

Esta función separa esos casos para que (a) `auth.unauthenticated_access` no
confunda un TLS roto con "el server exige auth", y (b) el orquestador emita un
finding de "corrida INCOMPLETA" cuando la conexión falló por una razón que no
sea el 401 legítimo -- en vez de dejar que el scan termine en un falso
"100/100 ALLOW" sobre tests que nunca llegaron a correr.
"""
from __future__ import annotations

TLS = "tls"
AUTH = "auth"
NETWORK = "network"
OTHER = "other"

# Marcadores en el texto del error (lowercased). Orden de chequeo: TLS primero
# (es el más peligroso de confundir), luego auth, luego red, si no -> other.
_TLS_MARKERS = (
    "certificate", "cert verify", "certificate_verify", "cert_verify",
    "self-signed", "self signed", "unable to get local issuer",
    "sslcertverification", "ssl: ", "sslerror", "ssl error", "ssl handshake",
    "tlsv1", "wrong_version_number", "ca_md_too_weak", "certificate_unknown",
    "unknown ca", "hostname mismatch", "doesn't match", "cert is not yet valid",
    "certificate has expired", "certificate verify failed",
)
_AUTH_MARKERS = (
    "401", "403", "unauthorized", "forbidden", "www-authenticate",
    "authentication required", "not authenticated", "invalid token",
    "invalid_token", "access denied", "permission denied (auth",
)
_NETWORK_MARKERS = (
    "connection refused", "refused", "getaddrinfo", "name or service not known",
    "nodename nor servname", "temporary failure in name resolution",
    "timed out", "timeout", "network is unreachable", "no route to host",
    "connection reset", "connecterror", "connecttimeout",
    "all connection attempts failed", "failed to establish", "name resolution",
)


def classify_connection_error(err: str | None) -> str:
    """Devuelve 'tls' | 'auth' | 'network' | 'other' para un mensaje de error de
    conexión. Ante la duda cae en 'other' -- que el orquestador trata como corrida
    incompleta (fail-closed): preferimos marcar de más que ocultar un scan que no
    llegó a probar nada."""
    if not err:
        return OTHER
    low = err.lower()
    if any(m in low for m in _TLS_MARKERS):
        return TLS
    if any(m in low for m in _AUTH_MARKERS):
        return AUTH
    if any(m in low for m in _NETWORK_MARKERS):
        return NETWORK
    return OTHER


def is_expected_auth_rejection(err: str | None, auth_configured: bool) -> bool:
    """True solo para el caso legítimo y esperado: SIN credenciales configuradas,
    el server rechazó la sesión a nivel HTTP (401/403). Ese es el escenario que
    `auth.unauthenticated_access` reporta como señal positiva. Si se habían
    configurado credenciales (y aun así fue rechazado) o el fallo fue TLS/red,
    NO es un rechazo de auth esperado -- la corrida quedó incompleta."""
    return (not auth_configured) and classify_connection_error(err) == AUTH
