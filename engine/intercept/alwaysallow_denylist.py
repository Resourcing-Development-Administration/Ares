"""
Lista code-owned (no configurable) de binarios peligrosos que nunca deben
ejecutarse sin flags restrictivos explícitos, incluso si hay una allow-rule.

Puerto de ARTEX's intercept/alwaysallow_denylist.go.
"""
from __future__ import annotations

import os


# Shells e intérpretes — pueden ejecutar código arbitrario
SHELL_BINARIES: frozenset[str] = frozenset({
    "sh", "bash", "zsh", "fish", "dash", "csh", "tcsh", "ksh", "ash",
    "python", "python3", "python2", "ruby", "perl", "node", "nodejs",
    "php", "lua", "tclsh", "awk", "sed", "xargs",
})

# Binarios de escalada de privilegios
PRIV_ESCALATION: frozenset[str] = frozenset({
    "sudo", "su", "doas", "pkexec", "newgrp", "sg", "runuser",
})

# Binarios de acceso remoto / movimiento lateral
REMOTE_ACCESS: frozenset[str] = frozenset({
    "ssh", "scp", "sftp", "rsync", "nc", "ncat", "netcat", "socat", "telnet",
    "rsh", "rcp", "rlogin",
})

# Binarios de sistema sensibles
SYSTEM_SENSITIVE: frozenset[str] = frozenset({
    "mount", "umount", "fdisk", "mkfs", "dd", "chmod", "chown", "chroot",
    "iptables", "nftables", "ip", "route", "ifconfig",
    "crontab", "at", "systemctl", "service", "init",
    "useradd", "userdel", "usermod", "passwd", "groupadd",
})

# TODOS los binarios que requieren flags explícitos en allow-rules
ALWAYS_DENYLIST: frozenset[str] = (
    SHELL_BINARIES | PRIV_ESCALATION | REMOTE_ACCESS | SYSTEM_SENSITIVE
)


def requires_flags_restriction(binary_name: str) -> bool:
    """Retorna True si este binario requiere flags restrictivos en cualquier allow-rule.

    Un allow-rule de tipo "allow sh" sin flags es siempre rechazada.
    Debe especificarse: "allow sh -c 'comando-específico'" o similar.
    """
    base = os.path.basename(binary_name).lower()
    return base in ALWAYS_DENYLIST


def validate_allow_rule(
    program: str,
    allowed_args: list[str] | None,
) -> tuple[bool, str]:
    """Valida que un allow-rule sea seguro.

    Retorna (valid: bool, reason: str).
    """
    if requires_flags_restriction(program):
        if not allowed_args:
            return (
                False,
                f"'{program}' requiere flags restrictivos en la allow-rule "
                "(no se permite allow sin args)",
            )
        if any(a in ("*", "") for a in allowed_args):
            return (
                False,
                f"'{program}' no permite wildcard '*' en args de allow-rule",
            )
    return True, "ok"
