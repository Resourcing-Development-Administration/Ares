"""
Tabla de aridad de comandos y extracción de argv prefix.
Puerto de ARTEX's intercept/argv.go.
"""
from __future__ import annotations

import os
import shlex
from dataclasses import dataclass


# Número de tokens que forman el "prefijo" de un programa (programa + subcomando).
# Ej: "git commit" tiene aridad 2 → el prefijo son los primeros 2 tokens.
ARGV_ARITY: dict[str, int] = {
    "git": 2, "npm": 2, "yarn": 2, "pip": 2, "pip3": 2,
    "python": 1, "python3": 1, "node": 1, "ruby": 1, "perl": 1,
    "bash": 1, "sh": 1, "zsh": 1, "fish": 1, "dash": 1,
    "sudo": 2, "su": 1,
    "ssh": 1, "scp": 1, "rsync": 1, "curl": 1, "wget": 1,
    "nmap": 1, "sqlmap": 1, "ffuf": 1, "nuclei": 1, "httpx": 1,
    "nc": 1, "netcat": 1, "socat": 1,
    "docker": 2, "kubectl": 2, "helm": 2,
}


@dataclass
class ParsedArgv:
    program: str          # primer token
    prefix: list[str]     # programa + subcomando (según aridad)
    args: list[str]       # resto de argumentos
    raw: str              # comando original


def parse_argv(command: str) -> ParsedArgv | None:
    """Parsea un comando shell y extrae program + prefix + args.

    Retorna None si el comando no se puede parsear (shlex.SplitError).
    """
    try:
        tokens = shlex.split(command)
    except ValueError:
        return None

    if not tokens:
        return None

    program = tokens[0].lstrip("./")
    base = os.path.basename(program)
    arity = ARGV_ARITY.get(base, ARGV_ARITY.get(program, 1))

    prefix = tokens[:arity]
    args = tokens[arity:]
    return ParsedArgv(program=program, prefix=prefix, args=args, raw=command)
