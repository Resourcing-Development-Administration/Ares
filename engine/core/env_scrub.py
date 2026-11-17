"""
Limpieza de variables de entorno sensibles post-arranque.
Borra secretos, contraseñas y API keys de os.environ para reducir superficie de ataque
en caso de RCE o lectura de /proc/self/environ. Nunca loguea valores, solo nombres.
"""
from __future__ import annotations

import logging
import os
import re

logger = logging.getLogger(__name__)

# Patrones de nombres de env vars que deben borrarse post-arranque.
# Usar re.fullmatch para evitar falsos positivos parciales.
SCRUB_PATTERNS: list[str] = [
    r".*DSN.*",
    r".*DATABASE_URL.*",
    r"ANTHROPIC_API_KEY",
    r"OPENAI_API_KEY",
    r".*_SECRET.*",
    r".*PASSWORD.*",
    r"DEEPSEEK_API_KEY",
    r"NVIDIA_API_KEY",
    r"MISTRAL_API_KEY",
    r"GROQ_API_KEY",
    r"TOGETHER_API_KEY",
    r"AZURE_OPENAI_KEY",
    r"OPENROUTER_API_KEY",
    r"GEMINI_API_KEY",
    r"XAI_API_KEY",
    r"CUSTOM_LLM_KEY",
]

# Patrones de nombres de env vars que deben CONSERVARSE aunque coincidan con scrub.
KEEP_PATTERNS: list[str] = [
    r"ARES_TOKEN",
    r"ARES_NOTIFY_.*",
    r"ARES_.*",
    r"PYTHONPATH",
    r"PATH",
    r"HOME",
    r"USER",
    r"SHELL",
    r"LANG",
    r"LC_.*",
    r"TERM",
    r"LOGNAME",
    r"PWD",
    r"TMPDIR",
    r"TMP",
    r"TEMP",
    r"XDG_.*",
]

_scrub_re = [re.compile(p, re.IGNORECASE) for p in SCRUB_PATTERNS]
_keep_re  = [re.compile(p, re.IGNORECASE) for p in KEEP_PATTERNS]


def _should_scrub(key: str) -> bool:
    # Si coincide con algún keep, conservar
    if any(r.fullmatch(key) for r in _keep_re):
        return False
    # Si coincide con algún scrub, borrar
    return any(r.fullmatch(key) for r in _scrub_re)


def scrub_env() -> dict[str, str]:
    """Elimina de os.environ las keys sensibles. Retorna {key: 'SCRUBBED'} para logging."""
    scrubbed: dict[str, str] = {}
    for key in list(os.environ.keys()):
        if _should_scrub(key):
            del os.environ[key]
            scrubbed[key] = "SCRUBBED"
    if scrubbed:
        logger.info("scrub_env: eliminadas %d vars sensibles: %s",
                    len(scrubbed), ", ".join(sorted(scrubbed)))
    return scrubbed
