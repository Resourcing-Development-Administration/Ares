"""
Perfil de ruido "low-and-slow" inyectado en prompts para modular
agresividad/ritmo del agente según el nivel configurado.

Port de ARTEX agent/noise_profile.go.
"""
from __future__ import annotations
from enum import Enum

class NoiseLevel(str, Enum):
    SILENT   = "silent"    # pasivo, sin tráfico activo
    QUIET    = "quiet"     # muy lento, una petición a la vez
    BALANCED = "balanced"  # moderado (default)
    ACTIVE   = "active"    # normal, mayor cobertura
    LOUD     = "loud"      # agresivo, máxima cobertura

_NOISE_PROMPTS: dict[NoiseLevel, str] = {
    NoiseLevel.SILENT: (
        "PERFIL DE RUIDO: SILENCIOSO. No hagas peticiones activas al target. "
        "Solo análisis pasivo con datos ya disponibles. No ejecutes herramientas de scanning."
    ),
    NoiseLevel.QUIET: (
        "PERFIL DE RUIDO: BAJO. Ejecuta una sola herramienta a la vez. "
        "Espera a que complete antes de lanzar la siguiente. "
        "Usa los parámetros menos agresivos disponibles (rate-limit bajo, threads=1)."
    ),
    NoiseLevel.BALANCED: (
        "PERFIL DE RUIDO: BALANCEADO. Cobertura moderada con ritmo razonable. "
        "No uses más de 3-5 threads. Prioriza herramientas de bajo impacto antes de las agresivas."
    ),
    NoiseLevel.ACTIVE: (
        "PERFIL DE RUIDO: ACTIVO. Cobertura amplia con ritmo normal. "
        "Puedes usar parámetros estándar. Cubre todas las categorías de vulnerabilidades."
    ),
    NoiseLevel.LOUD: (
        "PERFIL DE RUIDO: AGRESIVO. Cobertura máxima. "
        "Usa todos los parámetros disponibles para mayor detección. "
        "Solo en ambientes de lab o con autorización explícita para testing agresivo."
    ),
}

class NoiseProfile:
    def __init__(self, level: NoiseLevel):
        self.level = level

    @classmethod
    def for_level(cls, level: NoiseLevel | str) -> "NoiseProfile":
        if isinstance(level, str):
            level = NoiseLevel(level)
        return cls(level)

    @classmethod
    def from_env(cls) -> "NoiseProfile":
        import os
        level_str = os.environ.get("ARES_NOISE_PROFILE", "balanced").lower()
        try:
            return cls(NoiseLevel(level_str))
        except ValueError:
            return cls(NoiseLevel.BALANCED)

    def to_prompt_text(self) -> str:
        return _NOISE_PROMPTS.get(self.level, _NOISE_PROMPTS[NoiseLevel.BALANCED])

    @property
    def max_concurrent_tools(self) -> int:
        return {
            NoiseLevel.SILENT: 0,
            NoiseLevel.QUIET: 1,
            NoiseLevel.BALANCED: 3,
            NoiseLevel.ACTIVE: 5,
            NoiseLevel.LOUD: 10,
        }[self.level]

    @property
    def requests_per_second(self) -> float:
        return {
            NoiseLevel.SILENT: 0.0,
            NoiseLevel.QUIET: 0.5,
            NoiseLevel.BALANCED: 2.0,
            NoiseLevel.ACTIVE: 5.0,
            NoiseLevel.LOUD: 20.0,
        }[self.level]
