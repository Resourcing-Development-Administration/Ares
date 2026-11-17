"""
Sistema de tools MCP diferidas: se listan por nombre pero su schema
no se expone hasta que el agente las "desbloquea" (vía skill o petición explícita).

Port de ARTEX agent/deferred.go.
Relevante cuando Ares actúa como cliente MCP y quiere limitar el surface
de tools disponibles para el agente.
"""
from __future__ import annotations
from dataclasses import dataclass, field

@dataclass
class DeferredTool:
    """Tool cuyo schema está oculto hasta unlock."""
    name: str
    hint: str           # descripción de 1 línea para que el agente sepa si vale la pena desbloquear
    unlock_via: str     # cómo desbloquearla: "skill:<name>" | "explicit_request" | "auto"
    schema: dict | None = None      # schema completo, None hasta que se cargue
    unlocked: bool = False

class DeferredRegistry:
    """Registro de tools diferidas por sesión de agente."""

    def __init__(self):
        self._deferred: dict[str, DeferredTool] = {}
        self._unlocked: dict[str, dict] = {}  # name → schema completo

    def register(self, tool: DeferredTool) -> None:
        self._deferred[tool.name] = tool

    def unlock(self, name: str, schema: dict) -> bool:
        """Desbloquea una tool, haciendo su schema disponible."""
        if name not in self._deferred:
            return False
        self._deferred[name].schema = schema
        self._deferred[name].unlocked = True
        self._unlocked[name] = schema
        return True

    def get_hints_text(self) -> str:
        """Texto para incluir en el system prompt listando tools diferidas."""
        lines = ["HERRAMIENTAS DISPONIBLES BAJO PETICIÓN (requieren desbloqueo):"]
        for t in self._deferred.values():
            if not t.unlocked:
                lines.append(f"  - {t.name}: {t.hint} [unlock: {t.unlock_via}]")
        return "\n".join(lines) if len(lines) > 1 else ""

    def get_unlocked_schemas(self) -> dict[str, dict]:
        return dict(self._unlocked)

    def list_deferred_names(self) -> list[str]:
        return [t.name for t in self._deferred.values() if not t.unlocked]
