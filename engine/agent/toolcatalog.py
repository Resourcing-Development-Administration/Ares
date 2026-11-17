"""
Catálogo de herramientas del agente con capacidad de override desde BD.
Port de ARTEX agent/toolcatalog.go.

Las tools hard-codeadas son el fallback; la BD puede añadir/modificar/desactivar.
"""
from __future__ import annotations
from dataclasses import dataclass, field
from typing import Any, Callable, Awaitable

@dataclass
class ToolDefinition:
    """Definición de una herramienta del agente."""
    name: str
    description: str
    parameters: dict[str, Any]       # JSON Schema de parámetros
    handler: Callable | None = None  # función Python que implementa la tool
    enabled: bool = True
    source: str = "builtin"          # "builtin" | "db" | "mcp"
    tags: list[str] = field(default_factory=list)

class ToolCatalog:
    """Catálogo de herramientas con prioridad: db_override > builtin."""

    def __init__(self):
        self._builtin: dict[str, ToolDefinition] = {}
        self._overrides: dict[str, ToolDefinition] = {}  # de BD, mayor prioridad

    def register(self, tool: ToolDefinition) -> None:
        """Registra una tool built-in."""
        self._builtin[tool.name] = tool

    def register_many(self, tools: list[ToolDefinition]) -> None:
        for t in tools: self.register(t)

    def apply_db_override(self, name: str, override: ToolDefinition) -> None:
        """Aplica un override desde BD."""
        self._overrides[name] = override

    def clear_overrides(self) -> None:
        self._overrides.clear()

    def get(self, name: str) -> ToolDefinition | None:
        """Retorna la tool, con override de BD si existe."""
        return self._overrides.get(name) or self._builtin.get(name)

    def all_enabled(self) -> list[ToolDefinition]:
        """Retorna todas las tools enabled, con overrides aplicados."""
        merged = {**self._builtin, **self._overrides}
        return [t for t in merged.values() if t.enabled]

    def to_anthropic_tools(self) -> list[dict]:
        """Convierte el catálogo a formato de tools para la API de Anthropic."""
        result = []
        for tool in self.all_enabled():
            result.append({
                "name": tool.name,
                "description": tool.description,
                "input_schema": {"type": "object", **tool.parameters},
            })
        return result

    def to_openai_tools(self) -> list[dict]:
        """Convierte el catálogo a formato de tools para OpenAI-compatible APIs."""
        result = []
        for tool in self.all_enabled():
            result.append({
                "type": "function",
                "function": {
                    "name": tool.name,
                    "description": tool.description,
                    "parameters": {"type": "object", **tool.parameters},
                }
            })
        return result

# Catálogo global singleton
_DEFAULT_CATALOG = ToolCatalog()

def get_default_catalog() -> ToolCatalog:
    return _DEFAULT_CATALOG
