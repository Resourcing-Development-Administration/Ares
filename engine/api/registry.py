"""Registro propio de tests de API (separado del de MCP: reciben un ApiTarget, no un MCPTarget)."""
from __future__ import annotations
from engine.core.models import TestMeta, Category

_REG: dict[str, tuple[TestMeta, object]] = {}


def api_test(id: str, name: str, description: str, level: int = 1, default_enabled: bool = True,
             kind: str = "rest"):
    """kind: 'rest' | 'graphql' -- el runner solo corre los de GraphQL si hay endpoint GraphQL."""
    def deco(fn):
        if id in _REG:
            raise ValueError(f"api test duplicado: {id}")
        meta = TestMeta(id=id, name=name, category=Category.API, description=description,
                        default_enabled=default_enabled, requires_network=False, level=level)
        meta.kind = kind  # type: ignore[attr-defined]
        _REG[id] = (meta, fn)
        return fn
    return deco


def all_api_tests() -> dict:
    import engine.api.rest_tests, engine.api.graphql_tests  # noqa: F401  (autoregistro)
    return dict(_REG)
