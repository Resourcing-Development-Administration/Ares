"""
Registro central de tests. Cada módulo (recon/static/dynamic/adversarial)
define funciones async decoradas con @register_test y quedan disponibles
automáticamente para el orquestador y para el listado en CLI/UI.
"""
from __future__ import annotations
from typing import Callable, Awaitable
from .models import TestMeta, Category

TestFunc = Callable[..., Awaitable[list]]  # (target: MCPTarget, ctx: dict) -> list[Finding]

_REGISTRY: dict[str, tuple[TestMeta, TestFunc]] = {}


def register_test(
    id: str,
    name: str,
    category: Category,
    description: str,
    default_enabled: bool = True,
    requires_network: bool = False,
    level: int = 1,
):
    if level not in (1, 2, 3, 4):
        raise ValueError(f"{id}: level debe ser 1-4, recibido {level!r}")
    def decorator(func: TestFunc):
        meta = TestMeta(
            id=id,
            name=name,
            category=category,
            description=description,
            default_enabled=default_enabled,
            requires_network=requires_network,
            level=level,
        )
        if id in _REGISTRY:
            raise ValueError(f"test id duplicado: {id}")
        _REGISTRY[id] = (meta, func)
        return func
    return decorator


def all_tests() -> dict[str, tuple[TestMeta, TestFunc]]:
    return dict(_REGISTRY)


def get_test(test_id: str):
    return _REGISTRY.get(test_id)


def list_meta() -> list[TestMeta]:
    return [meta for meta, _ in _REGISTRY.values()]


def ids_at_or_below_level(max_level: int) -> list[str]:
    """IDs de todos los tests con level <= max_level -- usado por --max-level en la CLI
    y por el selector de nivel del webui para pre-armar la selección por defecto."""
    return [meta.id for meta, _ in _REGISTRY.values() if meta.level <= max_level]
