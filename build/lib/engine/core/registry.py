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
):
    def decorator(func: TestFunc):
        meta = TestMeta(
            id=id,
            name=name,
            category=category,
            description=description,
            default_enabled=default_enabled,
            requires_network=requires_network,
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
