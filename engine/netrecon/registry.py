"""
Registry de tests de red. Patrón idéntico al de engine/api/registry.py:
  - @net_test(id, level, name, category, description) decora funciones async
  - all_net_tests() devuelve la lista ordenada
  - list_net_meta() devuelve sólo los metadatos (para --list-tests)

Convención de IDs: "net.<nombre>" (ej: "net.httpx_probe")
"""
from __future__ import annotations
import functools
from typing import Callable, Any

from engine.core.models import TestMeta, Category


_NET_REGISTRY: dict[str, dict[str, Any]] = {}


def net_test(
    *,
    id: str,
    level: int,
    name: str,
    category: str = "network",
    description: str = "",
) -> Callable:
    """Decorator que registra una función como test de red."""
    def decorator(fn: Callable) -> Callable:
        _NET_REGISTRY[id] = {
            "id":          id,
            "level":       level,
            "name":        name,
            "category":    category,
            "description": description,
            "fn":          fn,
        }
        @functools.wraps(fn)
        async def wrapper(*args, **kwargs):
            return await fn(*args, **kwargs)
        return wrapper
    return decorator


def all_net_tests() -> list[dict[str, Any]]:
    """Lista de tests de red ordenados por nivel."""
    return sorted(_NET_REGISTRY.values(), key=lambda t: t["level"])


def list_net_meta() -> list[TestMeta]:
    """Metadatos de los tests de red, misma forma que list_meta() del registry MCP."""
    return [
        TestMeta(
            id=t["id"],
            level=t["level"],
            name=t["name"],
            category=Category.NETWORK,
            description=t["description"],
            requires_network=True,
        )
        for t in all_net_tests()
    ]


def get_net_test(id: str) -> dict[str, Any] | None:
    return _NET_REGISTRY.get(id)
