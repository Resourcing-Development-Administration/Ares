"""Provenance summary utilities. ARTEX-port."""
from __future__ import annotations
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .store import FactStore


def provenance_summary(store: "FactStore") -> dict:
    """Resumen de procedencia del FactStore: conteos por fuente y herramienta."""
    by_source: dict[str, int] = {}
    by_tool: dict[str, int] = {}
    by_predicate: dict[str, int] = {}

    for fact in store.all_facts():
        src = fact.source.value
        by_source[src] = by_source.get(src, 0) + 1
        if fact.tool:
            by_tool[fact.tool] = by_tool.get(fact.tool, 0) + 1
        by_predicate[fact.predicate] = by_predicate.get(fact.predicate, 0) + 1

    return {
        "total_facts": len(store),
        "by_source": by_source,
        "by_tool": by_tool,
        "by_predicate": by_predicate,
        "unique_subjects": len(store.all_subjects()),
    }
