"""
Tool RAG — inject only the subset of tools relevant to the current intent.

Port of ARTEX ARTEX_TOOL_RAG feature. When the bound tool list is large,
only the subset relevant to the current intent is injected.

Env vars:
  ARES_TOOL_RAG=1   enable (off by default)
"""
from __future__ import annotations

import os
import re
from typing import Any


ESSENTIAL_TOOLS = frozenset({"finish", "add_analyst_note", "ask_operator"})


class ToolRAG:
    """Selects relevant tools from a fixed list based on intent text."""

    def __init__(self, all_tools: list[dict[str, Any]]) -> None:
        self._tools = all_tools
        # pre-build token sets per tool for fast scoring
        self._tool_tokens: list[tuple[str, frozenset[str]]] = []
        for t in all_tools:
            name = t.get("name", "")
            desc = t.get("description", "")
            tokens = _tokenize(f"{name} {desc}")
            self._tool_tokens.append((name, tokens))

    def relevant_for(self, intent_text: str, max_tools: int = 12) -> list[dict[str, Any]]:
        if len(self._tools) <= max_tools:
            return self._tools

        query_tokens = _tokenize(intent_text)
        scored: list[tuple[int, str, dict]] = []
        for (name, tool_tokens), tool in zip(self._tool_tokens, self._tools):
            if name in ESSENTIAL_TOOLS:
                continue
            score = len(query_tokens & tool_tokens)
            scored.append((score, name, tool))

        scored.sort(key=lambda x: (-x[0], x[1]))

        # always include essentials
        result: list[dict] = []
        essential_added = set()
        for t in self._tools:
            if t.get("name") in ESSENTIAL_TOOLS:
                result.append(t)
                essential_added.add(t.get("name"))

        slots = max_tools - len(result)
        for _, _, tool in scored[:slots]:
            result.append(tool)

        return result

    @staticmethod
    def enabled_from_env() -> bool:
        return os.environ.get("ARES_TOOL_RAG", "").strip() in ("1", "true", "yes")


def _tokenize(text: str) -> frozenset[str]:
    return frozenset(w.lower() for w in re.split(r"\W+", text) if len(w) > 2)

# ARTEX-port: tool subset injection based on intent keyword overlap
