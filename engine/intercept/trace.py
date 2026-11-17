"""
Trazas de llamadas de herramienta con límites defensivos anti-DoS.
Puerto de ARTEX's intercept/trace.go.
"""
from __future__ import annotations

import hashlib
import time
from dataclasses import dataclass, field
from typing import Any


# Límites por defecto (en caracteres)
MAX_CONTEXT_LEN   = 8_000    # máx chars de contexto de sesión
MAX_INPUT_LEN     = 32_000   # máx chars de input a una tool
MAX_PROMPT_LEN    = 100_000  # máx chars de prompt total al LLM
MAX_OUTPUT_LEN    = 50_000   # máx chars de output de una tool
TRUNCATION_SUFFIX = "\n...[truncado por límite de seguridad]"


def cap_text(text: str, max_len: int, suffix: str = TRUNCATION_SUFFIX) -> str:
    """Trunca text a max_len chars. NUNCA falla silenciosamente: añade suffix si trunca."""
    if len(text) <= max_len:
        return text
    return text[:max_len] + suffix


@dataclass
class CallTrace:
    """Traza completa de una llamada de herramienta."""

    session_id: str
    call_id: str = field(
        default_factory=lambda: hashlib.sha256(
            str(time.time_ns()).encode()
        ).hexdigest()[:16]
    )
    tool_name: str = ""
    args_capped: dict[str, str] = field(default_factory=dict)
    input_hash: str = ""        # sha256 del input original (para replay)
    output_capped: str = ""
    started_at: float = field(default_factory=time.time)
    finished_at: float = 0.0
    decision: str = ""          # guard decision
    error: str = ""

    def finish(self, output: str, error: str = "") -> None:
        self.finished_at = time.time()
        self.output_capped = cap_text(output, MAX_OUTPUT_LEN)
        self.error = cap_text(error, 500)

    @property
    def duration_ms(self) -> float:
        return (self.finished_at - self.started_at) * 1000 if self.finished_at else 0.0


class TraceContext:
    """Contexto de trazabilidad para una sesión completa."""

    def __init__(self, session_id: str) -> None:
        self.session_id = session_id
        self._traces: list[CallTrace] = []

    def new_call(self, tool_name: str, args: dict) -> CallTrace:
        """Inicia una nueva traza de llamada."""
        capped: dict[str, str] = {}
        raw_parts: list[str] = []
        for k, v in args.items():
            vs = str(v)
            capped[k] = cap_text(vs, 2_000)
            raw_parts.append(f"{k}={vs}")

        raw = ";".join(raw_parts)
        h = hashlib.sha256(raw.encode()).hexdigest()[:16]

        trace = CallTrace(
            session_id=self.session_id,
            tool_name=tool_name,
            args_capped=capped,
            input_hash=h,
        )
        self._traces.append(trace)
        return trace

    def traces(self, limit: int = 100) -> list[CallTrace]:
        return self._traces[-limit:]

    def to_summary(self) -> dict[str, Any]:
        return {
            "session_id": self.session_id,
            "total_calls": len(self._traces),
            "tools_used": list({t.tool_name for t in self._traces}),
            "decisions": {
                d: sum(1 for t in self._traces if t.decision == d)
                for d in ("approved", "denied", "pending_human")
            },
        }
