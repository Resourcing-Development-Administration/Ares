"""
Grabador de llamadas LLM para observabilidad, debugging y replay.
Registra cada llamada con request/response, tokens y atribución a tarea/sesión.

Port de ARTEX llmrec/llmrec.go + capture.go.
"""
from __future__ import annotations
import asyncio
import json
import time
import hashlib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Awaitable

@dataclass
class UsageMetrics:
    prompt_tokens: int = 0
    completion_tokens: int = 0
    total_tokens: int = 0
    latency_ms: float = 0.0
    model: str = ""
    provider: str = ""

@dataclass
class LLMRecord:
    """Registro de una sola llamada LLM."""
    record_id: str
    task_id: str
    session_id: str
    worker_role: str        # "planner" | "worker" | "judge" | "chat" | "retest"
    messages: list[dict]    # input messages (posiblemente truncados)
    response: str           # texto de respuesta (posiblemente truncado)
    system: str = ""        # system prompt (truncado)
    usage: UsageMetrics = field(default_factory=UsageMetrics)
    ts: float = field(default_factory=time.time)
    error: str = ""

    def to_dict(self) -> dict:
        return {
            "id": self.record_id, "task_id": self.task_id,
            "session_id": self.session_id, "role": self.worker_role,
            "ts": self.ts, "model": self.usage.model,
            "tokens": self.usage.total_tokens, "latency_ms": self.usage.latency_ms,
            "error": self.error,
            "messages_count": len(self.messages),
        }

class LLMRecorder:
    """Graba llamadas LLM en un archivo JSONL local.

    Diseñado para wrappear LLMPool sin cambiar su interfaz.
    """

    MAX_CONTENT_LEN = 10_000  # chars máx por campo para evitar archivos enormes

    def __init__(self, output_dir: str | Path, task_id: str = "", session_id: str = ""):
        self._dir = Path(output_dir)
        self._dir.mkdir(parents=True, exist_ok=True)
        self._task_id = task_id
        self._session_id = session_id
        self._file = self._dir / f"llm_records_{task_id or 'default'}.jsonl"
        self._lock = asyncio.Lock()
        self._in_memory: list[LLMRecord] = []
        self._total_tokens = 0

    async def record(
        self,
        messages: list[dict],
        response: str,
        system: str = "",
        worker_role: str = "worker",
        usage: UsageMetrics | None = None,
        error: str = "",
    ) -> LLMRecord:
        """Registra una llamada LLM."""
        # Generar ID único basado en contenido
        content = json.dumps(messages[-1] if messages else {}) + response[:100]
        record_id = hashlib.sha256(f"{time.time_ns()}:{content}".encode()).hexdigest()[:16]

        # Truncar contenido largo
        def cap(s: str, n: int = self.MAX_CONTENT_LEN) -> str:
            return s[:n] + "...[truncated]" if len(s) > n else s

        rec = LLMRecord(
            record_id=record_id,
            task_id=self._task_id,
            session_id=self._session_id,
            worker_role=worker_role,
            messages=[{"role": m.get("role", "user"), "content": cap(str(m.get("content", "")))} for m in messages[-5:]],
            response=cap(response),
            system=cap(system, 2000),
            usage=usage or UsageMetrics(),
            error=error,
        )

        self._in_memory.append(rec)
        self._total_tokens += rec.usage.total_tokens

        # Escribir a JSONL
        async with self._lock:
            with self._file.open("a") as f:
                f.write(json.dumps(rec.to_dict()) + "\n")

        return rec

    def recent(self, limit: int = 20) -> list[LLMRecord]:
        return self._in_memory[-limit:]

    @property
    def total_tokens(self) -> int:
        return self._total_tokens

    async def read_records(self, limit: int = 100) -> list[dict]:
        """Lee los últimos N registros del archivo JSONL."""
        if not self._file.exists():
            return []
        lines = self._file.read_text().splitlines()
        result = []
        for line in lines[-limit:]:
            try:
                result.append(json.loads(line))
            except Exception:
                pass
        return result
