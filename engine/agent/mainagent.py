"""
Chat agent separado del planner/worker que permite al operador humano
interactuar con una sesión en curso: hacer preguntas, inyectar hints,
recibir actualizaciones de estado sin interrumpir el loop autónomo.

Port de ARTEX agent/mainagent.go.
"""
from __future__ import annotations
import asyncio
from dataclasses import dataclass, field
from typing import AsyncIterator, Callable, TYPE_CHECKING
if TYPE_CHECKING:
    from engine.agent.llmpool import LLMPool
    from engine.core.models import ScanReport

@dataclass
class ChatMessage:
    role: str  # "operator" | "agent"
    content: str
    is_hint: bool = False  # True si es un hint para el planner

class MainAgent:
    """Agent de chat que corre en paralelo al loop planner/worker.

    Permite al operador:
    - Hacer preguntas sobre el estado del scan en curso
    - Inyectar hints de alta prioridad al planner
    - Recibir actualizaciones periódicas

    NO interrumpe el loop autónomo. Se comunica con él via queues async.
    """

    def __init__(self, pool: "LLMPool", hint_queue: asyncio.Queue | None = None):
        self._pool = pool
        self._hint_queue = hint_queue or asyncio.Queue(maxsize=10)
        self._history: list[dict] = []
        self._report_ref: "ScanReport | None" = None
        self._system_prompt = (
            "Eres el agente de chat del sistema Ares. Tienes acceso al estado actual del scan "
            "en curso. El operador puede preguntarte sobre el progreso, findings encontrados, "
            "o pedirte que dirijas la atención del scanner a algo específico.\n"
            "Si el operador pide enfocarse en algo concreto, responde con un [HINT] al inicio "
            "para que el planner lo reciba como prioridad alta.\n"
            "Responde siempre en el idioma del operador. Sé conciso y directo."
        )

    def attach_report(self, report: "ScanReport") -> None:
        """Adjunta el report en curso para que el chat pueda referenciarlo."""
        self._report_ref = report

    async def chat(self, operator_message: str) -> str:
        """Procesa un mensaje del operador y retorna la respuesta del agente."""
        # Construir contexto del scan si hay report
        context = ""
        if self._report_ref:
            findings_summary = f"{len(self._report_ref.findings)} findings encontrados"
            context = f"\n[Estado actual del scan: target={self._report_ref.target}, {findings_summary}]"

        # Añadir mensaje del operador
        self._history.append({"role": "user", "content": operator_message + context})

        try:
            response = await self._pool.chat(
                messages=self._history,
                system=self._system_prompt,
                max_tokens=1000,
            )
        except Exception as e:
            response = f"[Error en chat agent: {e}]"

        self._history.append({"role": "assistant", "content": response})

        # Si la respuesta contiene [HINT], enviar al queue del planner
        if "[HINT]" in response and not self._hint_queue.full():
            hint = response.replace("[HINT]", "").strip()
            try:
                self._hint_queue.put_nowait(hint)
            except asyncio.QueueFull:
                pass

        return response

    async def get_hint(self) -> str | None:
        """Obtiene el próximo hint para el planner (non-blocking)."""
        try:
            return self._hint_queue.get_nowait()
        except asyncio.QueueEmpty:
            return None

    def clear_history(self) -> None:
        self._history.clear()
