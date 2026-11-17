"""
Servicio de preguntas laterales: el operador humano puede hacer preguntas
al agente en curso usando un snapshot del contexto actual, sin interrumpir
el loop planner/worker.

Port de ARTEX sidequestion/service.go + capture.go + context.go.

Dirección: HUMANO → AGENTE (el operador pregunta, el agente responde)
El agente no se detiene; la pregunta se procesa en un contexto snapshot.
"""
from __future__ import annotations
import asyncio
import time
import uuid
from dataclasses import dataclass, field
from typing import TYPE_CHECKING
if TYPE_CHECKING:
    from engine.agent.llmpool import LLMPool
    from engine.core.models import ScanReport

@dataclass
class SideQuestion:
    id: str = field(default_factory=lambda: str(uuid.uuid4())[:8])
    question: str = ""
    asked_at: float = field(default_factory=time.time)
    context_snapshot: str = ""  # snapshot del estado del scan al momento de la pregunta
    answer: str = ""
    answered_at: float = 0.0
    is_pending: bool = True

# Una pregunta respondida sirve como contenedor de respuesta — alias idiomático
# del patrón Go donde SideQuestionAnswer era un struct separado.
SideQuestionAnswer = SideQuestion

class ContextBudget:
    """Presupuesto de contexto para side questions (evita prompts enormes)."""
    MAX_SNAPSHOT_CHARS = 4_000
    MAX_FINDINGS_IN_SNAPSHOT = 5

    @staticmethod
    def build_snapshot(report: "ScanReport") -> str:
        """Construye un snapshot conciso del estado del scan para el contexto de la pregunta."""
        parts = [f"Target: {report.target}"]
        if hasattr(report, 'findings') and report.findings:
            top = report.findings[:ContextBudget.MAX_FINDINGS_IN_SNAPSHOT]
            parts.append(f"Findings encontrados ({len(report.findings)} total):")
            for f in top:
                parts.append(f"  - [{getattr(f,'severity','?').upper()}] {getattr(f,'title','?')}")
            if len(report.findings) > ContextBudget.MAX_FINDINGS_IN_SNAPSHOT:
                parts.append(f"  ... y {len(report.findings) - ContextBudget.MAX_FINDINGS_IN_SNAPSHOT} más")

        snapshot = "\n".join(parts)
        if len(snapshot) > ContextBudget.MAX_SNAPSHOT_CHARS:
            snapshot = snapshot[:ContextBudget.MAX_SNAPSHOT_CHARS] + "\n...[snapshot truncado]"
        return snapshot

class SideQuestionService:
    """Permite al operador hacer preguntas al agente en curso.

    Las preguntas se procesan con un snapshot del contexto actual,
    usando una llamada LLM independiente que no afecta al loop principal.
    """

    _BUSY_TIMEOUT_S = 10  # máx tiempo de espera si el servicio está ocupado

    def __init__(self, pool: "LLMPool"):
        self._pool = pool
        self._questions: dict[str, SideQuestion] = {}
        self._sem = asyncio.Semaphore(1)  # solo una pregunta a la vez
        self._report_ref: "ScanReport | None" = None

    def attach_report(self, report: "ScanReport") -> None:
        self._report_ref = report

    async def ask(self, question: str, timeout_s: float = 30.0) -> SideQuestion:
        """El operador hace una pregunta. Retorna la pregunta con su respuesta."""
        # Construir snapshot del contexto actual
        snapshot = ""
        if self._report_ref:
            snapshot = ContextBudget.build_snapshot(self._report_ref)

        sq = SideQuestion(question=question, context_snapshot=snapshot)
        self._questions[sq.id] = sq

        try:
            async with asyncio.timeout(timeout_s):
                async with self._sem:
                    sq.answer = await self._answer(sq)
                    sq.answered_at = time.time()
                    sq.is_pending = False
        except asyncio.TimeoutError:
            sq.answer = "[Timeout: el agente no pudo responder a tiempo]"
            sq.is_pending = False

        return sq

    async def _answer(self, sq: SideQuestion) -> str:
        system = (
            "Eres el agente Ares respondiendo una pregunta lateral del operador. "
            "Tienes acceso al estado actual del scan. Responde de forma concisa y directa. "
            "Esta es una pregunta informacional — no cambies el plan del scan."
        )
        user_msg = f"Estado actual del scan:\n{sq.context_snapshot}\n\nPregunta del operador: {sq.question}"
        try:
            return await self._pool.chat(
                messages=[{"role": "user", "content": user_msg}],
                system=system,
                max_tokens=500,
            )
        except Exception as e:
            return f"[Error al procesar pregunta: {e}]"

    def get_question(self, question_id: str) -> SideQuestion | None:
        return self._questions.get(question_id)

    def all_questions(self) -> list[SideQuestion]:
        return sorted(self._questions.values(), key=lambda q: q.asked_at, reverse=True)
