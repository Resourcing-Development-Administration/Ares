"""
Planner — decides WHAT to explore next.
Puerto de ARTEX agent/planner.go: el planner es el único generador de intents.
No ejecuta herramientas directamente; emite intents al frontier para que los workers los ejecuten.
"""
from __future__ import annotations
import asyncio
import heapq
import json
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Callable, Optional

from engine.agent.llmpool import LLMPool

# ARTEX-port: planner + intent frontier


@dataclass
class Intent:
    description: str
    priority: int = 1           # 1–5; mayor → antes
    id: str = field(default_factory=lambda: uuid.uuid4().hex[:8])
    status: str = "pending"     # pending/running/done/failed/cancelled
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    result: str = ""
    tests_suggested: list[str] = field(default_factory=list)
    claim_token: str = ""

    def to_dict(self) -> dict:
        return {
            "id": self.id, "description": self.description,
            "priority": self.priority, "status": self.status,
            "created_at": self.created_at, "result": self.result,
            "tests_suggested": self.tests_suggested,
        }


class IntentFrontier:
    """Min-heap priority queue (negated priority → highest first)."""

    def __init__(self) -> None:
        self._heap: list[tuple[int, int, Intent]] = []  # (-prio, seq, intent)
        self._seq = 0
        self._lock = asyncio.Lock()

    async def add(self, intent: Intent) -> None:
        async with self._lock:
            heapq.heappush(self._heap, (-intent.priority, self._seq, intent))
            self._seq += 1

    async def next(self) -> Optional[Intent]:
        async with self._lock:
            while self._heap:
                _, _, intent = heapq.heappop(self._heap)
                if intent.status == "pending":
                    intent.status = "running"
                    return intent
            return None

    def cancel_all(self) -> None:
        for _, _, intent in self._heap:
            if intent.status == "pending":
                intent.status = "cancelled"
        self._heap.clear()

    def as_list(self) -> list[Intent]:
        return [i for _, _, i in self._heap]

    def pending_count(self) -> int:
        return sum(1 for _, _, i in self._heap if i.status == "pending")


_PLANNER_TOOLS = [
    {
        "name": "emit_intent",
        "description": (
            "Emite un nuevo intent de exploración al frontier. "
            "El intent será ejecutado por un worker especializado."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "description": {
                    "type": "string",
                    "description": "Qué explorar en detalle (ej: 'Enumerar subdominios y verificar cuáles tienen panel admin expuesto')",
                },
                "priority": {
                    "type": "integer",
                    "description": "Prioridad 1-5 (5=crítica, 1=baja). Default 3.",
                    "minimum": 1, "maximum": 5,
                },
                "suggested_tests": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "IDs de tests sugeridos (ej: ['net.subfinder', 'net.nuclei_scan']). Puede ser vacío.",
                },
            },
            "required": ["description"],
        },
    },
    {
        "name": "prove_goal_met",
        "description": "Declara que el objetivo del operador fue cumplido con evidencia suficiente.",
        "input_schema": {
            "type": "object",
            "properties": {
                "evidence": {
                    "type": "string",
                    "description": "Resumen de la evidencia que demuestra que el objetivo fue cumplido.",
                },
            },
            "required": ["evidence"],
        },
    },
    {
        "name": "finish_planning",
        "description": "Termina esta ronda del planner. Llamá cuando no tenés más intents útiles para emitir.",
        "input_schema": {
            "type": "object",
            "properties": {
                "reason": {
                    "type": "string",
                    "description": "Por qué terminaste: cobertura suficiente, objetivo cumplido, límite de rondas, etc.",
                },
            },
            "required": [],
        },
    },
]


class Planner:
    """LLM-driven planner: reads state, emits intents. Never executes tools directly."""

    def __init__(self, pool: LLMPool, max_intents: int = 20) -> None:
        self._pool = pool
        self._max_intents = max_intents
        self._goal_met = False
        self._goal_evidence = ""

    @property
    def goal_met(self) -> bool:
        return self._goal_met

    @property
    def goal_evidence(self) -> str:
        return self._goal_evidence

    def _build_system_prompt(self, target_url: str, scope: list[str], goal: str) -> str:
        scope_desc = ", ".join(scope) if scope else "(sin restricción de scope declarada)"
        return f"""Sos el planner de Ares, una plataforma de red-team autónoma.

TU ÚNICO TRABAJO es analizar el estado actual del scan y decidir QUÉ explorar a continuación.
No ejecutás herramientas directamente. Emitís intents que workers especializados van a ejecutar.

TARGET: {target_url}
SCOPE: {scope_desc}
OBJETIVO DEL OPERADOR: {goal or "Encontrar y documentar vulnerabilidades de seguridad"}

REGLAS:
- Emitís 0 a N intents por ronda. Cada intent es una dirección de exploración específica.
- Priorizá por impacto potencial: vulnerabilidades críticas primero, enumeración básica después.
- No repitas intents ya ejecutados (te muestro el historial).
- Cuando el objetivo esté cumplido o no haya más vectores útiles, llamá finish_planning().
- Nunca emitas más de {self._max_intents} intents en total a lo largo del scan.

HERRAMIENTAS:
- emit_intent: agregar un intent nuevo al frontier
- prove_goal_met: declarar que el objetivo fue cumplido
- finish_planning: terminar esta ronda

Los workers que ejecuten tus intents pueden usar: list_available_tests, run_test, get_scan_state,
add_analyst_note, get_coverage. Vos no podés usar esas herramientas directamente."""

    def _build_user_message(
        self,
        current_findings: list[dict],
        coverage_summary: dict,
        facts_context: str,
        previous_intents: list[dict],
        budget_line: str,
        force_wrapup: bool,
    ) -> str:
        parts = []

        # Operator context
        parts.append("[Operator context — definido por el operador, no derivado del target]:")
        parts.append(f"Ronda de planning. Force wrapup: {force_wrapup}.")
        if budget_line:
            parts.append(budget_line)

        # Derived: findings
        findings_txt = json.dumps(current_findings[:20], ensure_ascii=False) if current_findings else "[]"
        parts.append(f"\n[Hallazgos actuales (datos derivados del scan)]:\n{findings_txt}")

        # Coverage
        cov_txt = json.dumps(coverage_summary, ensure_ascii=False) if coverage_summary else "{}"
        parts.append(f"\n[Coverage del scan]:\n{cov_txt}")

        # Facts
        if facts_context:
            parts.append(f"\n[Facts conocidos del target (datos derivados)]:\n{facts_context}")

        # Previous intents
        if previous_intents:
            prev_txt = json.dumps(previous_intents[-10:], ensure_ascii=False)
            parts.append(f"\n[Intents ya ejecutados]:\n{prev_txt}")

        if force_wrapup:
            parts.append(
                "\n[WRAPUP]: El presupuesto está agotado o se alcanzó el límite de rondas. "
                "Emití solo los intents críticos pendientes, luego llamá finish_planning()."
            )

        return "\n".join(parts)

    async def plan(
        self,
        target_url: str,
        scope: list[str],
        goal: str,
        current_findings: list[dict],
        coverage_summary: dict,
        facts_context: str,
        previous_intents: list[dict],
        budget_line: str = "",
        force_wrapup: bool = False,
        progress_cb: Callable[[dict], None] | None = None,
    ) -> list[Intent]:
        """One planning round → list of new intents to add to the frontier."""

        def emit(event: dict) -> None:
            if progress_cb:
                try:
                    progress_cb(event)
                except Exception:
                    pass

        system = self._build_system_prompt(target_url, scope, goal)
        user_msg = self._build_user_message(
            current_findings, coverage_summary, facts_context,
            previous_intents, budget_line, force_wrapup,
        )

        messages: list[dict] = [{"role": "user", "content": user_msg}]
        new_intents: list[Intent] = []
        done = False

        for _ in range(6):  # max planner turns per round
            try:
                response = await self._pool.chat(
                    messages,
                    system=system,
                    tools=_PLANNER_TOOLS,
                    max_tokens=2048,
                )
            except Exception as e:
                emit({"type": "planner_error", "error": str(e)})
                break

            messages.append({"role": "assistant", "content": response["content"]})
            tool_results = []

            for block in response.get("content_normalized", []):
                if not isinstance(block, dict) or block.get("type") != "tool_use":
                    continue
                tool_name = block.get("name", "")
                tool_input = block.get("input", {})
                tool_id = block.get("id", "")

                if tool_name == "emit_intent":
                    desc = (tool_input.get("description") or "").strip()
                    if desc:
                        intent = Intent(
                            description=desc,
                            priority=min(max(int(tool_input.get("priority") or 3), 1), 5),
                            tests_suggested=tool_input.get("suggested_tests") or [],
                        )
                        new_intents.append(intent)
                        emit({"type": "planner_intent_emitted", "intent": intent.to_dict()})
                    result_text = f"Intent '{desc[:60]}' emitido con prioridad {intent.priority}."

                elif tool_name == "prove_goal_met":
                    evidence = (tool_input.get("evidence") or "").strip()
                    self._goal_met = True
                    self._goal_evidence = evidence
                    emit({"type": "planner_goal_met", "evidence": evidence})
                    result_text = "Objetivo marcado como cumplido."
                    done = True

                elif tool_name == "finish_planning":
                    reason = tool_input.get("reason", "")
                    emit({"type": "planner_finished", "reason": reason})
                    result_text = "Planning finalizado."
                    done = True

                else:
                    result_text = f"Tool '{tool_name}' no disponible para el planner."

                tool_results.append({
                    "type": "tool_result",
                    "tool_use_id": tool_id,
                    "content": result_text,
                })

            if tool_results:
                messages.append({"role": "user", "content": tool_results})

            if response.get("stop_reason") == "end_turn" or done:
                break

        return new_intents
