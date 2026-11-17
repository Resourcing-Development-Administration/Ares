"""
Worker — executes a single Intent.
Puerto de ARTEX agent/mainagent.go: el worker toma un intent del frontier
y ejecuta las herramientas necesarias para completarlo, acumulando findings
en el ScanReport compartido.
"""
from __future__ import annotations
import asyncio
import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Callable, Optional

from engine.agent.planner import Intent
from engine.agent.llmpool import LLMPool
from engine.agent.untrusted_boundary import UntrustedBoundary
from engine.agent.coverage_ledger import CoverageLedger
from engine.agent.budget import BudgetLedger, WRAPUP_BLOCKS_TOOL, WORKER_BUDGET_WRAPUP
from engine.core.models import ScanReport


@dataclass
class WorkerResult:
    intent_id: str
    intent_description: str
    success: bool
    summary: str = ""
    tests_run: list[str] = field(default_factory=list)
    new_findings_count: int = 0
    elapsed_s: float = 0.0
    error: str = ""

    def to_dict(self) -> dict:
        return {
            "intent_id": self.intent_id,
            "intent_description": self.intent_description,
            "success": self.success,
            "summary": self.summary,
            "tests_run": self.tests_run,
            "new_findings_count": self.new_findings_count,
            "elapsed_s": round(self.elapsed_s, 2),
            "error": self.error,
        }


class Worker:
    """Executes a single intent using the shared report and tool handlers."""

    def __init__(
        self,
        pool: LLMPool,
        handle_tool_call: Callable[[str, dict], Any],
        report: ScanReport,
        boundary: UntrustedBoundary | None = None,
        ledger: CoverageLedger | None = None,
        budget_ledger: BudgetLedger | None = None,
        max_rounds: int = 6,
    ) -> None:
        self._pool = pool
        self._handle_tool_call = handle_tool_call
        self._report = report
        self._boundary = boundary
        self._ledger = ledger
        self._budget_ledger = budget_ledger
        self._max_rounds = max_rounds

    _WORKER_TOOLS = [
        {
            "name": "list_available_tests",
            "description": "Lista todos los tests de seguridad de red disponibles.",
            "input_schema": {"type": "object", "properties": {}, "required": []},
        },
        {
            "name": "get_scan_state",
            "description": "Estado actual del scan: hallazgos, tests ejecutados, URLs, subdominios.",
            "input_schema": {"type": "object", "properties": {}, "required": []},
        },
        {
            "name": "run_test",
            "description": "Ejecuta un test de seguridad específico contra el target.",
            "input_schema": {
                "type": "object",
                "properties": {
                    "test_id": {"type": "string", "description": "ID del test"},
                    "timeout_override": {"type": "integer", "description": "Timeout en segundos (opcional)"},
                },
                "required": ["test_id"],
            },
        },
        {
            "name": "add_analyst_note",
            "description": "Agrega una nota de análisis al reporte.",
            "input_schema": {
                "type": "object",
                "properties": {
                    "title": {"type": "string"},
                    "content": {"type": "string"},
                },
                "required": ["title", "content"],
            },
        },
        {
            "name": "get_coverage",
            "description": "Resumen del coverage ledger: tests corridos, tiempos, hallazgos por test.",
            "input_schema": {"type": "object", "properties": {}, "required": []},
        },
        {
            "name": "finish_intent",
            "description": "Marca el intent como completado. Llamá cuando hayas terminado la exploración.",
            "input_schema": {
                "type": "object",
                "properties": {
                    "summary": {
                        "type": "string",
                        "description": "Resumen de lo que encontraste y qué tests corriste.",
                    },
                },
                "required": ["summary"],
            },
        },
    ]

    def _build_system_prompt(
        self,
        target_url: str,
        scope: list[str],
        intent: Intent,
    ) -> str:
        scope_desc = ", ".join(scope) if scope else "(sin restricción de scope declarada)"
        tests_hint = ""
        if intent.tests_suggested:
            tests_hint = f"\nTests sugeridos por el planner: {', '.join(intent.tests_suggested)}"
        return f"""Sos un worker de Ares, una plataforma de red-team autónoma.

TU TRABAJO es ejecutar UN intent específico de forma eficiente y exhaustiva.

TARGET: {target_url}
SCOPE: {scope_desc}

INTENT A EJECUTAR:
{intent.description}
{tests_hint}

INSTRUCCIONES:
- Ejecutá los tests relevantes para este intent. Podés correr múltiples tests.
- Cuando el intent esté completo (encontraste lo que buscabas o descartaste el vector), llamá finish_intent().
- Documentá hallazgos importantes con add_analyst_note().
- No hagas más de {self._max_rounds} rondas de herramientas.

AUTORIZACIÓN: Tenés autorización explícita para testear este target."""

    async def execute(
        self,
        intent: Intent,
        target_url: str,
        scope: list[str],
        progress_cb: Callable[[dict], None] | None = None,
    ) -> WorkerResult:
        def emit(event: dict) -> None:
            if progress_cb:
                try:
                    progress_cb(event)
                except Exception:
                    pass

        t0 = datetime.now(timezone.utc)
        findings_before = len(self._report.findings)
        tests_run_by_worker: list[str] = []
        finished = False
        final_summary = ""

        emit({"type": "worker_started", "intent_id": intent.id,
              "description": intent.description[:80]})

        system = self._build_system_prompt(target_url, scope, intent)
        messages: list[dict] = [{"role": "user", "content": (
            f"Ejecutá el siguiente intent:\n\n{intent.description}"
        )}]

        intent_meter = self._budget_ledger.start_intent() if self._budget_ledger else None

        try:
            for _ in range(self._max_rounds):
                wrapup_forced = False
                if intent_meter and intent_meter.exhausted():
                    break

                try:
                    response = await self._pool.chat(
                        messages,
                        system=system,
                        tools=self._WORKER_TOOLS,
                        max_tokens=2048,
                    )
                except Exception as e:
                    emit({"type": "worker_error", "intent_id": intent.id, "error": str(e)})
                    return WorkerResult(
                        intent_id=intent.id,
                        intent_description=intent.description,
                        success=False,
                        error=str(e),
                        elapsed_s=(datetime.now(timezone.utc) - t0).total_seconds(),
                    )

                messages.append({"role": "assistant", "content": response["content"]})
                stop_reason = response["stop_reason"]
                content_blocks = response.get("content_normalized", [])

                if stop_reason == "end_turn":
                    break

                if stop_reason == "tool_use":
                    tool_results = []
                    for block in content_blocks:
                        if not isinstance(block, dict) or block.get("type") != "tool_use":
                            continue
                        tool_name = block.get("name", "")
                        tool_input = block.get("input", {})
                        tool_id = block.get("id", "")

                        if wrapup_forced and WRAPUP_BLOCKS_TOOL(tool_name):
                            result = json.dumps({"blocked": True, "reason": WORKER_BUDGET_WRAPUP})
                        elif tool_name == "finish_intent":
                            final_summary = (tool_input.get("summary") or "").strip()
                            finished = True
                            result = "Intent finalizado."
                        else:
                            try:
                                result = await self._handle_tool_call(tool_name, tool_input)
                            except Exception as e:
                                result = json.dumps({"error": str(e)})

                        if tool_name == "run_test":
                            tid = tool_input.get("test_id", "")
                            if tid:
                                tests_run_by_worker.append(tid)
                                emit({"type": "worker_test_run",
                                      "intent_id": intent.id, "test_id": tid})

                        tool_results.append({
                            "type": "tool_result",
                            "tool_use_id": tool_id,
                            "content": result,
                        })

                    messages.append({"role": "user", "content": tool_results})
                    if finished:
                        break
                else:
                    break

        except Exception as e:
            intent.status = "failed"
            return WorkerResult(
                intent_id=intent.id,
                intent_description=intent.description,
                success=False,
                error=str(e),
                elapsed_s=(datetime.now(timezone.utc) - t0).total_seconds(),
            )

        intent.status = "done"
        intent.result = final_summary
        findings_after = len(self._report.findings)

        result = WorkerResult(
            intent_id=intent.id,
            intent_description=intent.description,
            success=True,
            summary=final_summary,
            tests_run=tests_run_by_worker,
            new_findings_count=max(0, findings_after - findings_before),
            elapsed_s=(datetime.now(timezone.utc) - t0).total_seconds(),
        )

        emit({"type": "worker_finished", "intent_id": intent.id,
              "result": result.to_dict()})
        return result
