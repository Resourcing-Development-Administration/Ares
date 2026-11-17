"""
Orquestador LLM para scans de red autónomos.
Equivalente a la capa Planner+Worker de ARTEX pero con arquitectura integrada:
un solo agente Claude que decide qué tests correr y los ejecuta directamente,
acumulando findings en un ScanReport compartido.

Requiere: pip install anthropic  (extra 'live-agent' en pyproject.toml)
"""
from __future__ import annotations
import asyncio
import json
import uuid
from datetime import datetime, timezone
from typing import Callable, Any

import engine.netrecon.tests  # noqa: F401 — fuerza el registro de tests

from engine.core.models import Finding, ScanReport, Category
from engine.netrecon.registry import all_net_tests
from engine.netrecon.target import NetworkTarget
from engine.reporting.suppress import apply_noise_reduction
from engine.reporting.scoring import calculate_score
from engine.policy.engine import PolicyEngine
from engine.intercept.gate import InterceptGate
from engine.agent.untrusted_boundary import UntrustedBoundary
from engine.agent.coverage_ledger import CoverageLedger
from engine.agent.llmpool import LLMPool
from engine.agent.budget import (
    BudgetLedger, budgets_from_env, WRAPUP_BLOCKS_TOOL,
    TASK_BUDGET_WRAPUP, WORKER_BUDGET_WRAPUP,
)
from engine.agent.tool_rag import ToolRAG
from engine.egress.governor import Governor, profile_from_env
from engine.facts.store import FactStore
from engine import __version__ as ARES_VERSION

# ---------------------------------------------------------------------------
# Stagnation detection
# ---------------------------------------------------------------------------

STAGNATION_WINDOW = 3  # rounds sin progreso = estancamiento

# ---------------------------------------------------------------------------
# System prompt
# ---------------------------------------------------------------------------

def _build_system_prompt(
    target_url: str,
    scope: list[str],
    goal: str,
    max_rounds: int,
    boundary: UntrustedBoundary | None = None,
) -> str:
    scope_desc = ", ".join(scope) if scope else "(sin restricción de scope declarada)"
    goal_desc = goal or "Encontrar y documentar vulnerabilidades de seguridad en el target"
    base = f"""Sos un agente autónomo de reconocimiento de seguridad de red para la plataforma Ares red-team.

AUTORIZACIÓN: Tenés autorización explícita del operador para testear este target.
Target: {target_url}
Scope: {scope_desc}
Objetivo del operador: {goal_desc}

TU TRABAJO es descubrir vulnerabilidades de seguridad y misconfiguraciones de forma sistemática y eficiente.

HERRAMIENTAS DISPONIBLES:
- list_available_tests: Listar todos los tests con descripción y nivel de riesgo
- get_scan_state: Ver el estado actual (subdominios encontrados, URLs, hallazgos, tests ejecutados)
- run_test: Ejecutar un test específico (ej. test_id="net.subfinder") — puede tardar minutos
- add_analyst_note: Documentar tu análisis y razonamiento — aparece en el reporte final
- finish: Marcar el scan como completo

ESTRATEGIA RECOMENDADA:
1. Empezá con tests pasivos nivel 1: net.httpx_probe (baseline), net.subfinder (subdominios), net.bbot_osint (OSINT)
2. Revisá get_scan_state y analizá qué se encontró
3. Avanzá a nivel 2 según hallazgos: net.nuclei_scan (CVEs/templates), net.katana_crawl (crawl JS), net.ffuf_fuzz (paths ocultos)
4. Dalfox XSS (net.dalfox_xss) si katana encontró URLs con parámetros
5. Nivel 3 (net.sqlmap_sqli) solo si hay puntos de inyección Y el gate lo permite
6. Documentá hipótesis importantes con add_analyst_note antes de decisiones
7. Llamá finish cuando tenés buena cobertura o más tests tendrían rendimiento marginal
8. Podés usar ask_operator para hacer preguntas al operador humano si necesitás aclaraciones

RESTRICCIONES:
- Nunca testees hosts fuera del scope declarado
- Si el gate bloquea un test, aceptalo y probá alternativas
- Tenés máximo {max_rounds} rondas de llamadas — planificá eficientemente
- No repitas tests ya ejecutados (verificá con get_scan_state)
- Priorizá tests de mayor valor basándote en hallazgos previos
"""
    if boundary:
        base += boundary.system_instructions()
    return base


# ---------------------------------------------------------------------------
# Tool definitions para la API de Claude
# ---------------------------------------------------------------------------

_TOOL_DEFINITIONS = [
    {
        "name": "list_available_tests",
        "description": "Lista todos los tests de seguridad de red disponibles con sus IDs, niveles y descripciones.",
        "input_schema": {"type": "object", "properties": {}, "required": []},
    },
    {
        "name": "get_scan_state",
        "description": "Estado actual del scan: subdominios descubiertos, URLs crawleadas, hallazgos por severidad, tests ejecutados y pendientes.",
        "input_schema": {"type": "object", "properties": {}, "required": []},
    },
    {
        "name": "run_test",
        "description": "Ejecuta un test de seguridad específico contra el target. Puede tardar varios minutos.",
        "input_schema": {
            "type": "object",
            "properties": {
                "test_id": {
                    "type": "string",
                    "description": "ID del test (ej. 'net.subfinder', 'net.nuclei_scan')",
                },
                "timeout_override": {
                    "type": "integer",
                    "description": "Timeout en segundos para este test (opcional)",
                },
            },
            "required": ["test_id"],
        },
    },
    {
        "name": "add_analyst_note",
        "description": "Agrega una nota de análisis al reporte final. Usá para documentar razonamiento, hipótesis y observaciones.",
        "input_schema": {
            "type": "object",
            "properties": {
                "title": {
                    "type": "string",
                    "description": "Título conciso (ej. 'Subdominios expuestos con panel admin')",
                },
                "content": {
                    "type": "string",
                    "description": "Contenido detallado del análisis",
                },
            },
            "required": ["title", "content"],
        },
    },
    {
        "name": "finish",
        "description": "Marca el scan como completo. Llamá cuando tenés buena cobertura o más tests tendrían rendimiento marginal.",
        "input_schema": {
            "type": "object",
            "properties": {
                "security_posture": {
                    "type": "string",
                    "description": "Resumen del análisis: postura general, áreas de riesgo, recomendaciones principales",
                },
            },
            "required": ["security_posture"],
        },
    },
    {
        "name": "ask_operator",
        "description": "Hace una pregunta al operador humano y espera su respuesta antes de continuar. Usalo para aclaraciones sobre scope, autorización, o contexto que no podés inferir.",
        "input_schema": {
            "type": "object",
            "properties": {
                "question": {
                    "type": "string",
                    "description": "La pregunta al operador (ej: '¿Tenemos autorización para testear subdominios de terceros como cdn.example.com?')",
                },
                "urgency": {
                    "type": "string",
                    "enum": ["blocking", "informational"],
                    "description": "'blocking' = necesito la respuesta para continuar; 'informational' = puedo continuar pero la respuesta mejora el análisis",
                },
            },
            "required": ["question"],
        },
    },
    {
        "name": "get_coverage",
        "description": "Obtiene un resumen detallado del coverage ledger: qué tests corrieron, cuánto tiempo tomaron, hallazgos por test.",
        "input_schema": {"type": "object", "properties": {}, "required": []},
    },
]


# ---------------------------------------------------------------------------
# Función principal
# ---------------------------------------------------------------------------

async def run_agent_scan(
    *,
    target_url: str,
    scope: list[str] | None = None,
    goal: str | None = None,
    model: str | None = None,
    provider: str = "auto",
    pool: LLMPool | None = None,
    max_rounds: int = 8,
    nuclei_severity: list[str] | None = None,
    timeout_s: int = 180,
    rate_limit: int = 150,
    min_confidence: str = "heuristic",
    environment: str = "production",
    allow_level3: bool = False,
    allow_private: bool = False,
    denylist: list[str] | None = None,
    allowlist_path: str | None = None,
    enable_proxy: bool = False,
    proxy_port: int = 8788,
    budget_ledger: BudgetLedger | None = None,
    side_question_cb: Callable[[str, str], Any] | None = None,
    progress_cb: Callable[[dict], None] | None = None,
) -> ScanReport:
    """Orquesta un scan de red dirigido por LLM.

    El agente Claude decide iterativamente qué tests correr basándose en los
    hallazgos acumulados, con un gate de intercepción pre-ejecución.
    """
    # construir pool LLM si no se pasó uno externamente
    if pool is None:
        pool = LLMPool.from_env(
            preferred=provider,
            model_override=model,
        )

    # emitir info del provider activo
    active = pool.active_provider()

    # budget ledger — from env if not passed explicitly
    if budget_ledger is None:
        budget_ledger = BudgetLedger.from_env()  # None when no budgets configured

    # tool RAG
    _rag = ToolRAG(_TOOL_DEFINITIONS)
    _rag_enabled = ToolRAG.enabled_from_env()

    def emit(event: dict) -> None:
        if progress_cb:
            progress_cb(event)

    target = NetworkTarget(url=target_url, scope=scope or [])
    gate = InterceptGate(
        scope=scope,
        denylist=denylist,
        allow_level3=allow_level3,
        allow_private=allow_private,
    )
    boundary = UntrustedBoundary()
    ledger = CoverageLedger()
    _governor = Governor(profile_from_env())
    _fact_store = FactStore()

    ctx: dict[str, Any] = {
        "timeout_s": timeout_s,
        "nuclei_severity": nuclei_severity or ["critical", "high", "medium"],
        "rate_limit": rate_limit,
        "environment": environment,
        "noise_governor": _governor,
        "fact_store": _fact_store,
    }

    all_tests_list = all_net_tests()
    tests_by_id = {t["id"]: t for t in all_tests_list}

    # traffic proxy (opcional)
    _proxy = None
    if enable_proxy:
        try:
            from engine.proxy.recorder import TrafficProxy
            _proxy = TrafficProxy(
                port=proxy_port,
                scan_id=str(uuid.uuid4())[:8],
                reports_dir="reports",
            )
            await _proxy.start()
            ctx["proxy_url"] = _proxy.proxy_url
        except Exception as e:
            emit({"type": "log", "message": f"[proxy] No se pudo iniciar en :{proxy_port}: {e}"})

    report = ScanReport(
        scan_id=str(uuid.uuid4())[:8],
        target_name=target_url,
        started_at=datetime.now(timezone.utc).isoformat(),
        ares_version=ARES_VERSION,
    )
    emit({"type": "scan_started", "scan_id": report.scan_id,
          "tests_selected": [], "mode": "agent",
          "provider": active})

    tests_run: list[str] = []
    system_prompt = _build_system_prompt(
        target_url, scope or [], goal or "", max_rounds, boundary
    )

    # -----------------------------------------------------------------------
    # Tool handlers
    # -----------------------------------------------------------------------

    async def handle_tool_call(name: str, tool_input: dict) -> str:

        if name == "list_available_tests":
            info = []
            for t in all_tests_list:
                decision = gate.check(target_url, t["id"], t.get("level", 1))
                blocked = decision.action == "deny"
                info.append({
                    "id": t["id"],
                    "level": t.get("level", 1),
                    "name": t["name"],
                    "description": t.get("description", ""),
                    "blocked_by_gate": blocked,
                    "gate_reason": decision.reason if blocked else None,
                    "already_run": t["id"] in tests_run,
                })
            raw = json.dumps(info, ensure_ascii=False)
            return boundary.wrap("list_available_tests", raw)

        elif name == "get_scan_state":
            by_sev: dict[str, int] = {}
            for f in report.findings:
                if not f.passed:
                    sev = f.severity.value
                    by_sev[sev] = by_sev.get(sev, 0) + 1
            state = {
                "tests_run": tests_run,
                "tests_remaining": [
                    t["id"] for t in all_tests_list if t["id"] not in tests_run
                ],
                "discovered_subdomains": list(target.discovered_subdomains),
                "crawled_urls_count": len(target.crawled_urls),
                "crawled_parametric_urls_count": sum(
                    1 for u in target.crawled_urls if "?" in u
                ),
                "findings_by_severity": by_sev,
                "total_confirmed_findings": sum(1 for f in report.findings if not f.passed),
            }
            raw = json.dumps(state, ensure_ascii=False)
            return boundary.wrap("get_scan_state", raw)

        elif name == "run_test":
            test_id = (tool_input.get("test_id") or "").strip()
            timeout_override = tool_input.get("timeout_override")

            if test_id not in tests_by_id:
                return json.dumps({
                    "error": f"test_id desconocido: '{test_id}'. "
                             f"Usá list_available_tests para ver los disponibles.",
                })
            if test_id in tests_run:
                return json.dumps({
                    "error": f"{test_id} ya corrió. "
                             f"Usá get_scan_state para ver qué tests quedan.",
                })

            test = tests_by_id[test_id]
            decision = gate.check(target_url, test_id, test.get("level", 1))

            # LLM judge for level 2+ tests (fail-closed inside judge)
            if test.get("level", 1) >= 2 and decision.action == "allow":
                try:
                    from engine.intercept.judge import InterceptJudge
                    _judge = InterceptJudge(pool=pool)
                    _jdecision = await _judge.judge(
                        test_id=test_id,
                        target_url=target_url,
                        test_description=test.get("description", test.get("name", test_id)),
                        scope=scope,
                        environment=environment,
                    )
                    if _jdecision.action == "block":
                        emit({"type": "judge_blocked", "test_id": test_id,
                              "reason": _jdecision.reason})
                        ledger.record_gate_denied(test_id, target_url,
                                                  f"judge: {_jdecision.reason}")
                        return json.dumps({"blocked": True,
                                           "gate_reason": f"LLM judge bloqueó: {_jdecision.reason}"})
                except Exception:
                    pass  # judge setup error → fail-open (fail-closed is inside judge)

            if decision.action == "deny":
                emit({"type": "gate_denied", "test_id": test_id, "reason": decision.reason})
                ledger.record_gate_denied(test_id, target_url, decision.reason)
                return json.dumps({
                    "blocked": True,
                    "gate_reason": decision.reason,
                    "suggestion": "Considerá usar un test de menor nivel o revisar la configuración del gate.",
                })

            emit({"type": "agent_tool_call", "tool": "run_test", "test_id": test_id})
            emit({"type": "test_started", "test_id": test_id, "name": test["name"]})
            ledger.record_started(test_id, target_url)

            run_ctx = dict(ctx)
            if timeout_override:
                run_ctx["timeout_s"] = int(timeout_override)

            prev_subdomains = set(target.discovered_subdomains)
            prev_urls = set(target.crawled_urls)

            try:
                findings = await test["fn"](target, run_ctx)
            except Exception as exc:
                emit({"type": "test_error", "test_id": test_id, "error": str(exc)})
                tests_run.append(test_id)
                ledger.record_finished(test_id, outcome="error", error=str(exc))
                return json.dumps({"error": str(exc), "test_id": test_id})

            # Persist ingest facts if the test deposited any
            for ingest_r in run_ctx.get("ingest_results", []):
                try:
                    await _fact_store.insert_from_ingest(ingest_r, task_id=report.scan_id)
                except Exception:
                    pass

            report.findings.extend(findings)
            tests_run.append(test_id)
            confirmed = sum(1 for f in findings if not f.passed)
            ledger.record_finished(test_id, findings_count=len(findings),
                                   confirmed_count=confirmed)
            emit({"type": "test_finished", "test_id": test_id,
                  "findings_count": len(findings), "confirmed": confirmed})

            new_subdomains = list(target.discovered_subdomains - prev_subdomains)
            new_urls_count = len(target.crawled_urls - prev_urls)
            new_findings = [f for f in findings if not f.passed]

            summary_parts = [f"Test {test_id} completado."]
            if confirmed:
                sev_counts: dict[str, int] = {}
                for f in new_findings:
                    sev_counts[f.severity.value] = sev_counts.get(f.severity.value, 0) + 1
                summary_parts.append(
                    f"{confirmed} hallazgos confirmados: " +
                    ", ".join(f"{v} {k}" for k, v in sev_counts.items())
                )
            else:
                summary_parts.append("Sin hallazgos confirmados.")
            if new_subdomains:
                shown = new_subdomains[:8]
                extra = f" (+{len(new_subdomains)-8} más)" if len(new_subdomains) > 8 else ""
                summary_parts.append(f"Nuevos subdominios: {', '.join(shown)}{extra}")
            if new_urls_count:
                summary_parts.append(f"{new_urls_count} nuevas URLs crawleadas.")

            top_findings = []
            for f in new_findings[:5]:
                top_findings.append({
                    "title": f.title,
                    "severity": f.severity.value,
                    "confidence": f.confidence,
                    "description": (f.description or "")[:300],
                })

            raw = json.dumps({
                "test_id": test_id,
                "findings_count": len(findings),
                "confirmed_count": confirmed,
                "summary": " ".join(summary_parts),
                "new_subdomains": new_subdomains[:8],
                "new_urls_count": new_urls_count,
                "top_findings": top_findings,
            }, ensure_ascii=False)
            return boundary.wrap(test_id, raw)

        elif name == "add_analyst_note":
            title = (tool_input.get("title") or "Nota del agente").strip()
            content = (tool_input.get("content") or "").strip()
            emit({"type": "agent_thinking", "title": title,
                  "content": content[:600]})
            report.findings.append(Finding(
                test_id="agent.analyst_note",
                title=f"[Agente] {title}",
                category=Category.NETWORK,
                target=target_url,
                description=content,
                passed=True,
            ))
            return json.dumps({"saved": True, "title": title})

        elif name == "finish":
            posture = (tool_input.get("security_posture") or "").strip()
            emit({"type": "agent_finished", "security_posture": posture})
            report.findings.append(Finding(
                test_id="agent.final_analysis",
                title="[Agente] Análisis final de seguridad",
                category=Category.NETWORK,
                target=target_url,
                description=posture,
                passed=True,
            ))
            return json.dumps({"finished": True})

        elif name == "ask_operator":
            question = (tool_input.get("question") or "").strip()
            urgency = tool_input.get("urgency", "informational")
            emit({"type": "side_question", "question": question, "urgency": urgency})
            if side_question_cb is not None:
                try:
                    answer = side_question_cb(question, urgency)
                    if asyncio.iscoroutine(answer):
                        answer = await answer
                    answer_str = str(answer) if answer else "(sin respuesta del operador)"
                except Exception as e:
                    answer_str = f"(error al obtener respuesta: {e})"
            else:
                answer_str = "(operador no disponible en este modo)"
            return boundary.wrap("ask_operator", json.dumps({
                "question": question, "answer": answer_str,
            }, ensure_ascii=False))

        elif name == "get_coverage":
            cov = ledger.summary()
            cov["coverage_pct"] = round(
                len(ledger.tested_ids) / len(all_tests_list) * 100, 1
            ) if all_tests_list else 0
            return boundary.wrap("get_coverage", json.dumps(cov, ensure_ascii=False))

        return json.dumps({"error": f"herramienta desconocida: {name}"})

    # -----------------------------------------------------------------------
    # LLM loop — usa el pool multi-proveedor
    # -----------------------------------------------------------------------

    messages: list[dict] = [{
        "role": "user",
        "content": (
            f"Comenzá el reconocimiento de {target_url}. "
            f"Scope: {', '.join(scope or []) or 'sin restricción'}. "
            f"Objetivo: {goal or 'encontrar vulnerabilidades de seguridad'}."
        ),
    }]

    finished = False
    intent_meter = budget_ledger.start_intent() if budget_ledger else None

    # Stagnation detection state
    _last_findings_count: int = 0
    _stagnation_rounds: int = 0
    _stagnation_hints: list[str] = []

    for round_num in range(max_rounds):
        # ── budget check ────────────────────────────────────────────────────
        wrapup_forced = False
        if budget_ledger:
            bstate = budget_ledger.state()
            emit({"type": "budget_state", **bstate.as_dict()})
            if bstate.at_margin:
                if budget_ledger.begin_wrapup():
                    emit({"type": "budget_wrapup", "message": TASK_BUDGET_WRAPUP})
                    messages.append({"role": "user", "content": TASK_BUDGET_WRAPUP})
                wrapup_forced = True

        # ── inject stagnation hints if any ──────────────────────────────────
        if _stagnation_hints:
            for hint in _stagnation_hints:
                messages.append({"role": "user", "content": hint})
            _stagnation_hints.clear()

        # ── tool RAG ────────────────────────────────────────────────────────
        last_msg = messages[-1].get("content", "") if messages else ""
        if isinstance(last_msg, list):
            last_msg = " ".join(
                b.get("content", "") if isinstance(b, dict) else ""
                for b in last_msg
            )
        tools_this_round = _rag.relevant_for(str(last_msg)) if _rag_enabled else _TOOL_DEFINITIONS

        emit({"type": "agent_round", "round": round_num + 1, "max_rounds": max_rounds,
              "provider": pool.active_provider(),
              "tools_count": len(tools_this_round)})
        try:
            response = await pool.chat(
                messages,
                system=system_prompt,
                tools=tools_this_round,
                max_tokens=4096,
            )
        except Exception as e:
            emit({"type": "agent_error", "error": f"Error de API LLM: {e}",
                  "pool_health": pool.health_summary()})
            report.errors.append(f"Error de API LLM en ronda {round_num + 1}: {e}")
            break

        # meter usage into budget
        if budget_ledger and "usage" in response:
            u = response["usage"]
            tokens = (u.get("input_tokens", 0) or 0) + (u.get("output_tokens", 0) or 0)
            budget_ledger.record(tokens, turns=1)
            if intent_meter:
                intent_meter.record(tokens, turns=1)

        # content nativo (Anthropic) o normalizado (resto de proveedores)
        messages.append({"role": "assistant", "content": response["content"]})

        stop_reason = response["stop_reason"]
        content_blocks = response["content_normalized"]

        if stop_reason == "end_turn":
            break

        if stop_reason == "tool_use":
            tool_results = []
            for block in content_blocks:
                if isinstance(block, dict) and block.get("type") == "tool_use":
                    tool_name = block["name"]
                    # budget wrapup: block non-essential tools
                    if wrapup_forced and WRAPUP_BLOCKS_TOOL(tool_name):
                        result = json.dumps({"blocked": True, "reason": WORKER_BUDGET_WRAPUP})
                    else:
                        result = await handle_tool_call(tool_name, block.get("input", {}))
                    tool_results.append({
                        "type": "tool_result",
                        "tool_use_id": block["id"],
                        "content": result,
                    })
                    if tool_name == "finish":
                        finished = True
            messages.append({"role": "user", "content": tool_results})

            # ── Stagnation detection ─────────────────────────────────────────
            current_findings = len(report.findings)
            if current_findings == _last_findings_count:
                _stagnation_rounds += 1
                if _stagnation_rounds >= STAGNATION_WINDOW:
                    emit({"type": "stagnation_detected",
                          "rounds": _stagnation_rounds,
                          "findings_count": current_findings})
                    stagnation_hint = (
                        f"[STAGNATION DETECTED] Llevas {_stagnation_rounds} rondas sin encontrar "
                        "nuevos hallazgos. Cambia de estrategia: prueba un vector diferente, amplía el scope "
                        "de búsqueda, o si has cubierto todas las categorías relevantes, prepara el wrap-up."
                    )
                    _stagnation_hints.append(stagnation_hint)
            else:
                _stagnation_rounds = 0
            _last_findings_count = current_findings
            # ────────────────────────────────────────────────────────────────

            if finished:
                break
            # stop if budget exhausted after wrapup
            if intent_meter and intent_meter.exhausted():
                emit({"type": "budget_exhausted", "message": "Intent budget exhausted"})
                break
        else:
            # max_tokens u otro stop_reason
            break

    if intent_meter:
        intent_meter.finish()

    report.finished_at = datetime.now(timezone.utc).isoformat()

    # detener proxy si se inició
    if _proxy is not None:
        try:
            await _proxy.stop()
            summary = _proxy.get_summary()
            emit({"type": "proxy_summary", **summary})
        except Exception:
            pass

    # emitir resumen del pool al finalizar
    emit({"type": "pool_health", "providers": pool.health_summary()})

    noise = apply_noise_reduction(report, allowlist_path, min_confidence)
    if noise["allowlisted"] or noise["below_confidence_floor"]:
        emit({
            "type": "noise_reduction",
            "allowlisted": noise["allowlisted"],
            "below_confidence_floor": noise["below_confidence_floor"],
        })

    report.score = calculate_score(report)
    report.policy_verdict = PolicyEngine().evaluate(report, environment)

    # Enrich discovered subdomains
    try:
        from engine.enrich.probe import EnrichEngine
        _enrich = EnrichEngine(gate=gate, noise_governor=_governor, max_workers=4)
        _assets_to_enrich = [
            {"kind": "domain", "value": d}
            for d in list(target.discovered_subdomains)[:20]
        ]
        if _assets_to_enrich:
            _enrich_results = await _enrich.enrich_batch(
                _assets_to_enrich, scope or [], progress_cb=emit
            )
            emit({"type": "enrich_complete", "count": len(_enrich_results)})
            for r in _enrich_results:
                if not r.error and r.asset_value not in report.extra_assets:
                    report.extra_assets.append(r.asset_value)
    except Exception:
        pass

    # Facts summary
    try:
        facts_summary = await _fact_store.recent(limit=5, task_id=report.scan_id)
        if facts_summary:
            emit({"type": "facts_summary", "count": len(facts_summary),
                  "sample": [f"{f.subject} {f.predicate} {f.object}"
                              for f in facts_summary[:3]]})
    except Exception:
        pass

    # RSI: extract lessons from completed scan (shadow mode by default)
    try:
        from engine.rsi.lessons import LessonLibrary
        from engine.rsi.extractor import extract_lessons_from_report
        import os
        rsi_mode = os.environ.get("ARES_RSI_MODE", "shadow")
        if rsi_mode != "disabled":
            _lib = LessonLibrary()
            new_lessons = extract_lessons_from_report(report, _lib, rsi_mode=rsi_mode)
            if new_lessons:
                emit({"type": "rsi_lessons_extracted", "count": len(new_lessons),
                      "lesson_ids": [l.id for l in new_lessons]})
    except Exception:
        pass

    return report
