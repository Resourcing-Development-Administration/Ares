"""
Orquestador Planner+Worker para scans de red autónomos.
Puerto de ARTEX agent/ — arquitectura separada donde el Planner emite intents
al IntentFrontier y los Workers los consumen concurrentemente.
"""
from __future__ import annotations
import asyncio
import json
import uuid
from datetime import datetime, timezone
from typing import Any, Callable

import engine.netrecon.tests  # noqa: F401

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
from engine.agent.budget import BudgetLedger, budgets_from_env
from engine.agent.claim import ClaimStore, get_store as get_claim_store
from engine.agent.planner import Planner, IntentFrontier, Intent
from engine.agent.worker import Worker
from engine import __version__ as ARES_VERSION

_DEFAULT_MAX_CONCURRENT_WORKERS = 3
_DEFAULT_PLANNER_ROUNDS = 4


async def run_agent_scan_v2(
    *,
    target_url: str,
    scope: list[str] | None = None,
    goal: str | None = None,
    model: str | None = None,
    provider: str = "auto",
    pool: LLMPool | None = None,
    max_planner_rounds: int = _DEFAULT_PLANNER_ROUNDS,
    max_concurrent_workers: int = _DEFAULT_MAX_CONCURRENT_WORKERS,
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
    """Orquesta un scan con arquitectura Planner+Worker separados.

    El Planner decide QUÉ explorar; los Workers ejecutan concurrentemente
    los intents en el frontier. Ambos usan el ScanReport compartido.
    """
    if pool is None:
        pool = LLMPool.from_env(preferred=provider, model_override=model)

    active = pool.active_provider()

    if budget_ledger is None:
        budget_ledger = BudgetLedger.from_env()

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

    ctx: dict[str, Any] = {
        "timeout_s": timeout_s,
        "nuclei_severity": nuclei_severity or ["critical", "high", "medium"],
        "rate_limit": rate_limit,
        "environment": environment,
    }

    all_tests_list = all_net_tests()
    tests_by_id = {t["id"]: t for t in all_tests_list}

    # traffic proxy
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
          "tests_selected": [], "mode": "agent_v2", "provider": active})

    # -----------------------------------------------------------------
    # Shared tool handler (same semantics as orchestrator.py)
    # -----------------------------------------------------------------
    _report_ref = report  # capture for closure

    async def handle_tool_call(name: str, tool_input: dict) -> str:
        if name == "list_available_tests":
            tests = all_net_tests()
            return json.dumps([
                {"id": t["id"], "description": t.get("description", ""), "level": t.get("level", 1)}
                for t in tests
            ], ensure_ascii=False)

        elif name == "get_scan_state":
            return json.dumps({
                "target": target_url,
                "findings_count": len(_report_ref.findings),
                "findings_by_severity": {
                    s: sum(1 for f in _report_ref.findings if f.severity.value == s)
                    for s in ["critical", "high", "medium", "low", "info"]
                },
                "extra_assets": (_report_ref.extra_assets[:20] if hasattr(_report_ref, "extra_assets") else []),
                "subdomains_found": len(target.discovered_subdomains),
            }, ensure_ascii=False)

        elif name == "run_test":
            test_id = tool_input.get("test_id", "")
            timeout_override = tool_input.get("timeout_override")

            if not test_id:
                return json.dumps({"error": "test_id requerido"})

            test_def = tests_by_id.get(test_id)
            if not test_def:
                return json.dumps({"error": f"Test '{test_id}' no encontrado"})

            # intercept gate check
            gate_result = gate.check(target_url, test_def.get("level", 1))
            if not gate_result.allowed:
                return json.dumps({"blocked": True, "reason": gate_result.reason})

            fn = test_def.get("fn")
            if fn is None:
                return json.dumps({"error": f"Test '{test_id}' no tiene función registrada"})

            test_timeout = timeout_override or ctx["timeout_s"]
            prev_subdomains = set(target.discovered_subdomains)
            prev_urls = set(target.crawled_urls)

            try:
                findings = await asyncio.wait_for(
                    fn(target, {**ctx, "test_id": test_id}),
                    timeout=test_timeout,
                )
            except asyncio.TimeoutError:
                return json.dumps({"error": f"Test '{test_id}' timeout ({test_timeout}s)"})
            except Exception as e:
                emit({"type": "test_error", "test_id": test_id, "error": str(e)})
                ledger.record_finished(test_id, outcome="error", error=str(e))
                return json.dumps({"error": str(e), "test_id": test_id})

            _report_ref.findings.extend(findings)
            confirmed = sum(1 for f in findings if not f.passed)
            ledger.record_finished(test_id, findings_count=len(findings), confirmed_count=confirmed)
            emit({"type": "test_finished", "test_id": test_id,
                  "findings_count": len(findings), "confirmed": confirmed})

            new_subdomains = list(target.discovered_subdomains - prev_subdomains)
            new_urls_count = len(target.crawled_urls - prev_urls)
            new_findings = [f for f in findings if not f.passed]
            top_findings = [
                {"title": f.title, "severity": f.severity.value, "description": (f.description or "")[:200]}
                for f in new_findings[:5]
            ]
            raw = json.dumps({
                "test_id": test_id, "findings_count": len(findings),
                "confirmed_count": confirmed,
                "new_subdomains": new_subdomains[:8],
                "new_urls_count": new_urls_count,
                "top_findings": top_findings,
            }, ensure_ascii=False)
            return boundary.wrap(test_id, raw)

        elif name == "add_analyst_note":
            title = (tool_input.get("title") or "Nota del agente").strip()
            content = (tool_input.get("content") or "").strip()
            if title and content:
                emit({"type": "agent_thinking", "title": title, "content": content[:600]})
                _report_ref.findings.append(Finding(
                    test_id="agent.analyst_note",
                    title=f"[Agente] {title}",
                    category=Category.NETWORK,
                    target=target_url,
                    description=content,
                    passed=True,
                ))
            return json.dumps({"saved": True, "title": title})

        elif name == "get_coverage":
            return json.dumps(ledger.summary(), ensure_ascii=False)

        else:
            return json.dumps({"error": f"Tool '{name}' no reconocida"})

    # -----------------------------------------------------------------
    # Planner + Worker loop
    # -----------------------------------------------------------------
    frontier = IntentFrontier()
    planner = Planner(pool, max_intents=20)
    _claim_store = ClaimStore()
    all_intent_history: list[dict] = []

    for round_n in range(max_planner_rounds):
        # check task-level budget
        force_wrapup = False
        budget_line = ""
        if budget_ledger:
            state = budget_ledger.state()
            if not state.dispatch and round_n > 0:
                force_wrapup = True
            budget_line = (
                f"Budget: {state.remaining.tokens} tokens / {state.remaining.turns} turns restantes"
                if state.remaining.tokens or state.remaining.turns else ""
            )

        emit({"type": "planner_round", "round": round_n + 1, "max": max_planner_rounds})

        # get current findings for planner context
        current_findings_dicts = [
            {"id": f.id, "title": f.title, "severity": f.severity, "url": f.url}
            for f in _report_ref.findings[:30]
        ]
        coverage_summary = ledger.summary()

        new_intents = await planner.plan(
            target_url=target_url,
            scope=scope or [],
            goal=goal or "",
            current_findings=current_findings_dicts,
            coverage_summary=coverage_summary,
            facts_context="",
            previous_intents=all_intent_history,
            budget_line=budget_line,
            force_wrapup=force_wrapup,
            progress_cb=progress_cb,
        )

        for intent in new_intents:
            await frontier.add(intent)
            all_intent_history.append(intent.to_dict())

        # drain frontier with concurrent workers
        if frontier.pending_count() > 0:
            worker = Worker(
                pool=pool,
                handle_tool_call=handle_tool_call,
                report=_report_ref,
                boundary=boundary,
                ledger=ledger,
                budget_ledger=budget_ledger,
                max_rounds=6,
            )

            tasks = []
            for _ in range(max_concurrent_workers):
                next_intent = await frontier.next()
                if next_intent is None:
                    break
                _token = uuid.uuid4().hex
                next_intent.claim_token = _token
                await _claim_store.claim(next_intent.id, _token)
                tasks.append(
                    asyncio.create_task(
                        _claim_store.run_with_heartbeat(
                            next_intent.id,
                            _token,
                            worker.execute(
                                next_intent,
                                target_url=target_url,
                                scope=scope or [],
                                progress_cb=progress_cb,
                            ),
                        )
                    )
                )

            if tasks:
                results = await asyncio.gather(*tasks, return_exceptions=True)
                for r in results:
                    if isinstance(r, Exception):
                        emit({"type": "worker_exception", "error": str(r)})
                    else:
                        all_intent_history[-1]["result"] = r.summary if r.success else r.error

        if planner.goal_met:
            emit({"type": "goal_met", "evidence": planner.goal_evidence})
            break

        if force_wrapup:
            break

    # drain any remaining frontier intents sequentially
    worker = Worker(
        pool=pool,
        handle_tool_call=handle_tool_call,
        report=_report_ref,
        boundary=boundary,
        ledger=ledger,
        budget_ledger=budget_ledger,
        max_rounds=4,
    )
    while True:
        next_intent = await frontier.next()
        if next_intent is None:
            break
        await worker.execute(
            next_intent,
            target_url=target_url,
            scope=scope or [],
            progress_cb=progress_cb,
        )

    # -----------------------------------------------------------------
    # Finalise
    # -----------------------------------------------------------------
    if _proxy is not None:
        try:
            await _proxy.stop()
            emit({"type": "proxy_summary", **_proxy.get_summary()})
        except Exception:
            pass

    emit({"type": "pool_health", "providers": pool.health_summary()})

    _report_ref.finished_at = datetime.now(timezone.utc).isoformat()

    noise = apply_noise_reduction(_report_ref, allowlist_path, min_confidence)
    if noise["allowlisted"] or noise["below_confidence_floor"]:
        emit({
            "type": "noise_reduction",
            "allowlisted": noise["allowlisted"],
            "below_confidence_floor": noise["below_confidence_floor"],
        })

    _report_ref.score = calculate_score(_report_ref)
    _report_ref.policy_verdict = PolicyEngine().evaluate(_report_ref, environment)

    return _report_ref
