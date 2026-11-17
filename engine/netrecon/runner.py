"""
Orquestador de scans de red. Equivalente a engine/api/runner.py pero para
NetworkTarget en vez de MCPTarget.

Uso:
    report = await run_netrecon_scan(
        target_url="https://example.com",
        scope=["example.com"],
        selected_tests=["net.httpx_probe", "net.nuclei_scan"],
        nuclei_severity=["critical", "high"],
    )
"""
from __future__ import annotations
import asyncio
import uuid
from datetime import datetime, timezone
from typing import Callable, Any

# importar los tests para que el decorator los registre en _NET_REGISTRY
import engine.netrecon.tests  # noqa: F401

from engine.core.models import Finding, ScanReport, Category
from engine.netrecon.registry import all_net_tests
from engine.netrecon.target import NetworkTarget
from engine.reporting.suppress import apply_noise_reduction
from engine.intercept.gate import InterceptGate
from engine import __version__ as ARES_VERSION


async def run_netrecon_scan(
    *,
    target_url: str,
    scope: list[str] | None = None,
    selected_tests: list[str] | None = None,
    nuclei_severity: list[str] | None = None,
    timeout_s: int = 180,
    rate_limit: int = 150,
    min_confidence: str = "heuristic",
    environment: str = "production",
    allowlist_path: str | None = None,
    gate: InterceptGate | None = None,
    progress_cb: Callable[[dict], None] | None = None,
    kg: Any = None,
) -> ScanReport:
    """Ejecuta un scan de reconocimiento de red contra target_url.

    Args:
        target_url:        URL o dominio del objetivo.
        scope:             Dominios/IPs permitidos; None = sin restricción.
        selected_tests:    IDs de tests a ejecutar; None = todos.
        nuclei_severity:   Severidades nuclei a incluir (default: critical,high,medium).
        timeout_s:         Timeout por test en segundos.
        rate_limit:        Peticiones/seg máximas hacia el target.
        min_confidence:    Umbral mínimo de confianza para incluir findings.
        environment:       "production" | "staging" | "lab".
        allowlist_path:    Ruta a .ares_allowlist.yml para suprimir findings conocidos.
        progress_cb:       Callback opcional que recibe dicts de evento (mismo protocolo
                           que engine/api/runner: type test_started/test_finished/log).
    """
    def emit(event: dict) -> None:
        if progress_cb:
            progress_cb(event)

    target = NetworkTarget(
        url=target_url,
        scope=scope or [],
    )

    ctx: dict[str, Any] = {
        "timeout_s":       timeout_s,
        "nuclei_severity": nuclei_severity or ["critical", "high", "medium"],
        "rate_limit":      rate_limit,
        "environment":     environment,
    }

    # resolver lista de tests a ejecutar (all_net_tests() ya ordena por level)
    all_tests = all_net_tests()
    if selected_tests:
        tests_to_run = [t for t in all_tests if t["id"] in selected_tests]
    else:
        tests_to_run = all_tests

    started_at = datetime.now(timezone.utc).isoformat()
    report = ScanReport(
        scan_id=str(uuid.uuid4())[:8],
        target_name=target_url,
        started_at=started_at,
        ares_version=ARES_VERSION,
    )

    emit({"type": "scan_started", "scan_id": report.scan_id,
          "tests_selected": [t["id"] for t in tests_to_run]})

    # ejecutar tests en secuencia para que subfinder/katana alimenten a los siguientes
    for test in tests_to_run:
        tid  = test["id"]
        name = test["name"]

        # gate de intercepción opcional (lo usa el agent-scan; netrecon directo lo ignora)
        if gate is not None:
            if hasattr(gate, "check_async"):
                decision = await gate.check_async(target_url, tid, test.get("level", 1))
            else:
                decision = gate.check(target_url, tid, test.get("level", 1))
            if decision.action == "deny":
                emit({"type": "gate_denied", "test_id": tid, "reason": decision.reason})
                report.findings.append(Finding(
                    test_id=tid,
                    title=f"[gate] {tid} denegado",
                    category=Category.NETWORK,
                    target=target_url,
                    description=f"El gate interceptó este test: {decision.reason}",
                    passed=True,
                ))
                continue

        emit({"type": "test_started", "test_id": tid, "name": name})
        try:
            findings = await test["fn"](target, ctx)
        except Exception as exc:
            emit({"type": "test_error", "test_id": tid, "error": str(exc)})
            findings = [Finding(
                test_id=tid,
                title=f"Error inesperado en {tid}",
                category=Category.NETWORK,
                target=target_url,
                description=str(exc),
                passed=True,
            )]

        report.findings.extend(findings)
        confirmed = sum(1 for f in findings if not f.passed)
        emit({"type": "test_finished", "test_id": tid,
              "findings_count": len(findings), "confirmed": confirmed})

    report.finished_at = datetime.now(timezone.utc).isoformat()

    noise = apply_noise_reduction(report, allowlist_path, min_confidence)
    if noise["allowlisted"] or noise["below_confidence_floor"]:
        emit({"type": "noise_reduction",
              "allowlisted": noise["allowlisted"],
              "below_confidence_floor": noise["below_confidence_floor"]})

    from engine.reporting.scoring import calculate_score
    from engine.policy.engine import PolicyEngine
    report.score = calculate_score(report)
    report.policy_verdict = PolicyEngine().evaluate(report, environment)

    # Wire: persist findings + assets into the knowledge graph
    if kg is not None:
        try:
            await kg.populate_from_report(report)
            emit({"type": "kg_populated", "scan_id": report.scan_id})
        except Exception as exc:
            emit({"type": "kg_error", "error": str(exc)})

    return report
