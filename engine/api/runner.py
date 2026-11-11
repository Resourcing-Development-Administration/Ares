"""
Orquestador del módulo de APIs -- equivalente a engine/orchestrator.py pero para ApiTarget.
Reutiliza ScanReport/Finding/scoring/policy/redacción/SARIF tal cual: un reporte de API y uno de MCP
tienen la misma forma, así CLI/webui/dashboard no necesitan un camino separado para mostrarlos.
"""
from __future__ import annotations
import re
import traceback
import uuid
from datetime import datetime, timezone

from engine import __version__ as ARES_VERSION
from engine.core.models import ScanReport, Finding, Category
from engine.api.client import ApiTarget
from engine.api.registry import all_api_tests
from engine.api.spec import load_endpoints
from engine.reporting.scoring import calculate_score
from engine.reporting.suppress import apply_noise_reduction
from engine.policy.engine import PolicyEngine

_RECURSIVE_HINT = re.compile(r"repl(y|ies)|comment|child|parent|sub", re.I)


def _resolved_tests(selected: list[str] | None) -> dict:
    reg = all_api_tests()
    if not selected:
        return {k: v for k, v in reg.items() if v[0].default_enabled}
    return {k: v for k, v in reg.items() if k in selected}


async def _probe_graphql(target, path_hint: str | None) -> dict:
    """Devuelve {'graphql_path':..., 'gql_recursive_field':..., 'gql_query_fields':[...], 'gql_probe_field':...}
    o {'graphql_path': None} si no hay GraphQL. Hace como máximo UNA query de introspección."""
    from engine.api.graphql_tests import INTROSPECTION_QUERY
    candidates = [path_hint] if path_hint else ["/graphql", "/api/graphql", "/v1/graphql", "/gql"]
    for path in candidates:
        if not path:
            continue
        r = await target.request("POST", path, json_body={"query": "{ __typename }"}, auth="a")
        if r["status"] and r["status"] < 500 and (r.get("json") or {}).get("data", {}):
            out: dict = {"graphql_path": path}
            ir = await target.request("POST", path, json_body={"query": INTROSPECTION_QUERY}, auth="a")
            types = (((ir.get("json") or {}).get("data") or {}).get("__schema") or {}).get("types") or []
            qfields, recursive = [], None
            qt_name = (((ir.get("json") or {}).get("data") or {}).get("__schema") or {}).get("queryType", {}).get("name")
            for t in types:
                # los tipos de introspección (__Schema, __Type...) tienen campos como "subscriptionType"
                # que matchean el hint por nombre sin ser un campo de DATOS real -- se excluyen enteros.
                if str(t["name"]).startswith("__"):
                    continue
                for f in t.get("fields") or []:
                    if _RECURSIVE_HINT.search(f["name"] or "") and not str(f["name"]).startswith("__"):
                        recursive = f["name"]
            # probe_field: SIEMPRE __typename -- cualquier otro campo "sin args" puede ser costoso de
            # verdad (confirmado: un campo de diagnóstico sin args tardó >15s por request real a un
            # servicio externo), y 40 alias de ese campo en gql.alias_batching dispararía un timeout,
            # no una medición válida de batching.
            probe_field = "__typename"
            qt = next((t for t in types if t["name"] == ((ir.get("json") or {}).get("data", {}).get("__schema", {}).get("queryType", {}) or {}).get("name")), None)
            if qt:
                qfields = [f["name"] for f in (qt.get("fields") or [])]
            out["gql_recursive_field"] = recursive
            out["gql_query_fields"] = qfields
            out["gql_probe_field"] = probe_field
            return out
    return {"graphql_path": None}


async def run_api_scan(*, base_url: str, spec_source: str | None = None, selected_tests: list[str] | None = None,
                       headers: dict | None = None, auth_a: dict | None = None, auth_b: dict | None = None,
                       jwt: str | None = None, verify=True, delay_ms: int = 0, max_fuzz: int = 40,
                       test_timeout_s: float = 60.0, graphql_path: str | None = None,
                       allowlist_path: str | None = None, min_confidence: str = "heuristic",
                       environment: str = "production", progress_cb=None) -> ScanReport:
    """progress_cb: callable opcional (event: dict) -> None -- mismo vocabulario de eventos que
    engine/orchestrator.py::run_scan (scan_started/test_started/test_finished/test_error/log), para
    que el dashboard (webui/app.py::ws_api_scan) reuse el mismo JS de progreso que ya tiene para MCP."""
    import asyncio

    def emit(event: dict):
        if progress_cb:
            progress_cb(event)

    report = ScanReport(scan_id=str(uuid.uuid4())[:8], target_name=base_url,
                        started_at=datetime.now(timezone.utc).isoformat(), ares_version=ARES_VERSION)
    target = ApiTarget(base_url, headers=headers, auth_a=auth_a, auth_b=auth_b, verify=verify, delay_ms=delay_ms)
    try:
        emit({"type": "log", "message": f"Cargando endpoints/spec de {base_url} ..."})
        endpoints, origin = await load_endpoints(target, spec_source)
        report.errors.append(f"endpoints: {origin} ({len(endpoints)} encontrados)")
        emit({"type": "log", "message": f"endpoints: {origin} ({len(endpoints)} encontrados)"})
        gql = await _probe_graphql(target, graphql_path)
        if gql.get("graphql_path"):
            emit({"type": "log", "message": f"GraphQL detectado en {gql['graphql_path']}"})

        ctx = {"endpoints": endpoints, "auth_a": target.has_auth("a"), "auth_b": target.has_auth("b"),
               "max_fuzz": max_fuzz, "jwt": jwt, **gql}

        if not endpoints and not gql.get("graphql_path"):
            report.findings.append(Finding(
                test_id="api.no_spec", title="No se encontraron endpoints ni GraphQL -- scan incompleto",
                category=Category.API, target="server", passed=False,
                description=f"No se cargaron endpoints desde un spec ({origin}) ni se detectó un endpoint "
                             f"GraphQL en las rutas comunes. Pasá --spec (OpenAPI/Postman) o --graphql-path.",
                remediation="Proveer --spec con la URL/archivo del OpenAPI/Postman, o --graphql-path."))

        tests = _resolved_tests(selected_tests)
        emit({"type": "scan_started", "scan_id": report.scan_id, "tests_selected": list(tests)})
        for test_id, (meta, fn) in tests.items():
            kind = getattr(meta, "kind", "rest")
            if kind == "graphql" and not ctx.get("graphql_path"):
                continue  # el propio test ya sabe reportar "sin endpoint graphql" si se lo llama a mano; en
                          # el runner automático simplemente no tiene sentido correrlo
            emit({"type": "test_started", "test_id": test_id, "name": meta.name})
            try:
                findings = await asyncio.wait_for(fn(target, ctx), timeout=test_timeout_s)
                report.findings.extend(findings)
                emit({"type": "test_finished", "test_id": test_id, "findings_count": len(findings),
                      "confirmed": sum(1 for f in findings if not f.passed)})
            except asyncio.TimeoutError:
                report.errors.append(f"test '{test_id}' no terminó en {test_timeout_s}s y se cortó.")
                emit({"type": "test_error", "test_id": test_id, "error": "timeout", "timeout": True})
            except Exception as e:
                report.errors.append(f"test '{test_id}' falló con excepción: {e}\n{traceback.format_exc()}")
                emit({"type": "test_error", "test_id": test_id, "error": str(e)})

        report.tools_enumerated = [{"name": e.key, "description": e.summary, "input_schema": {}} for e in endpoints]
    finally:
        await target.close()

    noise = apply_noise_reduction(report, allowlist_path, min_confidence)
    report.finished_at = datetime.now(timezone.utc).isoformat()
    report.score = calculate_score(report)
    report.policy_verdict = PolicyEngine().evaluate(report, environment)
    return report
