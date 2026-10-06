"""
Dashboard (FastAPI + WebSocket): mismo motor que la CLI, sin lógica
duplicada -- correr scan/vet/full desde el navegador con progreso en vivo, y
navegar reportes históricos. Sin build step ni JS framework -- un solo HTML
con <script> vanilla.

Arrancar: python cli/main.py serve   (ver cli/main.py::cmd_serve)

IMPORTANTE: este dashboard puede lanzar procesos locales arbitrarios
(transporte stdio) y abrir conexiones salientes reales si tildás
"allow_network"/"source_path", corrés `vet` (que las fuerza), o corrés
`full` sobre varios targets. Bindea a 127.0.0.1 por default a propósito --
no lo expongas a una red no confiable sin ponerle autenticación/proxy encima.

Gate de token opcional: si la variable de entorno ARES_DASHBOARD_TOKEN está
seteada, TODAS las rutas (HTTP y WebSocket) exigen ese token vía header
`X-Ares-Token` o querystring `?token=...` -- 401/close si falta o no matchea.
Sin la variable seteada, el comportamiento es el de siempre (confiar en el
bind a localhost). No es RBAC ni multi-usuario -- es un gate mínimo para no
quedar completamente abierto si alguien lo expone más allá de localhost
(ej. detrás de un port-forward) sin querer.
"""
from __future__ import annotations
import asyncio
import json
import os
import re
import secrets
import uuid
from datetime import datetime, timezone

import httpx
from fastapi import FastAPI, Request, WebSocket, WebSocketDisconnect, status
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse

from engine.core.models import ScanConfig, AuthConfig, ScanReport
from engine.core.tls import resolve_ca_bundle
from engine.core.registry import list_meta, all_tests
from engine.orchestrator import run_scan
from engine.compare import run_auth_comparison
from engine.reporting.html_report import save_html_report
from engine.reporting.sarif import save_sarif_report
from engine.reporting.redact import redact_report
from engine.reporting.suppress import default_allowlist_path
from engine.reporting.scoring import calculate_score
from engine.policy.engine import PolicyEngine
from engine.baseline import diff_against_baseline
from engine.discovery.local_configs import discover_mcp_servers
from engine.crossserver import analyze_cross_server, cross_server_findings

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
ARES_DIR = os.path.dirname(BASE_DIR)
REPORTS_DIR = os.path.join(ARES_DIR, "reports")
INDEX_PATH = os.path.join(REPORTS_DIR, "index.json")

DASHBOARD_TOKEN = os.environ.get("ARES_DASHBOARD_TOKEN")


def _token_ok(supplied: str | None) -> bool:
    if not DASHBOARD_TOKEN:
        return True  # sin token configurado -- sin cambios de comportamiento
    return bool(supplied) and secrets.compare_digest(supplied, DASHBOARD_TOKEN)


def websocket_token_ok(websocket: WebSocket) -> bool:
    """Chequeo para rutas WebSocket, llamado a mano al principio de cada
    @app.websocket(...) -- un middleware HTTP (de abajo) nunca intercepta el
    handshake de upgrade de un WebSocket en Starlette, así que esto es la ÚNICA
    protección real para /ws/scan y /ws/full, no defensa en profundidad."""
    supplied = websocket.headers.get("X-Ares-Token") or websocket.query_params.get("token")
    return _token_ok(supplied)


app = FastAPI(title="Ares Dashboard")


@app.middleware("http")
async def _token_gate(request: Request, call_next):
    """Gate de token para rutas HTTP normales. NO usar `dependencies=[Depends(...)]` a
    nivel app para esto -- se probó y rompe TODA conexión WebSocket: FastAPI intenta
    inyectar un `Request` (típico de HTTP) también en el scope de un WebSocket, donde no
    existe, y el handshake entero falla con 500 ("require_token() missing 1 required
    positional argument") -- incluso con ARES_DASHBOARD_TOKEN sin configurar. Un
    middleware `@app.middleware("http")` sí es seguro: Starlette solo lo aplica a
    requests HTTP normales, nunca al upgrade de un WebSocket -- ver websocket_token_ok()
    para la protección equivalente de /ws/scan y /ws/full."""
    supplied = request.headers.get("X-Ares-Token") or request.query_params.get("token")
    if not _token_ok(supplied):
        return JSONResponse({"detail": "falta o es inválido X-Ares-Token (header) / ?token= (querystring)"},
                             status_code=status.HTTP_401_UNAUTHORIZED)
    return await call_next(request)


def _load_index() -> list[dict]:
    if not os.path.isfile(INDEX_PATH):
        return []
    with open(INDEX_PATH, "r", encoding="utf-8") as f:
        return json.load(f)


def _save_index(entries: list[dict]):
    os.makedirs(REPORTS_DIR, exist_ok=True)
    with open(INDEX_PATH, "w", encoding="utf-8") as f:
        json.dump(entries, f, indent=2, ensure_ascii=False)


def _add_index_entry(entry: dict):
    entries = _load_index()
    entries.insert(0, entry)
    _save_index(entries[:200])  # cap histórico


# --- construcción de ScanConfig: separado en (transporte+conexión) por un lado
# y (resto de opciones) por otro, para reusar el mismo builder de opciones tanto
# en un scan de un solo target como en cada target de un batch `full` --------

def _connection_from_params(params: dict) -> tuple[str, dict]:
    transport = params.get("transport", "stdio")
    if transport == "stdio":
        return transport, {"command": params.get("command"), "args": (params.get("args") or "").split()}
    return transport, {"url": params.get("url")}


def _resolve_ca_bundle(raw: str | None) -> str | None:
    """Igual que la CLI: --ca-bundle con fallback a SSL_CERT_FILE. Si la ruta dada no
    existe, no reventamos el request con un 500 -- devolvemos la ruta tal cual para que
    el intento de conexión TLS falle de forma visible y quede como error de conexión en
    el reporte (mismo camino que cualquier otro target TLS inaccesible)."""
    raw = (raw or "").strip() or None
    try:
        return resolve_ca_bundle(raw)
    except ValueError:
        return raw


def _build_config(params: dict, target_name: str, transport: str, connection: dict, mode: str = "scan") -> ScanConfig:
    connection = dict(connection)
    headers = {}
    for line in (params.get("headers_raw") or "").splitlines():
        if ":" in line:
            k, v = line.split(":", 1)
            headers[k.strip()] = v.strip()
    if headers:
        connection.setdefault("headers", {}).update(headers)

    auth = None
    if params.get("auth_token"):
        auth = AuthConfig(
            type=params.get("auth_type") or "bearer",
            token=params["auth_token"],
            header_name=params.get("auth_header_name") or None,
        )

    secondary_auth = None
    if params.get("auth_token_b"):
        secondary_auth = AuthConfig(
            type=params.get("auth_type_b") or "bearer",
            token=params["auth_token_b"],
            header_name=params.get("auth_header_name_b") or None,
        )

    is_vet = mode == "vet"
    selected = sorted(all_tests().keys()) if is_vet else (params.get("tests") or [])
    allowlist_path = params.get("allowlist_path") or default_allowlist_path()

    return ScanConfig(
        target_name=target_name,
        transport=transport,
        connection=connection,
        selected_tests=selected,
        max_fuzz_cases_per_tool=int(params.get("max_fuzz_cases") or (50 if is_vet else 25)),
        allow_network_side_effects=True if is_vet else bool(params.get("allow_network")),
        auth=auth,
        environment="production" if is_vet else (params.get("environment") or "production"),
        source_path=params.get("source_path") or None,
        ca_bundle=_resolve_ca_bundle(params.get("ca_bundle")),  # CA (PEM) para validar TLS del server contra CA interna
        trust_presented_cert=bool(params.get("trust_presented_cert")),  # pinning TOFU del cert presentado (opt-in)
        request_delay_ms=int(params.get("request_delay_ms") or 0),
        oob_callback_host=params.get("oob_callback_host") or None,
        allowlist_path=allowlist_path,
        min_confidence=params.get("min_confidence") or "heuristic",
        live_agent_provider=params.get("live_agent_provider") or "auto",
        package_name=params.get("package_name") or None,
        test_timeout_s=float(params.get("test_timeout_s") or 60.0),
        baseline_path=params.get("baseline_path") or None,
        verbose=bool(params.get("verbose")),
        # antes de este fix, _build_config del dashboard NO pasaba ninguno de estos -- no era
        # un agujero de seguridad (los defaults del dataclass ya son seguros: sandbox+circuit
        # breaker+reset de sesión ON), pero sí dejaba al dashboard sin ningún control fino
        # sobre ellos, a diferencia de la CLI. Mismos params que la UI ya puede mandar.
        max_consecutive_timeouts=int(params.get("max_consecutive_timeouts") or 3),
        sandbox_subprocess=not bool(params.get("no_sandbox")),
        sandbox_mem_mb=int(params.get("sandbox_mem_mb") or 512),
        sandbox_cpu_s=int(params.get("sandbox_cpu_s") or 120),
        sandbox_nproc=int(params["sandbox_nproc"]) if params.get("sandbox_nproc") else None,
        sandbox_nofile=int(params.get("sandbox_nofile") or 256),
        max_text_for_analysis=int(params["max_text_for_analysis"]) if params.get("max_text_for_analysis") else None,
        max_response_content=int(params["max_response_content"]) if params.get("max_response_content") else None,
        reset_session_on_timeout=not bool(params.get("no_session_reset")),
        secondary_auth=secondary_auth,
    )


def _incomplete_reason(report) -> str | None:
    """Si la corrida quedó incompleta porque no se pudo conectar (o el target dejó de
    responder), devuelve la descripción del finding -- para que el dashboard muestre un
    banner de 'resultado NO válido como postura' en vez de un score engañoso."""
    for f in report.findings:
        if f.test_id in ("orchestrator.connection_failed", "orchestrator.target_unresponsive_sustained") and not f.passed:
            return f.description
    return None


def _cert_summary(report) -> dict | None:
    """Extrae del reporte el hallazgo de exposure.certificate_type y lo devuelve en
    forma compacta, para que el dashboard muestre el TIPO de certificado (autofirmado
    vs normal/CA) directo en los resultados, sin tener que abrir el HTML. Devuelve None
    si el test no corrió (p.ej. target stdio o endpoint sin TLS)."""
    for f in report.findings:
        if f.test_id != "exposure.certificate_type":
            continue
        resp = (f.evidence.response if f.evidence else None) or {}
        if "error" in resp:
            return {"available": False, "error": resp.get("error")}
        # Si el cert es un hallazgo (self-signed / cadena desconocida / expirado), incluir la
        # clasificación de riesgo y los frameworks para mostrarlos en la tarjeta del dashboard.
        risk = None
        if not f.passed:
            r = f.risk or {}
            risk = {
                "severity": f.severity.value,
                "risk_rating": r.get("risk_rating"),
                "cvss_score": r.get("cvss_score"),
                "frameworks": [f"{t['framework']} {t.get('id') or ''}".strip() for t in f.frameworks],
                "references": f.references,
            }
        return {
            "available": True,
            "passed": f.passed,
            "risk": risk,
            "assessment": resp.get("assessment"),  # {verdict, headline, factors[]} -- dictamen minucioso
            "type": resp.get("type"),
            "self_signed": resp.get("self_signed"),
            "issuer": resp.get("issuer"),
            "subject": resp.get("subject"),
            "not_before": resp.get("not_before"),
            "not_after": resp.get("not_after"),
            "expired": resp.get("expired"),
            "tls_version": resp.get("tls_version"),
            "fingerprint_sha256": resp.get("fingerprint_sha256"),
            "signature_algorithm": resp.get("signature_algorithm"),
            "key_type": resp.get("key_type"),
            "trusted_by_default": resp.get("trusted_by_default"),
            "trusted_by_custom_ca": resp.get("trusted_by_custom_ca"),
        }
    return None


def _regression_summary(new_findings: list[dict]) -> list[dict]:
    """Payload liviano para el webhook -- nunca evidence.request/response
    (un webhook es un destino externo; no le mandamos ahí lo mismo que
    redact.py saca antes de persistir a disco)."""
    return [{"test_id": f["test_id"], "severity": f["severity"], "target": f["target"], "title": f["title"]} for f in new_findings]


async def _post_webhook(url: str, payload: dict) -> str | None:
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.post(url, json=payload)
        return f"webhook enviado a {url} (HTTP {resp.status_code})"
    except Exception as e:
        return f"no se pudo enviar el webhook a {url}: {e}"


async def _apply_baseline_and_webhook(report, config: ScanConfig, webhook_url: str | None) -> str | None:
    """Devuelve una línea de log opcional (baseline diff y/o resultado del webhook)."""
    if not config.baseline_path:
        return None
    try:
        report.baseline_diff = diff_against_baseline(report, config.baseline_path)
    except FileNotFoundError:
        return f"--baseline '{config.baseline_path}' no existe, se omite el diff."
    line = f"baseline: {report.baseline_diff['summary']}"
    if webhook_url:
        new = report.baseline_diff.get("new") or []
        if new:
            webhook_result = await _post_webhook(webhook_url, {
                "event": "ares_regression", "target": report.target_name,
                "new_count": len(new), "new_findings": _regression_summary(new),
                "summary": report.baseline_diff["summary"],
            })
            line += f" · {webhook_result}"
    return line


# --- API read-only -------------------------------------------------------

@app.get("/", response_class=HTMLResponse)
async def index():
    with open(os.path.join(BASE_DIR, "static", "index.html"), "r", encoding="utf-8") as f:
        return f.read()


@app.get("/api/tests")
async def api_tests():
    return [
        {
            "id": m.id, "name": m.name, "category": m.category.value,
            "description": m.description, "default_enabled": m.default_enabled,
            "requires_network": m.requires_network,
        }
        for m in sorted(list_meta(), key=lambda m: (m.category.value, m.id))
    ]


@app.get("/api/discover")
async def api_discover():
    return discover_mcp_servers()


@app.get("/api/reports")
async def api_reports():
    return _load_index()


@app.get("/reports/{scan_id}/{filename}")
async def get_report_file(scan_id: str, filename: str):
    safe = os.path.basename(filename)
    path = os.path.join(REPORTS_DIR, scan_id, safe)
    if not os.path.isfile(path):
        return JSONResponse({"error": "no encontrado"}, status_code=404)
    return FileResponse(path)


async def _persist_report(scan_id: str, suffix: str, report) -> dict:
    safe_report = redact_report(report)  # nunca persistir secretos que hayan quedado en la evidencia cruda
    scan_dir = os.path.join(REPORTS_DIR, scan_id)
    os.makedirs(scan_dir, exist_ok=True)
    html_name = f"report{suffix}.html"
    json_name = f"report{suffix}.json"
    sarif_name = f"report{suffix}.sarif"
    save_html_report(safe_report, os.path.join(scan_dir, html_name))
    with open(os.path.join(scan_dir, json_name), "w", encoding="utf-8") as f:
        json.dump(safe_report.to_dict(), f, indent=2, ensure_ascii=False, default=str)
    save_sarif_report(safe_report, os.path.join(scan_dir, sarif_name))
    return {"html": f"/reports/{scan_id}/{html_name}", "json": f"/reports/{scan_id}/{json_name}", "sarif": f"/reports/{scan_id}/{sarif_name}"}


# --- scan / vet: un solo target -------------------------------------------

@app.websocket("/ws/scan")
async def ws_scan(websocket: WebSocket):
    if not websocket_token_ok(websocket):
        await websocket.close(code=1008)  # policy violation -- defensa en profundidad, ver require_token
        return
    await websocket.accept()
    try:
        raw = await websocket.receive_text()
        params = json.loads(raw)
    except Exception as e:
        await websocket.send_json({"type": "fatal_error", "error": f"config inválida: {e}"})
        await websocket.close()
        return

    try:
        mode = params.get("mode") or "scan"
        transport, connection = _connection_from_params(params)
        target_name = params.get("name") or params.get("command") or params.get("url") or "target"
        config = _build_config(params, target_name, transport, connection, mode=mode)
    except Exception as e:
        await websocket.send_json({"type": "fatal_error", "error": f"no se pudo armar la config: {e}"})
        await websocket.close()
        return

    queue: asyncio.Queue = asyncio.Queue()

    def progress(event: dict):
        queue.put_nowait(event)

    compare_auth = bool(params.get("compare_auth"))

    async def run():
        if compare_auth:
            return await run_auth_comparison(config, progress_cb=progress)
        report = await run_scan(config, progress_cb=progress)
        return report, None

    task = asyncio.create_task(run())

    try:
        while not task.done():
            try:
                event = await asyncio.wait_for(queue.get(), timeout=0.2)
                await websocket.send_json({"type": "progress", "event": event})
            except asyncio.TimeoutError:
                continue
        while not queue.empty():
            event = queue.get_nowait()
            await websocket.send_json({"type": "progress", "event": event})

        report_with, report_without = task.result()
    except WebSocketDisconnect:
        task.cancel()
        return
    except Exception as e:
        await websocket.send_json({"type": "fatal_error", "error": str(e)})
        await websocket.close()
        return

    baseline_line = await _apply_baseline_and_webhook(report_with, config, params.get("webhook_on_regression") or None)
    if baseline_line:
        await websocket.send_json({"type": "progress", "event": {"type": "log", "message": baseline_line}})

    scan_id = report_with.scan_id or uuid.uuid4().hex[:8]
    links = await _persist_report(scan_id, "", report_with)
    links_without = None
    if report_without is not None:
        links_without = await _persist_report(scan_id, ".sin_auth", report_without)

    _add_index_entry({
        "scan_id": scan_id,
        "target_name": report_with.target_name,
        "started_at": report_with.started_at,
        "finished_at": report_with.finished_at,
        "score": report_with.score,
        "policy_verdict": report_with.policy_verdict,
        "compare_auth": compare_auth,
        "mode": mode,
        "links": links,
        "saved_at": datetime.now(timezone.utc).isoformat(),
    })

    await websocket.send_json({
        "type": "done",
        "scan_id": scan_id,
        "summary": report_with.summary(),
        "score": report_with.score,
        "policy_verdict": report_with.policy_verdict,
        "auth_impact": report_with.auth_impact,
        "baseline_diff": report_with.baseline_diff,
        "tls_certificate": _cert_summary(report_with),
        "incomplete_reason": _incomplete_reason(report_with),
        "links": links,
        "links_without_auth": links_without,
    })
    await websocket.close()


# --- full: varios targets en paralelo + correlación cross-server ---------

def _servers_from_config_json(raw: str) -> list[dict]:
    data = json.loads(raw)
    servers = data.get("mcpServers") or data.get("mcp_servers") or {}
    out = []
    for name, cfg in servers.items():
        if not isinstance(cfg, dict):
            continue
        out.append({
            "server_name": name, "command": cfg.get("command"),
            "args": cfg.get("args", []), "url": cfg.get("url") or cfg.get("serverUrl"),
            "headers": cfg.get("headers"),
        })
    return out


async def _run_full_target(sem: asyncio.Semaphore, params: dict, mode: str, server: dict,
                            scan_id: str, results: list, emit):
    name = server.get("server_name") or server.get("command") or server.get("url") or "target"
    async with sem:
        if server.get("url"):
            transport, connection = "http", {"url": server["url"]}
            if server.get("headers"):
                connection["headers"] = server["headers"]
        elif server.get("command"):
            transport, connection = "stdio", {"command": server["command"], "args": server.get("args") or []}
        else:
            results.append({"name": name, "error": "sin command ni url"})
            emit({"type": "target_error", "target": name, "error": "sin command ni url"})
            return

        config = _build_config(params, name, transport, connection, mode=mode)

        def progress(event: dict):
            emit({"type": "progress", "target": name, "event": event})

        try:
            report = await run_scan(config, progress_cb=progress)
            baseline_line = await _apply_baseline_and_webhook(report, config, None)  # webhook agregado, no por target
            if baseline_line:
                emit({"type": "progress", "target": name, "event": {"type": "log", "message": baseline_line}})

            safe_name = re.sub(r"[^\w.-]+", "_", str(name)) or "target"
            links = await _persist_report(scan_id, f".{safe_name}", report)
            _add_index_entry({
                "scan_id": scan_id, "target_name": name,
                "started_at": report.started_at, "finished_at": report.finished_at,
                "score": report.score, "policy_verdict": report.policy_verdict,
                "compare_auth": False, "mode": mode, "batch_id": scan_id,
                "links": links,
                "saved_at": datetime.now(timezone.utc).isoformat(),
            })
            entry = {
                "name": name, "summary": report.summary(), "score": report.score,
                "policy_verdict": report.policy_verdict, "links": links,
                "baseline_diff": report.baseline_diff, "tools_enumerated": report.tools_enumerated,
            }
            results.append(entry)
            emit({"type": "target_done", "target": name, **{k: v for k, v in entry.items() if k != "tools_enumerated"}})
        except Exception as e:
            results.append({"name": name, "error": str(e)})
            emit({"type": "target_error", "target": name, "error": str(e)})


@app.websocket("/ws/full")
async def ws_full(websocket: WebSocket):
    if not websocket_token_ok(websocket):
        await websocket.close(code=1008)
        return
    await websocket.accept()
    try:
        raw = await websocket.receive_text()
        params = json.loads(raw)
    except Exception as e:
        await websocket.send_json({"type": "fatal_error", "error": f"config inválida: {e}"})
        await websocket.close()
        return

    try:
        config_json = (params.get("full_config_json") or "").strip()
        if config_json:
            servers = _servers_from_config_json(config_json)
        else:
            servers = params.get("full_selected_targets") or []
        if not servers:
            await websocket.send_json({"type": "fatal_error", "error": "ningún target seleccionado para 'full' (tildá servers descubiertos o pegá un config JSON)"})
            await websocket.close()
            return
        mode = params.get("full_mode") or "vet"
        concurrency = max(1, int(params.get("concurrency") or 3))
    except Exception as e:
        await websocket.send_json({"type": "fatal_error", "error": f"no se pudo armar la corrida full: {e}"})
        await websocket.close()
        return

    scan_id = uuid.uuid4().hex[:8]
    queue: asyncio.Queue = asyncio.Queue()

    def emit(event: dict):
        queue.put_nowait(event)

    results: list = []
    sem = asyncio.Semaphore(concurrency)

    async def run_all():
        await asyncio.gather(*(
            _run_full_target(sem, params, mode, s, scan_id, results, emit) for s in servers
        ))

    task = asyncio.create_task(run_all())

    try:
        while not task.done():
            try:
                event = await asyncio.wait_for(queue.get(), timeout=0.2)
                await websocket.send_json(event)
            except asyncio.TimeoutError:
                continue
        while not queue.empty():
            await websocket.send_json(queue.get_nowait())
        task.result()
    except WebSocketDisconnect:
        task.cancel()
        return
    except Exception as e:
        await websocket.send_json({"type": "fatal_error", "error": str(e)})
        await websocket.close()
        return

    ok_results = [r for r in results if "error" not in r]
    cross_server = None
    cross_server_report_summary = None
    if len(ok_results) >= 2:
        reports_by_server = {r["name"]: r.get("tools_enumerated") or [] for r in ok_results}
        cross_server = analyze_cross_server(reports_by_server)
        if cross_server:
            cs_dir = os.path.join(REPORTS_DIR, scan_id)
            os.makedirs(cs_dir, exist_ok=True)
            with open(os.path.join(cs_dir, "cross_server_correlation.json"), "w", encoding="utf-8") as f:
                json.dump(cross_server, f, indent=2, ensure_ascii=False)

            # mismo fix que cli/main.py::_run_cross_server_correlation -- antes esto nunca
            # pasaba por calculate_score/PolicyEngine/SARIF, aunque el propio dict ya marca
            # severity='critical' para directive_cross_reference. Ver engine/crossserver.py.
            cs_findings = cross_server_findings(reports_by_server)
            cs_report = ScanReport(
                scan_id=f"{scan_id}-cross", target_name="(correlación cross-server)",
                started_at=datetime.now(timezone.utc).isoformat(), ares_version="",
                findings=cs_findings,
            )
            cs_report.finished_at = datetime.now(timezone.utc).isoformat()
            cs_report.score = calculate_score(cs_report)
            cs_report.policy_verdict = PolicyEngine().evaluate(cs_report, params.get("environment") or "production")
            safe_cs_report = redact_report(cs_report)
            with open(os.path.join(cs_dir, "cross_server_correlation_report.json"), "w", encoding="utf-8") as f:
                json.dump(safe_cs_report.to_dict(), f, indent=2, ensure_ascii=False, default=str)
            save_html_report(safe_cs_report, os.path.join(cs_dir, "cross_server_correlation.html"))
            save_sarif_report(safe_cs_report, os.path.join(cs_dir, "cross_server_correlation.sarif"))
            cross_server_report_summary = {"score": cs_report.score, "policy": cs_report.policy_verdict}

    await websocket.send_json({
        "type": "full_done",
        "scan_id": scan_id,
        "results": [{k: v for k, v in r.items() if k != "tools_enumerated"} for r in results],
        "cross_server": cross_server,
        "cross_server_report": cross_server_report_summary,
    })
    await websocket.close()
