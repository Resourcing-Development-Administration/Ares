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
from typing import Any

import httpx
from fastapi import Body, Depends, FastAPI, HTTPException, Request, WebSocket, WebSocketDisconnect, status
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse

from engine.auth.auth import validate_token, create_token, verify_password, get_admin_hash
from engine.auth.login_limit import LoginLimiter
from engine.core.models import ScanConfig, AuthConfig, ScanReport
from engine.core.tls import resolve_ca_bundle
from engine.core.sandbox import DEFAULT_MEM_MB as DEFAULT_SANDBOX_MEM_MB
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

# --- Auth layer ------------------------------------------------------------------

from engine.core.env_scrub import scrub_env as _scrub_env
_scrub_env()

_login_limiter = LoginLimiter()


async def _require_auth(request: Request) -> str:
    """Dependency de FastAPI que valida Bearer JWT."""
    auth = request.headers.get("Authorization", "")
    token = auth.removeprefix("Bearer ").strip()
    if not token:
        # Chequear también cookie "ares_token"
        token = request.cookies.get("ares_token", "")
    if not token:
        raise HTTPException(401, "No autenticado")
    return validate_token(token)["sub"]


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


MAX_INDEX_ENTRIES = 200  # tope histórico del index -- ver _add_index_entry


def _delete_report_dir(scan_id: str):
    """Borra reports/<scan_id>/ del disco -- separado de _save_index para que tanto el
    cap automático como el borrado manual (DELETE /api/reports/{id}) y la purga masiva
    usen el mismo camino y no dejen carpetas huérfanas (bug real de antes: el cap de
    _add_index_entry solo recortaba el index.json, nunca el directorio en disco -- un
    reporte #201+ en adelante quedaba invisible en la UI pero SEGUÍA ocupando espacio
    para siempre, sin ninguna forma de encontrarlo para borrarlo a mano)."""
    import shutil
    scan_dir = os.path.join(REPORTS_DIR, scan_id)
    if os.path.isdir(scan_dir):
        shutil.rmtree(scan_dir, ignore_errors=True)


def _add_index_entry(entry: dict):
    entries = _load_index()
    entries.insert(0, entry)
    # El cap nunca saca un entry fijado ("pinned": true) -- esa es la garantía completa de
    # fijar un reporte: sin esto, un reporte importante fijado hoy igual podía desaparecer
    # más tarde si se acumulaban 200 corridas nuevas encima. Se recorta primero lo NO
    # fijado, más viejo primero (la lista ya viene más-nuevo-primero por el insert(0,...)
    # de arriba, así que lo no-fijado al final de la lista es lo más viejo).
    pinned = [e for e in entries if e.get("pinned")]
    unpinned = [e for e in entries if not e.get("pinned")]
    keep_unpinned_budget = max(0, MAX_INDEX_ENTRIES - len(pinned))
    to_drop = unpinned[keep_unpinned_budget:]
    kept_ids = {e["scan_id"] for e in pinned} | {e["scan_id"] for e in unpinned[:keep_unpinned_budget]}
    for e in to_drop:
        _delete_report_dir(e["scan_id"])
    _save_index([e for e in entries if e["scan_id"] in kept_ids])


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


def _resolve_oauth2_token(params: dict) -> str | None:
    """Mismo flujo que la CLI (ver cli/main.py::_resolve_oauth2_token): si se dio
    oauth2_token_url, resuelve un access_token real vía client_credentials. Lanza
    ValueError (lo atrapa el caller y lo devuelve como error de config) si faltan
    client_id/client_secret o si el provider rechaza las credenciales."""
    token_url = (params.get("oauth2_token_url") or "").strip()
    if not token_url:
        return None
    client_id = params.get("oauth2_client_id")
    client_secret = params.get("oauth2_client_secret")
    if not client_id or not client_secret:
        raise ValueError("--oauth2-token-url requiere oauth2_client_id y oauth2_client_secret")
    from engine.core.oauth import fetch_client_credentials_token
    try:
        return fetch_client_credentials_token(token_url, client_id, client_secret, scope=params.get("oauth2_scope") or None)
    except RuntimeError as e:
        raise ValueError(str(e))


def _build_config(params: dict, target_name: str, transport: str, connection: dict, mode: str = "scan") -> ScanConfig:
    connection = dict(connection)
    headers = {}
    for line in (params.get("headers_raw") or "").splitlines():
        if ":" in line:
            k, v = line.split(":", 1)
            headers[k.strip()] = v.strip()
    if headers:
        connection.setdefault("headers", {}).update(headers)

    oauth2_token = _resolve_oauth2_token(params)
    auth = None
    if oauth2_token:
        auth = AuthConfig(type="bearer", token=oauth2_token)
    elif params.get("auth_token"):
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
        proxy=params.get("proxy") or None,
        client_cert=params.get("client_cert") or None,
        client_key=params.get("client_key") or None,
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
        sandbox_mem_mb=int(params.get("sandbox_mem_mb") or DEFAULT_SANDBOX_MEM_MB),
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

@app.post("/api/login")
async def api_login(request: Request, body: dict = Body(...)):
    ip = request.client.host if request.client else "unknown"
    if not _login_limiter.check_allowed(ip):
        raise HTTPException(429, "Demasiados intentos. Espera antes de reintentar.")
    username = body.get("username", "admin")
    password = body.get("password", "")
    if not verify_password(password, get_admin_hash()):
        _login_limiter.record_failure(ip)
        raise HTTPException(401, "Credenciales incorrectas")
    _login_limiter.clear_success(ip)
    token = create_token(username)
    return {"token": token, "token_type": "bearer"}


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
            "requires_network": m.requires_network, "level": m.level,
        }
        for m in sorted(list_meta(), key=lambda m: (m.level, m.category.value, m.id))
    ]


@app.get("/api/api-tests")
async def api_api_tests():
    """Tests del módulo de APIs (REST/GraphQL) -- mismo shape que /api/tests, + 'kind'
    (rest|graphql) para que el front los agrupe aparte."""
    from engine.api.registry import all_api_tests
    return [
        {
            "id": m.id, "name": m.name, "category": m.category.value,
            "description": m.description, "default_enabled": m.default_enabled,
            "requires_network": m.requires_network, "level": m.level,
            "kind": getattr(m, "kind", "rest"),
        }
        for m, _ in sorted(all_api_tests().values(), key=lambda mf: (getattr(mf[0], "kind", "rest"), mf[0].id))
    ]


@app.get("/api/netrecon-tests")
async def api_netrecon_tests():
    """Tests del módulo de reconocimiento de red -- mismo shape que /api/tests."""
    import engine.netrecon.tests  # noqa: F401 — fuerza el registro
    from engine.netrecon.registry import list_net_meta
    return [
        {
            "id": m.id, "name": m.name, "category": m.category.value,
            "description": m.description, "default_enabled": True,
            "requires_network": m.requires_network, "level": m.level,
        }
        for m in list_net_meta()
    ]


@app.get("/api/tools-status")
async def api_tools_status():
    """Estado de los binarios de herramientas de red gestionados por Ares."""
    from engine.tools.paths import tools_status
    return tools_status()


@app.post("/api/install-tools")
async def api_install_tools(request: Request, _user: str = Depends(_require_auth)):
    """Instala (o reinstala con force=true) los binarios de herramientas de red.
    Body JSON: {"tools": ["nuclei", ...], "force": false}
    Responde con {ok: true, errors: {}} o {ok: false, errors: {...}}."""
    body = await request.json()
    tools = body.get("tools") or None
    force = bool(body.get("force", False))

    from engine.tools.installer import install_all
    errors = await asyncio.get_event_loop().run_in_executor(
        None, lambda: install_all(tools=tools, force=force)
    )
    return {"ok": not errors, "errors": errors}


@app.get("/api/levels")
async def api_levels():
    from engine.core.models import LEVEL_NAMES, LEVEL_DESCRIPTIONS
    return [{"level": n, "name": LEVEL_NAMES[n], "description": LEVEL_DESCRIPTIONS[n]} for n in (1, 2, 3, 4)]


@app.get("/api/discover")
async def api_discover():
    return discover_mcp_servers()


@app.post("/api/maintenance/update-rules")
async def api_update_rules():
    """Equivalente a `ares update-rules`: refresca el cache local de patrones de secretos
    desde gitleaks.toml (público, sin API key). Única operación de este grupo que escribe algo
    (el cache que ya usa supplychain.secret_exposure); check-frameworks/check-lists son de solo
    lectura. Sin esto, un operador que solo usa el dashboard nunca se enteraría de que hace
    falta correr esto a mano por CLI para no quedar con patrones de secretos desactualizados."""
    from engine.supplychain.rule_sources import fetch_gitleaks_patterns, save_cache, cache_info
    try:
        patterns = await fetch_gitleaks_patterns()
    except Exception as e:
        return JSONResponse({"error": str(e)}, status_code=502)
    save_cache(patterns, source="gitleaks")
    return cache_info()


@app.get("/api/maintenance/check-frameworks")
async def api_check_frameworks():
    from engine.core.framework_watch import check_for_updates
    try:
        results = await check_for_updates()
    except Exception as e:
        return JSONResponse({"error": str(e)}, status_code=502)
    return {"results": results, "any_alert": any(r["status"] == "POSIBLE_ACTUALIZACION" for r in results)}


@app.get("/api/maintenance/check-lists")
async def api_check_lists():
    from engine.core.list_watch import check_all_lists, STATUS_BAD
    try:
        rows = await check_all_lists()
    except Exception as e:
        return JSONResponse({"error": str(e)}, status_code=502)
    return {"rows": rows, "bad": [r for r in rows if r["status"] in STATUS_BAD]}


@app.get("/api/reports")
async def api_reports():
    return _load_index()


@app.post("/api/reports/{scan_id}/pin")
async def api_pin_report(scan_id: str, request: Request):
    """Fija/desfija un reporte. Fijado = nunca lo saca el cap automático de
    _add_index_entry ni lo toca /api/reports/purge -- la decisión de "conservar esto"
    la toma la persona, no un timer. Sin decisión (queda sin fijar), eventualmente
    se lo lleva el cap o una purga manual -- ver _add_index_entry más arriba."""
    body = await request.json()
    pinned = bool(body.get("pinned", True))
    entries = _load_index()
    for e in entries:
        if e["scan_id"] == scan_id:
            e["pinned"] = pinned
            _save_index(entries)
            return {"scan_id": scan_id, "pinned": pinned}
    return JSONResponse({"error": "scan_id no encontrado"}, status_code=404)


@app.delete("/api/reports/{scan_id}")
async def api_delete_report(scan_id: str, force: bool = False):
    """Borra un reporte (index + carpeta en disco). Si está fijado, exige
    ?force=true -- fijar es justamente la protección contra un borrado por error;
    saltearla en silencio la volvería inútil."""
    entries = _load_index()
    match = next((e for e in entries if e["scan_id"] == scan_id), None)
    if match is None:
        return JSONResponse({"error": "scan_id no encontrado"}, status_code=404)
    if match.get("pinned") and not force:
        return JSONResponse(
            {"error": "este reporte está fijado -- desfijalo antes de borrarlo (o pasá ?force=true)"},
            status_code=409,
        )
    _delete_report_dir(scan_id)
    _save_index([e for e in entries if e["scan_id"] != scan_id])
    return {"scan_id": scan_id, "deleted": True}


@app.patch("/api/findings/{finding_id}")
async def api_patch_finding(finding_id: str, request: Request):
    """Actualiza campos de verificación/triage de un finding en su reporte JSON.

    Campos aceptados: verification_status, verification_note, counterevidence,
    confidence_rationale, triage_status, poe_level.
    """
    _ALLOWED = {
        "verification_status", "verification_note", "counterevidence",
        "confidence_rationale", "triage_status", "poe_level",
    }
    body = await request.json()
    updates = {k: v for k, v in body.items() if k in _ALLOWED}
    if not updates:
        return JSONResponse({"error": "sin campos válidos para actualizar"}, status_code=400)

    # buscar el reporte que contiene este finding_id
    entries = _load_index()
    for entry in entries:
        scan_id = entry["scan_id"]
        report_path = os.path.join(REPORTS_DIR, scan_id, "report.json")
        if not os.path.exists(report_path):
            continue
        try:
            with open(report_path, encoding="utf-8") as fh:
                report_data = json.load(fh)
        except Exception:
            continue
        findings = report_data.get("findings", [])
        for f in findings:
            if f.get("id") == finding_id:
                f.update(updates)
                with open(report_path, "w", encoding="utf-8") as fh:
                    json.dump(report_data, fh, ensure_ascii=False, indent=2)
                return {"finding_id": finding_id, "updated": updates}

    return JSONResponse({"error": f"finding '{finding_id}' no encontrado"}, status_code=404)


@app.post("/api/reports/purge")
async def api_purge_reports(request: Request):
    """Borra en bloque los reportes NO fijados más viejos que older_than_days. Nunca
    toca un fijado, pase lo que pase -- mismo criterio que el cap automático."""
    body = await request.json()
    older_than_days = float(body.get("older_than_days", 30))
    cutoff = datetime.now(timezone.utc).timestamp() - older_than_days * 86400
    entries = _load_index()
    kept, deleted = [], []
    for e in entries:
        if e.get("pinned"):
            kept.append(e)
            continue
        ts = e.get("started_at") or e.get("saved_at") or ""
        try:
            age_ts = datetime.fromisoformat(ts.replace("Z", "+00:00")).timestamp()
        except (ValueError, TypeError):
            kept.append(e)  # fecha ilegible -- no borrar a ciegas, mejor conservar
            continue
        if age_ts < cutoff:
            _delete_report_dir(e["scan_id"])
            deleted.append(e["scan_id"])
        else:
            kept.append(e)
    _save_index(kept)
    return {"deleted": deleted, "deleted_count": len(deleted), "remaining": len(kept)}


def _build_api_scan_config(params: dict) -> dict:
    """kwargs para engine.api.runner.run_api_scan a partir de los params del form del dashboard.
    Reusa los MISMOS campos de auth_type/auth_token/auth_header_name(_b) que ws_scan -- misma
    semántica, mismos inputs del HTML (ver toggleAuthFields)."""
    def auth_headers(token, atype, header_name):
        if not token:
            return None
        if atype == "bearer":
            return {"Authorization": f"Bearer {token}"}
        if atype == "basic":
            import base64
            user_pass = token if ":" in token else f"{token}:"
            return {"Authorization": f"Basic {base64.b64encode(user_pass.encode()).decode()}"}
        return {(header_name or "X-API-Key"): token}

    headers = {}
    for line in (params.get("headers_raw") or "").splitlines():
        if ":" in line:
            k, v = line.split(":", 1)
            headers[k.strip()] = v.strip()

    oauth2_token = _resolve_oauth2_token(params)
    auth_a = {"Authorization": f"Bearer {oauth2_token}"} if oauth2_token else \
        auth_headers(params.get("auth_token"), params.get("auth_type"), params.get("auth_header_name"))

    selected = params.get("tests") or None
    return dict(
        base_url=params["url"], spec_source=params.get("spec") or None,
        graphql_path=params.get("graphql_path") or None, selected_tests=selected,
        headers=headers or None,
        auth_a=auth_a,
        auth_b=auth_headers(params.get("auth_token_b"), params.get("auth_type_b"), params.get("auth_header_name_b")),
        jwt=params.get("jwt") or params.get("auth_token") or None,
        verify=_resolve_ca_bundle(params.get("ca_bundle")) if params.get("ca_bundle") else True,
        _trust_presented_cert=bool(params.get("trust_presented_cert")),
        proxy=params.get("proxy") or None,
        client_cert=params.get("client_cert") or None,
        client_key=params.get("client_key") or None,
        delay_ms=int(params.get("request_delay_ms") or 0),
        max_fuzz=int(params.get("max_fuzz_cases") or 40),
        test_timeout_s=float(params.get("test_timeout_s") or 60.0),
        allowlist_path=params.get("allowlist_path") or default_allowlist_path(),
        min_confidence=params.get("min_confidence") or "heuristic",
        environment=params.get("environment") or "production",
    )


@app.websocket("/ws/api_scan")
async def ws_api_scan(websocket: WebSocket):
    """Equivalente a ws_scan pero para el módulo de APIs (engine/api/runner.py::run_api_scan) --
    mismo vocabulario de eventos de progreso, mismo shape de reporte final, así el JS existente
    (log()/renderResult()) funciona sin cambios."""
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

    if not params.get("url"):
        await websocket.send_json({"type": "fatal_error", "error": "falta la URL de la API"})
        await websocket.close()
        return

    try:
        kwargs = _build_api_scan_config(params)
    except Exception as e:
        await websocket.send_json({"type": "fatal_error", "error": f"no se pudo armar la config: {e}"})
        await websocket.close()
        return

    from engine.api.runner import run_api_scan
    from engine.core.tls import fetch_presented_cert_pem

    # --trust-presented-cert: mismo pinning TOFU que ws_scan/scan/vet/full (ver
    # engine/orchestrator.py) -- antes solo existía como campo HTML sin equivalente en el
    # modo API del dashboard.
    want_pin = kwargs.pop("_trust_presented_cert", False)
    pinned_cert_file = None
    cert_pin_note = None
    if want_pin and kwargs.get("verify") is True and kwargs["base_url"].startswith("https://"):
        pinned_cert_file = fetch_presented_cert_pem(kwargs["base_url"])
        if pinned_cert_file:
            kwargs["verify"] = pinned_cert_file
            cert_pin_note = (
                "--trust-presented-cert: se fijó (pinning TOFU) el certificado que presentó el server "
                "para poder conectarse y auditar. Esto NO valida su identidad contra una CA de confianza "
                "-- si ya había un MITM, se fijó el cert del atacante."
            )
        else:
            cert_pin_note = "--trust-presented-cert: no se pudo obtener el certificado presentado por el server."

    queue: asyncio.Queue = asyncio.Queue()

    def progress(event: dict):
        queue.put_nowait(event)

    task = asyncio.create_task(run_api_scan(progress_cb=progress, **kwargs))

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
        report = task.result()
        if cert_pin_note:
            report.errors.append(cert_pin_note)
    except WebSocketDisconnect:
        task.cancel()
        return
    except Exception as e:
        await websocket.send_json({"type": "fatal_error", "error": str(e)})
        await websocket.close()
        return
    finally:
        if pinned_cert_file:
            try:
                os.unlink(pinned_cert_file)
            except OSError:
                pass

    scan_id = report.scan_id or uuid.uuid4().hex[:8]
    links = await _persist_report(scan_id, "", report, mode="api-scan")
    asyncio.create_task(_notify_scan(report, links, mode="api-scan"))
    _add_index_entry({
        "scan_id": scan_id, "target_name": report.target_name, "started_at": report.started_at,
        "finished_at": report.finished_at, "score": report.score, "policy_verdict": report.policy_verdict,
        "compare_auth": False, "mode": "api-scan", "links": links,
        "saved_at": datetime.now(timezone.utc).isoformat(),
    })

    await websocket.send_json({
        "type": "done", "scan_id": scan_id, "summary": report.summary(), "score": report.score,
        "policy_verdict": report.policy_verdict, "auth_impact": None, "baseline_diff": None,
        "tls_certificate": None, "incomplete_reason": None, "links": links, "links_without_auth": None,
    })
    await websocket.close()


@app.websocket("/ws/netrecon")
async def ws_netrecon(websocket: WebSocket):
    """Reconocimiento de red activo (httpx + subfinder + nuclei + katana).
    Mismo protocolo de eventos que /ws/api_scan -- el JS existente funciona sin cambios."""
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

    target_url = (params.get("net_target") or "").strip()
    if not target_url:
        await websocket.send_json({"type": "fatal_error", "error": "falta la URL del target de red (net_target)"})
        await websocket.close()
        return

    scope_raw = (params.get("net_scope") or "").strip()
    scope = [s.strip() for s in scope_raw.split(",") if s.strip()] if scope_raw else None
    selected = params.get("tests") or None
    sev_raw = (params.get("net_nuclei_severity") or "critical,high,medium").strip()
    severities = [s.strip() for s in sev_raw.split(",") if s.strip()]
    timeout_s  = int(params.get("net_timeout_s") or 180)
    rate_limit = int(params.get("net_rate_limit") or 150)
    environment    = params.get("environment") or "production"
    min_confidence = params.get("min_confidence") or "heuristic"
    allowlist_path = params.get("allowlist_path") or None

    from engine.netrecon.runner import run_netrecon_scan

    queue: asyncio.Queue = asyncio.Queue()

    def progress(event: dict):
        queue.put_nowait(event)

    task = asyncio.create_task(run_netrecon_scan(
        target_url=target_url,
        scope=scope,
        selected_tests=selected,
        nuclei_severity=severities,
        timeout_s=timeout_s,
        rate_limit=rate_limit,
        min_confidence=min_confidence,
        environment=environment,
        allowlist_path=allowlist_path,
        progress_cb=progress,
    ))

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
        report = task.result()
    except WebSocketDisconnect:
        task.cancel()
        return
    except Exception as e:
        await websocket.send_json({"type": "fatal_error", "error": str(e)})
        await websocket.close()
        return

    scan_id = report.scan_id or uuid.uuid4().hex[:8]
    links = await _persist_report(scan_id, "", report, mode="netrecon")
    asyncio.create_task(_notify_scan(report, links, mode="netrecon"))
    _add_index_entry({
        "scan_id": scan_id, "target_name": report.target_name,
        "started_at": report.started_at, "finished_at": report.finished_at,
        "score": report.score, "policy_verdict": report.policy_verdict,
        "compare_auth": False, "mode": "netrecon", "links": links,
        "saved_at": datetime.now(timezone.utc).isoformat(),
    })

    await websocket.send_json({
        "type": "done", "scan_id": scan_id, "summary": report.summary(),
        "score": report.score, "policy_verdict": report.policy_verdict,
        "auth_impact": None, "baseline_diff": None,
        "tls_certificate": None, "incomplete_reason": None,
        "links": links, "links_without_auth": None,
    })
    await websocket.close()


@app.websocket("/ws/agent_scan")
async def ws_agent_scan(websocket: WebSocket):
    """Scan autónomo dirigido por LLM (Claude).
    Protocolo de eventos idéntico a /ws/netrecon con eventos adicionales:
    agent_round, agent_thinking, agent_tool_call, agent_finished, gate_denied."""
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

    target_url = (params.get("agent_target") or "").strip()
    if not target_url:
        await websocket.send_json({"type": "fatal_error",
                                   "error": "falta la URL del target (agent_target)"})
        await websocket.close()
        return

    scope_raw = (params.get("agent_scope") or "").strip()
    scope = [s.strip() for s in scope_raw.split(",") if s.strip()] if scope_raw else None

    denylist_raw = (params.get("agent_denylist") or "").strip()
    denylist = [s.strip() for s in denylist_raw.split(",") if s.strip()] if denylist_raw else None

    model        = (params.get("agent_model") or "").strip() or None
    provider     = (params.get("agent_provider") or "auto").strip()
    max_rounds   = int(params.get("agent_max_rounds") or 8)
    goal         = (params.get("agent_goal") or "").strip() or None
    allow_level3 = bool(params.get("agent_allow_level3"))
    timeout_s    = int(params.get("agent_timeout_s") or 180)
    rate_limit   = int(params.get("agent_rate_limit") or 150)
    enable_proxy = bool(params.get("agent_enable_proxy"))
    use_v2       = bool(params.get("use_v2"))
    environment    = params.get("environment") or "production"
    min_confidence = params.get("min_confidence") or "heuristic"
    allowlist_path = params.get("allowlist_path") or None

    try:
        if use_v2:
            from engine.agent.orchestrator_v2 import run_agent_scan_v2
        else:
            from engine.agent.orchestrator import run_agent_scan
    except ImportError as e:
        await websocket.send_json({"type": "fatal_error", "error": str(e)})
        await websocket.close()
        return

    queue: asyncio.Queue = asyncio.Queue()
    # side_question_queue: el agente deposita (question, urgency, future)
    # el WS loop lo recibe, envía al cliente, espera la respuesta y resuelve el future
    sq_queue: asyncio.Queue = asyncio.Queue()

    def progress(event: dict):
        queue.put_nowait(event)

    async def side_question_cb(question: str, urgency: str = "informational") -> str:
        fut: asyncio.Future = asyncio.get_event_loop().create_future()
        sq_queue.put_nowait((question, urgency, fut))
        try:
            answer = await asyncio.wait_for(fut, timeout=300)  # 5 min para que el operador responda
            return answer
        except asyncio.TimeoutError:
            return "(tiempo de espera agotado — continuando sin respuesta)"

    if use_v2:
        task = asyncio.create_task(run_agent_scan_v2(
            target_url=target_url,
            scope=scope,
            goal=goal,
            model=model,
            provider=provider,
            timeout_s=timeout_s,
            rate_limit=rate_limit,
            min_confidence=min_confidence,
            environment=environment,
            allow_level3=allow_level3,
            enable_proxy=enable_proxy,
            denylist=denylist,
            allowlist_path=allowlist_path,
            progress_cb=progress,
        ))
    else:
        task = asyncio.create_task(run_agent_scan(
            target_url=target_url,
            scope=scope,
            goal=goal,
            model=model,
            provider=provider,
            max_rounds=max_rounds,
            timeout_s=timeout_s,
            rate_limit=rate_limit,
            min_confidence=min_confidence,
            environment=environment,
            allow_level3=allow_level3,
            enable_proxy=enable_proxy,
            denylist=denylist,
            allowlist_path=allowlist_path,
            side_question_cb=side_question_cb,
            progress_cb=progress,
        ))

    try:
        while not task.done():
            # despachar side questions pendientes
            while not sq_queue.empty():
                question, urgency, fut = sq_queue.get_nowait()
                await websocket.send_json({
                    "type": "side_question",
                    "question": question,
                    "urgency": urgency,
                })
                # esperar la respuesta del cliente (con timeout corto para no bloquear el loop)
                try:
                    raw_answer = await asyncio.wait_for(
                        websocket.receive_text(), timeout=300
                    )
                    answer_data = json.loads(raw_answer)
                    answer = answer_data.get("answer", "(sin respuesta)")
                except (asyncio.TimeoutError, Exception):
                    answer = "(tiempo de espera agotado)"
                if not fut.done():
                    fut.set_result(answer)

            try:
                event = await asyncio.wait_for(queue.get(), timeout=0.2)
                await websocket.send_json({"type": "progress", "event": event})
            except asyncio.TimeoutError:
                continue
        while not queue.empty():
            event = queue.get_nowait()
            await websocket.send_json({"type": "progress", "event": event})
        report = task.result()
    except WebSocketDisconnect:
        task.cancel()
        return
    except Exception as e:
        await websocket.send_json({"type": "fatal_error", "error": str(e)})
        await websocket.close()
        return

    scan_id = report.scan_id or uuid.uuid4().hex[:8]
    links = await _persist_report(scan_id, "", report, mode="agent-scan")
    _add_index_entry({
        "scan_id": scan_id, "target_name": report.target_name,
        "started_at": report.started_at, "finished_at": report.finished_at,
        "score": report.score, "policy_verdict": report.policy_verdict,
        "compare_auth": False, "mode": "agent-scan", "links": links,
        "saved_at": datetime.now(timezone.utc).isoformat(),
    })

    # notificaciones post-scan (best-effort, no bloquea la respuesta)
    asyncio.create_task(_notify_scan(report, links, mode="agent-scan"))

    await websocket.send_json({
        "type": "done", "scan_id": scan_id, "summary": report.summary(),
        "score": report.score, "policy_verdict": report.policy_verdict,
        "auth_impact": None, "baseline_diff": None,
        "tls_certificate": None, "incomplete_reason": None,
        "links": links, "links_without_auth": None,
    })
    await websocket.close()


async def _notify_scan(report, links: dict, mode: str = "scan") -> None:
    try:
        from engine.notify.notifier import Notifier
        notifier = Notifier.from_env()
        if notifier._cfg.any_configured:
            scan_url = links.get("html")
            await notifier.notify_scan_complete(report, scan_url=scan_url)
    except Exception:
        pass


# ─── Scheduler API ──────────────────────────────────────────────────────────

_scheduler: "Any | None" = None  # ScanScheduler, inicializado lazy

def _get_scheduler():
    global _scheduler
    if _scheduler is None:
        from engine.scheduler.scheduler import ScanScheduler
        _scheduler = ScanScheduler(REPORTS_DIR)
    return _scheduler


@app.get("/api/schedules")
async def api_list_schedules(request: Request):
    if not _token_ok(request.headers.get("X-Ares-Token") or request.query_params.get("token")):
        return JSONResponse({"error": "unauthorized"}, status_code=401)
    sched = _get_scheduler()
    from dataclasses import asdict
    return JSONResponse([asdict(e) for e in sched.list_all()])


@app.post("/api/schedules")
async def api_create_schedule(request: Request):
    if not _token_ok(request.headers.get("X-Ares-Token") or request.query_params.get("token")):
        return JSONResponse({"error": "unauthorized"}, status_code=401)
    try:
        body = await request.json()
    except Exception:
        return JSONResponse({"error": "body inválido"}, status_code=400)
    from engine.scheduler.scheduler import ScanScheduler, ScheduleEntry
    import uuid as _uuid
    sched = _get_scheduler()
    entry = ScheduleEntry(
        id=body.get("id") or _uuid.uuid4().hex[:8],
        cron=body.get("cron", "0 2 * * *"),
        scan_type=body.get("scan_type", "netrecon"),
        params=body.get("params", {}),
        enabled=body.get("enabled", True),
        notify_on_regression=body.get("notify_on_regression", True),
        notify_webhook=body.get("notify_webhook"),
    )
    result = sched.add(entry)
    from dataclasses import asdict
    return JSONResponse(asdict(result))


@app.delete("/api/schedules/{schedule_id}")
async def api_delete_schedule(schedule_id: str, request: Request):
    if not _token_ok(request.headers.get("X-Ares-Token") or request.query_params.get("token")):
        return JSONResponse({"error": "unauthorized"}, status_code=401)
    sched = _get_scheduler()
    ok = sched.delete(schedule_id)
    if not ok:
        return JSONResponse({"error": "schedule no encontrado"}, status_code=404)
    return JSONResponse({"deleted": schedule_id})


@app.patch("/api/schedules/{schedule_id}")
async def api_update_schedule(schedule_id: str, request: Request):
    if not _token_ok(request.headers.get("X-Ares-Token") or request.query_params.get("token")):
        return JSONResponse({"error": "unauthorized"}, status_code=401)
    try:
        body = await request.json()
    except Exception:
        return JSONResponse({"error": "body inválido"}, status_code=400)
    sched = _get_scheduler()
    result = sched.update(schedule_id, **body)
    if not result:
        return JSONResponse({"error": "schedule no encontrado"}, status_code=404)
    from dataclasses import asdict
    return JSONResponse(asdict(result))


# ─── Findings triage API ─────────────────────────────────────────────────────

@app.get("/api/findings/{scan_id}")
async def api_get_findings(scan_id: str, request: Request):
    if not _token_ok(request.headers.get("X-Ares-Token") or request.query_params.get("token")):
        return JSONResponse({"error": "unauthorized"}, status_code=401)
    report_path = os.path.join(REPORTS_DIR, scan_id, "report.json")
    if not os.path.exists(report_path):
        return JSONResponse({"error": "scan_id not found"}, status_code=404)
    try:
        with open(report_path, encoding="utf-8") as fh:
            report = json.load(fh)
        findings = report.get("findings", [])
        return JSONResponse({"scan_id": scan_id, "total": len(findings), "findings": findings})
    except Exception as e:
        return JSONResponse({"error": str(e)}, status_code=500)


@app.patch("/api/findings/{scan_id}/{finding_index}")
async def api_patch_finding(scan_id: str, finding_index: int, request: Request):
    if not _token_ok(request.headers.get("X-Ares-Token") or request.query_params.get("token")):
        return JSONResponse({"error": "unauthorized"}, status_code=401)
    body = await request.json()
    report_path = os.path.join(REPORTS_DIR, scan_id, "report.json")
    if not os.path.exists(report_path):
        return JSONResponse({"error": "scan_id not found"}, status_code=404)
    try:
        with open(report_path, encoding="utf-8") as fh:
            report = json.load(fh)
        findings = report.get("findings", [])
        if finding_index < 0 or finding_index >= len(findings):
            return JSONResponse({"error": f"finding index {finding_index} out of range"}, status_code=404)
        allowed = {"triage_status", "notes", "suppressed"}
        for key, val in body.items():
            if key in allowed:
                findings[finding_index][key] = val
        with open(report_path, "w", encoding="utf-8") as fh:
            json.dump(report, fh, indent=2, ensure_ascii=False, default=str)
        return JSONResponse({"scan_id": scan_id, "index": finding_index, "finding": findings[finding_index]})
    except Exception as e:
        return JSONResponse({"error": str(e)}, status_code=500)


@app.get("/api/findings/search")
async def api_search_findings(
    request: Request,
    q: str = "",
    severity: str = "",
    triage_status: str = "",
    limit: int = 100,
):
    if not _token_ok(request.headers.get("X-Ares-Token") or request.query_params.get("token")):
        return JSONResponse({"error": "unauthorized"}, status_code=401)
    results = []
    index = _load_index()
    for entry in index[:50]:  # search last 50 scans
        sid = entry.get("scan_id", "")
        rp = os.path.join(REPORTS_DIR, sid, "report.json")
        if not os.path.exists(rp):
            continue
        try:
            with open(rp, encoding="utf-8") as fh:
                report = json.load(fh)
            for i, f in enumerate(report.get("findings", [])):
                if severity and f.get("severity", "") != severity:
                    continue
                if triage_status and f.get("triage_status", "") != triage_status:
                    continue
                if q:
                    blob = json.dumps(f).lower()
                    if q.lower() not in blob:
                        continue
                results.append({"scan_id": sid, "index": i, "finding": f})
                if len(results) >= limit:
                    break
        except Exception:
            pass
        if len(results) >= limit:
            break
    return JSONResponse({"total": len(results), "findings": results})


# ─── Custom Tools API ─────────────────────────────────────────────────────────

_custom_tool_store: "Any | None" = None


def _get_custom_tool_store():
    global _custom_tool_store
    if _custom_tool_store is None:
        from engine.tools.custom import CustomToolStore
        store_path = os.path.join(REPORTS_DIR, "custom_tools.json")
        _custom_tool_store = CustomToolStore(store_path=store_path)
    return _custom_tool_store


@app.get("/api/custom-tools")
async def api_list_custom_tools(request: Request):
    if not _token_ok(request.headers.get("X-Ares-Token") or request.query_params.get("token")):
        return JSONResponse({"error": "unauthorized"}, status_code=401)
    store = _get_custom_tool_store()
    return JSONResponse({"tools": [t.to_dict() for t in store.list_all()]})


@app.post("/api/custom-tools")
async def api_create_custom_tool(request: Request):
    if not _token_ok(request.headers.get("X-Ares-Token") or request.query_params.get("token")):
        return JSONResponse({"error": "unauthorized"}, status_code=401)
    from engine.tools.custom import CustomTool, CustomToolType
    body = await request.json()
    try:
        tool_type_val = body.get("tool_type", "command")
        body["tool_type"] = CustomToolType(tool_type_val)
        tool = CustomTool(**{k: v for k, v in body.items() if k != "id"})
        store = _get_custom_tool_store()
        created = store.add(tool)
        return JSONResponse(created.to_dict(), status_code=201)
    except ValueError as e:
        return JSONResponse({"error": str(e)}, status_code=400)
    except Exception as e:
        return JSONResponse({"error": str(e)}, status_code=500)


@app.patch("/api/custom-tools/{tool_id}")
async def api_update_custom_tool(tool_id: str, request: Request):
    if not _token_ok(request.headers.get("X-Ares-Token") or request.query_params.get("token")):
        return JSONResponse({"error": "unauthorized"}, status_code=401)
    body = await request.json()
    store = _get_custom_tool_store()
    updated = store.update(tool_id, **body)
    if updated is None:
        return JSONResponse({"error": "tool not found"}, status_code=404)
    return JSONResponse(updated.to_dict())


@app.delete("/api/custom-tools/{tool_id}")
async def api_delete_custom_tool(tool_id: str, request: Request):
    if not _token_ok(request.headers.get("X-Ares-Token") or request.query_params.get("token")):
        return JSONResponse({"error": "unauthorized"}, status_code=401)
    store = _get_custom_tool_store()
    ok = store.delete(tool_id)
    if not ok:
        return JSONResponse({"error": "tool not found"}, status_code=404)
    return JSONResponse({"deleted": tool_id})


@app.post("/api/custom-tools/{tool_id}/test")
async def api_test_custom_tool(tool_id: str, request: Request):
    if not _token_ok(request.headers.get("X-Ares-Token") or request.query_params.get("token")):
        return JSONResponse({"error": "unauthorized"}, status_code=401)
    body = await request.json()
    params = body.get("params", {})
    store = _get_custom_tool_store()
    tool = store.get(tool_id)
    if tool is None:
        return JSONResponse({"error": "tool not found"}, status_code=404)
    output = await store.execute(tool_id, params)
    return JSONResponse({"tool_id": tool_id, "output": output})


# ─── Extension traffic capture endpoint ──────────────────────────────────────
# Primary path: engine/traffic/external.py stores to SQLite via Traffic singleton.
# Fallback ring buffer kept for environments without the traffic store.

_capture_buffer: list[dict] = []
_CAPTURE_MAX = 10_000

# Lazy-import the traffic module so the server starts even without aiosqlite
def _get_traffic_store():
    try:
        from engine.traffic.traffic import get as _traffic_get
        return _traffic_get()
    except Exception:
        return None


@app.post("/api/capture")
async def api_capture(request: Request):
    try:
        event = await request.json()
    except Exception:
        return JSONResponse({"ok": False}, status_code=400)

    # Try to store in the SQLite traffic store first
    t = _get_traffic_store()
    if t is not None:
        try:
            from engine.traffic.external import record_external
            await asyncio.get_event_loop().run_in_executor(None, record_external, t, event)
            return JSONResponse({"ok": True, "backend": "sqlite"})
        except Exception:
            pass  # fall through to ring buffer

    # Fallback: ring buffer
    if len(_capture_buffer) < _CAPTURE_MAX:
        _capture_buffer.append(event)
    return JSONResponse({"ok": True, "backend": "buffer"})


@app.get("/api/capture")
async def api_get_captured(request: Request, limit: int = 200, clear: bool = False):
    if not _token_ok(request.headers.get("X-Ares-Token") or request.query_params.get("token")):
        return JSONResponse({"error": "unauthorized"}, status_code=401)
    items = _capture_buffer[-limit:]
    if clear:
        _capture_buffer.clear()
    return JSONResponse({"total": len(_capture_buffer), "entries": items})


@app.get("/api/traffic/exchanges")
async def api_traffic_exchanges(
    request: Request,
    host: str = "",
    method: str = "",
    limit: int = 100,
    offset: int = 0,
):
    if not _token_ok(request.headers.get("X-Ares-Token") or request.query_params.get("token")):
        return JSONResponse({"error": "unauthorized"}, status_code=401)
    t = _get_traffic_store()
    if t is None:
        return JSONResponse({"error": "traffic store not initialized"}, status_code=503)
    try:
        rows = t.query_exchanges(
            host=host or None,
            method=method or None,
            limit=limit, offset=offset,
        )
        return JSONResponse({"total": len(rows), "exchanges": [vars(r) for r in rows]})
    except Exception as exc:
        return JSONResponse({"error": str(exc)}, status_code=500)


@app.get("/api/traffic/exchanges/{exchange_id}")
async def api_traffic_exchange_detail(exchange_id: str, request: Request):
    if not _token_ok(request.headers.get("X-Ares-Token") or request.query_params.get("token")):
        return JSONResponse({"error": "unauthorized"}, status_code=401)
    t = _get_traffic_store()
    if t is None:
        return JSONResponse({"error": "traffic store not initialized"}, status_code=503)
    ex = t.get_exchange(exchange_id)
    if ex is None:
        return JSONResponse({"error": "not found"}, status_code=404)
    d = vars(ex)
    # Decode body bytes for JSON transport
    for k in ("req_body", "resp_body"):
        if isinstance(d.get(k), (bytes, bytearray)):
            try:
                d[k] = d[k].decode("utf-8", errors="replace")
            except Exception:
                d[k] = d[k].hex()
    return JSONResponse(d)


@app.get("/api/traffic/stats")
async def api_traffic_stats(request: Request):
    if not _token_ok(request.headers.get("X-Ares-Token") or request.query_params.get("token")):
        return JSONResponse({"error": "unauthorized"}, status_code=401)
    t = _get_traffic_store()
    if t is None:
        return JSONResponse({"initialized": False, "total_exchanges": 0})
    return JSONResponse({**t.stats(), "initialized": True})


# ─── Traffic proxy API ───────────────────────────────────────────────────────

@app.get("/api/traffic/{scan_id}")
async def api_get_traffic(scan_id: str, request: Request):
    if not _token_ok(request.headers.get("X-Ares-Token") or request.query_params.get("token")):
        return JSONResponse({"error": "unauthorized"}, status_code=401)
    traffic_path = os.path.join(REPORTS_DIR, "traffic", scan_id, "traffic.jsonl")
    if not os.path.exists(traffic_path):
        return JSONResponse({"scan_id": scan_id, "entries": [], "error": "sin tráfico grabado"})
    entries = []
    try:
        with open(traffic_path, encoding="utf-8") as fh:
            for line in fh:
                try:
                    entries.append(json.loads(line))
                except Exception:
                    pass
    except Exception as e:
        return JSONResponse({"error": str(e)}, status_code=500)
    return JSONResponse({"scan_id": scan_id, "total": len(entries), "entries": entries[:200]})


# ---------------------------------------------------------------------------
# RSI endpoints
# ---------------------------------------------------------------------------

def _get_lesson_library():
    from engine.rsi.lessons import LessonLibrary
    return LessonLibrary()

@app.get("/api/rsi/lessons")
async def api_rsi_list_lessons(
    kind: str | None = None,
    limit: int = 100,
):
    """List RSI lessons. Optional ?kind= filter."""
    try:
        lib = _get_lesson_library()
        from engine.rsi.lessons import LessonKind
        if kind:
            try:
                lk = LessonKind(kind)
                lessons = lib.by_kind(lk)
            except ValueError:
                return JSONResponse({"error": f"kind inválido: {kind}"}, status_code=400)
        else:
            lessons = lib.all()
        lessons_sorted = sorted(lessons, key=lambda l: l.created_at, reverse=True)[:limit]
        return JSONResponse({"lessons": [l.to_dict() for l in lessons_sorted], "total": len(lib)})
    except Exception as e:
        return JSONResponse({"error": str(e)}, status_code=500)


@app.get("/api/rsi/lessons/{lesson_id}")
async def api_rsi_get_lesson(lesson_id: str):
    """Get a single RSI lesson by ID."""
    try:
        lib = _get_lesson_library()
        lesson = lib.get(lesson_id)
        if lesson is None:
            return JSONResponse({"error": "not found"}, status_code=404)
        return JSONResponse(lesson.to_dict())
    except Exception as e:
        return JSONResponse({"error": str(e)}, status_code=500)


@app.delete("/api/rsi/lessons/{lesson_id}")
async def api_rsi_delete_lesson(lesson_id: str):
    """Delete a single RSI lesson."""
    try:
        lib = _get_lesson_library()
        ok = lib.remove(lesson_id)
        if not ok:
            return JSONResponse({"error": "not found"}, status_code=404)
        return JSONResponse({"ok": True})
    except Exception as e:
        return JSONResponse({"error": str(e)}, status_code=500)


@app.delete("/api/rsi/lessons")
async def api_rsi_clear_lessons():
    """Clear all RSI lessons."""
    try:
        lib = _get_lesson_library()
        count = lib.clear()
        return JSONResponse({"ok": True, "cleared": count})
    except Exception as e:
        return JSONResponse({"error": str(e)}, status_code=500)


@app.get("/reports/{scan_id}/{filename}")
async def get_report_file(scan_id: str, filename: str):
    safe = os.path.basename(filename)
    path = os.path.join(REPORTS_DIR, scan_id, safe)
    if not os.path.isfile(path):
        return JSONResponse({"error": "no encontrado"}, status_code=404)
    return FileResponse(path)


async def _persist_report(scan_id: str, suffix: str, report, mode: str = "scan") -> dict:
    # deduplicar findings antes de persistir
    try:
        from engine.reporting.dedup import dedup_report
        dedup_report(report)
    except Exception:
        pass

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

    # persistir en Postgres si está configurado (best-effort, no bloquea)
    asyncio.create_task(_pg_save_report(safe_report, mode))

    return {"html": f"/reports/{scan_id}/{html_name}", "json": f"/reports/{scan_id}/{json_name}", "sarif": f"/reports/{scan_id}/{sarif_name}"}


async def _pg_save_report(report, mode: str) -> None:
    try:
        from engine.persistence.store import PersistenceStore
        store = await PersistenceStore.connect()
        if store.available:
            await store.save_report(report, mode=mode)
            await store.close()
    except Exception:
        pass

    # poblar knowledge graph (best-effort)
    try:
        from engine.persistence.knowledge_graph import KnowledgeGraph
        kg = await KnowledgeGraph.connect()
        if kg.available:
            await kg.populate_from_report(report)
            await kg.close()
    except Exception:
        pass


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
    links = await _persist_report(scan_id, "", report_with, mode=mode)
    links_without = None
    if report_without is not None:
        links_without = await _persist_report(scan_id, ".sin_auth", report_without, mode=mode)
    asyncio.create_task(_notify_scan(report_with, links, mode=mode))

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

        try:
            config = _build_config(params, name, transport, connection, mode=mode)
        except Exception as e:
            results.append({"name": name, "error": f"config inválida: {e}"})
            emit({"type": "target_error", "target": name, "error": f"config inválida: {e}"})
            return

        def progress(event: dict):
            emit({"type": "progress", "target": name, "event": event})

        try:
            report = await run_scan(config, progress_cb=progress)
            baseline_line = await _apply_baseline_and_webhook(report, config, None)  # webhook agregado, no por target
            if baseline_line:
                emit({"type": "progress", "target": name, "event": {"type": "log", "message": baseline_line}})

            safe_name = re.sub(r"[^\w.-]+", "_", str(name)) or "target"
            links = await _persist_report(scan_id, f".{safe_name}", report, mode=mode)
            asyncio.create_task(_notify_scan(report, links, mode=mode))
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


# ---------------------------------------------------------------------------
# AI Chat WebSocket  (/ws/chat)
# ---------------------------------------------------------------------------

@app.websocket("/ws/chat")
async def ws_chat(websocket: WebSocket):
    """Chat con IA con contexto del scan activo.

    Protocolo:
      Client → {"message": "...", "provider": "auto", "model": "",
                 "scan_context": {scan_id?, findings?, target?}}
      Server → {"type": "chunk", "text": "..."} (streaming)
              {"type": "done", "provider": "...", "model": "..."}
              {"type": "error", "error": "..."}
    """
    if not websocket_token_ok(websocket):
        await websocket.close(code=1008)
        return
    await websocket.accept()

    # Mantener historial de conversación por conexión
    history: list[dict] = []

    try:
        while True:
            try:
                raw = await websocket.receive_text()
            except Exception:
                break
            try:
                data = json.loads(raw)
            except Exception:
                await websocket.send_json({"type": "error", "error": "JSON inválido"})
                continue

            if data.get("type") == "clear":
                history.clear()
                await websocket.send_json({"type": "cleared"})
                continue

            user_msg = (data.get("message") or "").strip()
            if not user_msg:
                continue

            provider = data.get("provider") or "auto"
            model_override = data.get("model") or None
            scan_ctx = data.get("scan_context") or {}

            # Construir system prompt con contexto de scan si está disponible
            system_parts = [
                "Sos el asistente de Ares, una plataforma de seguridad ofensiva.",
                "Ayudás a analizar resultados de scans, interpretar hallazgos, "
                "sugerir próximos pasos y responder preguntas sobre seguridad.",
                "Respondé en el idioma del usuario. Sé conciso y técnico.",
            ]

            if scan_ctx.get("target"):
                system_parts.append(f"\nTarget activo: {scan_ctx['target']}")

            if scan_ctx.get("findings"):
                findings_text = json.dumps(scan_ctx["findings"][:10], ensure_ascii=False)
                system_parts.append(f"\nHallazgos recientes (últimos 10):\n{findings_text}")

            if scan_ctx.get("scan_id"):
                # Cargar reporte del disco si existe
                try:
                    report_path = os.path.join("reports", scan_ctx["scan_id"], "report.json")
                    if os.path.exists(report_path):
                        with open(report_path, encoding="utf-8") as fh:
                            rdata = json.load(fh)
                        score = rdata.get("score", "N/A")
                        total_f = len(rdata.get("findings", []))
                        confirmed = sum(1 for f in rdata.get("findings", []) if not f.get("passed", True))
                        system_parts.append(
                            f"\nScan {scan_ctx['scan_id']}: score={score}, "
                            f"{confirmed}/{total_f} hallazgos confirmados."
                        )
                except Exception:
                    pass

            system_prompt = "\n".join(system_parts)

            try:
                from engine.agent.llmpool import LLMPool
                pool = LLMPool.from_env(preferred=provider, model_override=model_override)
            except Exception as e:
                await websocket.send_json({"type": "error", "error": f"LLMPool no disponible: {e}"})
                continue

            history.append({"role": "user", "content": user_msg})

            try:
                response = await pool.chat(
                    messages=history,
                    system=system_prompt,
                    tools=[],
                    stream_cb=lambda chunk: asyncio.ensure_future(
                        websocket.send_json({"type": "chunk", "text": chunk})
                    ) if chunk else None,
                )
            except Exception as e:
                history.pop()  # revertir mensaje fallido
                await websocket.send_json({"type": "error", "error": str(e)})
                continue

            assistant_text = ""
            if isinstance(response.get("content"), str):
                assistant_text = response["content"]
            elif isinstance(response.get("content_normalized"), list):
                for block in response["content_normalized"]:
                    if block.get("type") == "text":
                        assistant_text += block.get("text", "")

            history.append({"role": "assistant", "content": assistant_text})

            await websocket.send_json({
                "type": "done",
                "provider": response.get("provider", provider),
                "model": response.get("model", ""),
                "text": assistant_text,
            })

    except Exception:
        pass
    finally:
        try:
            await websocket.close()
        except Exception:
            pass


# ─── ARTEX hybrid API ────────────────────────────────────────────────────────
# Goals & constraints

_goals_store: list[dict] = []
_constraints_store: dict = {"allow": [], "deny": [], "max_risk": 100}


@app.get("/api/goals")
async def api_get_goals(_user: str = Depends(_require_auth)):
    return JSONResponse({"goals": _goals_store})


@app.post("/api/goals")
async def api_set_goals(request: Request, _user: str = Depends(_require_auth)):
    try:
        body = await request.json()
    except Exception:
        return JSONResponse({"error": "body inválido"}, status_code=400)
    goals = body.get("goals", [])
    if not isinstance(goals, list):
        return JSONResponse({"error": "goals debe ser lista"}, status_code=400)
    _goals_store.clear()
    _goals_store.extend(goals)
    return JSONResponse({"goals": _goals_store})


@app.get("/api/constraints")
async def api_get_constraints(_user: str = Depends(_require_auth)):
    return JSONResponse(_constraints_store)


@app.post("/api/constraints")
async def api_set_constraints(request: Request, _user: str = Depends(_require_auth)):
    try:
        body = await request.json()
    except Exception:
        return JSONResponse({"error": "body inválido"}, status_code=400)
    for key in ("allow", "deny", "max_risk"):
        if key in body:
            _constraints_store[key] = body[key]
    return JSONResponse(_constraints_store)


# Task lifecycle — start / stop / pause
# Tasks are stored in the reports index; these endpoints relay signals to
# running WebSocket scan tasks via a shared asyncio.Event dict.

_task_cancel_events: dict[str, asyncio.Event] = {}
_task_pause_events: dict[str, asyncio.Event] = {}


@app.post("/api/tasks/{task_id}/start")
async def api_task_start(task_id: str, _user: str = Depends(_require_auth)):
    _task_cancel_events.pop(task_id, None)
    _task_pause_events.pop(task_id, None)
    return JSONResponse({"task_id": task_id, "action": "start"})


@app.post("/api/tasks/{task_id}/stop")
async def api_task_stop(task_id: str, _user: str = Depends(_require_auth)):
    ev = asyncio.Event()
    ev.set()
    _task_cancel_events[task_id] = ev
    return JSONResponse({"task_id": task_id, "action": "stop"})


@app.post("/api/tasks/{task_id}/pause")
async def api_task_pause(task_id: str, _user: str = Depends(_require_auth)):
    ev = _task_pause_events.get(task_id)
    if ev is None:
        ev = asyncio.Event()
        _task_pause_events[task_id] = ev
    if ev.is_set():
        ev.clear()
        action = "paused"
    else:
        ev.set()
        action = "resumed"
    return JSONResponse({"task_id": task_id, "action": action})


# Task archives / credentials / templates

@app.get("/api/tasks/archives")
async def api_task_archives(_user: str = Depends(_require_auth)):
    index = _load_index()
    archives = [e for e in index if e.get("archived")]
    return JSONResponse({"total": len(archives), "archives": archives})


@app.get("/api/tasks/credentials")
async def api_task_credentials(_user: str = Depends(_require_auth)):
    return JSONResponse({"credentials": []})


@app.get("/api/tasks/templates")
async def api_task_templates(_user: str = Depends(_require_auth)):
    tpl_path = os.path.join(REPORTS_DIR, "_templates.json")
    if os.path.exists(tpl_path):
        with open(tpl_path, encoding="utf-8") as f:
            templates = json.load(f)
    else:
        templates = []
    return JSONResponse({"templates": templates})


@app.post("/api/tasks/templates")
async def api_create_template(request: Request, _user: str = Depends(_require_auth)):
    try:
        body = await request.json()
    except Exception:
        return JSONResponse({"error": "body inválido"}, status_code=400)
    tpl_path = os.path.join(REPORTS_DIR, "_templates.json")
    templates = []
    if os.path.exists(tpl_path):
        with open(tpl_path, encoding="utf-8") as f:
            templates = json.load(f)
    import uuid as _uuid
    body.setdefault("id", _uuid.uuid4().hex[:8])
    templates.append(body)
    with open(tpl_path, "w", encoding="utf-8") as f:
        json.dump(templates, f, indent=2, ensure_ascii=False)
    return JSONResponse(body, status_code=201)


# Intercept HITL — approve / deny pending tool calls

_pending_intercepts: dict[str, dict] = {}
_intercept_futures: dict[str, asyncio.Future] = {}


@app.get("/api/intercept/pending")
async def api_intercept_pending(_user: str = Depends(_require_auth)):
    return JSONResponse({
        "pending": [
            {"id": k, **v.get("payload", {})}
            for k, v in _pending_intercepts.items()
        ]
    })


@app.post("/api/intercept/approve")
async def api_intercept_approve(request: Request, _user: str = Depends(_require_auth)):
    try:
        body = await request.json()
    except Exception:
        return JSONResponse({"error": "body inválido"}, status_code=400)
    iid = body.get("intercept_id")
    fut = _intercept_futures.pop(iid, None)
    _pending_intercepts.pop(iid, None)
    if fut and not fut.done():
        fut.set_result({"decision": "APPROVED", "operator": _user})
    return JSONResponse({"intercept_id": iid, "decision": "APPROVED"})


@app.post("/api/intercept/deny")
async def api_intercept_deny(request: Request, _user: str = Depends(_require_auth)):
    try:
        body = await request.json()
    except Exception:
        return JSONResponse({"error": "body inválido"}, status_code=400)
    iid = body.get("intercept_id")
    reason = body.get("reason", "denied by operator")
    fut = _intercept_futures.pop(iid, None)
    _pending_intercepts.pop(iid, None)
    if fut and not fut.done():
        fut.set_result({"decision": "DENIED", "reason": reason, "operator": _user})
    return JSONResponse({"intercept_id": iid, "decision": "DENIED"})


# Skills

@app.get("/api/skills")
async def api_list_skills(_user: str = Depends(_require_auth)):
    import pathlib
    skills_dir = pathlib.Path(__file__).parent.parent / "skills"
    skills = []
    if skills_dir.exists():
        for skill_dir in sorted(skills_dir.iterdir()):
            if skill_dir.is_dir():
                md = skill_dir / "SKILL.md"
                skills.append({
                    "name": skill_dir.name,
                    "has_skill_md": md.exists(),
                    "path": str(skill_dir),
                })
    return JSONResponse({"skills": skills})


@app.post("/api/skill/{skill_name}/load")
async def api_load_skill(skill_name: str, _user: str = Depends(_require_auth)):
    import pathlib
    skills_dir = pathlib.Path(__file__).parent.parent / "skills"
    skill_dir = skills_dir / skill_name
    if not skill_dir.exists():
        return JSONResponse({"error": f"skill '{skill_name}' no encontrado"}, status_code=404)
    md = skill_dir / "SKILL.md"
    content = md.read_text(encoding="utf-8") if md.exists() else ""
    return JSONResponse({"name": skill_name, "content": content})


# LLM records

@app.get("/api/llm-records")
async def api_llm_records(limit: int = 50, _user: str = Depends(_require_auth)):
    import pathlib
    rec_path = pathlib.Path.home() / ".ares" / "llm_records.jsonl"
    records = []
    if rec_path.exists():
        lines = rec_path.read_text(encoding="utf-8").splitlines()
        for line in reversed(lines[-limit:]):
            try:
                records.append(json.loads(line))
            except Exception:
                pass
    return JSONResponse({"total": len(records), "records": records})


# Tool usage statistics

@app.get("/api/tool-usage")
async def api_tool_usage(_user: str = Depends(_require_auth)):
    index = _load_index()
    tool_counts: dict[str, int] = {}
    for entry in index:
        sid = entry.get("scan_id", "")
        rp = os.path.join(REPORTS_DIR, sid, "report.json")
        if not os.path.exists(rp):
            continue
        try:
            with open(rp, encoding="utf-8") as fh:
                report = json.load(fh)
            for f in report.get("findings", []):
                tid = f.get("test_id", "unknown")
                tool_counts[tid] = tool_counts.get(tid, 0) + 1
        except Exception:
            pass
    sorted_tools = sorted(tool_counts.items(), key=lambda x: -x[1])
    return JSONResponse({"tools": [{"test_id": k, "count": v} for k, v in sorted_tools]})


# Side questions

@app.post("/api/sidequestion/ask")
async def api_sidequestion_ask(request: Request, _user: str = Depends(_require_auth)):
    try:
        body = await request.json()
    except Exception:
        return JSONResponse({"error": "body inválido"}, status_code=400)
    question = body.get("question", "").strip()
    task_id = body.get("task_id", "")
    if not question:
        return JSONResponse({"error": "question requerido"}, status_code=400)
    try:
        from engine.agent.llmpool import LLMPool
        pool = LLMPool.from_env()
        resp = await pool.complete(
            messages=[{"role": "user", "content": question}],
            system="You are a security analysis assistant. Answer the question concisely.",
        )
        answer = ""
        content = resp.get("content") or resp.get("content_normalized", [])
        if isinstance(content, str):
            answer = content
        elif isinstance(content, list):
            answer = "".join(b.get("text", "") for b in content if b.get("type") == "text")
    except Exception as e:
        answer = f"[error: {e}]"
    return JSONResponse({"task_id": task_id, "question": question, "answer": answer})


# Update check

@app.get("/api/update-check")
async def api_update_check(_user: str = Depends(_require_auth)):
    import importlib.metadata
    try:
        current = importlib.metadata.version("ares")
    except Exception:
        current = "dev"
    return JSONResponse({
        "current_version": current,
        "update_available": False,
        "latest": current,
        "note": "Connect to update feed for live version data.",
    })
