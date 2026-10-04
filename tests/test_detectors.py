"""
Test suite del motor: valida que cada test_id detecta lo que dice detectar
(positivo, contra los fixtures deliberadamente vulnerables) y que NO dispara
falsos positivos sobre un server bien construido (negativo, contra
tests/fixtures/safe_server.py). Sin esto, "análisis profundo y confiable" es
una promesa sin verificar -- un refactor futuro podría romper detección en
silencio.
"""
import os
import pytest

from engine.core.models import ScanConfig
from engine.orchestrator import run_scan
from conftest import VULN_STDIO, SAFE_STDIO, RUGPULLED_STDIO, VALIDATING_STDIO, stdio_connection


def confirmed_ids(report) -> set[str]:
    return {f.test_id for f in report.findings if not f.passed}


async def _scan(script_path: str, tests: list[str], **kwargs) -> "ScanReport":
    config = ScanConfig(
        target_name="test",
        transport="stdio",
        connection=stdio_connection(script_path),
        selected_tests=tests,
        **kwargs,
    )
    return await run_scan(config)


# --- positivos: target_server.py (vulnerable a propósito) -------------------

async def test_suspicious_description_detects_tool_poisoning():
    report = await _scan(VULN_STDIO, ["recon.suspicious_descriptions"])
    assert "recon.suspicious_descriptions" in confirmed_ids(report)


async def test_line_jumping_detects_injection_in_parameter_description():
    """format_number tiene descripción de TOOL benigna, pero el parámetro 'value'
    trae la instrucción maliciosa -- si esto no se detecta, es un falso negativo
    real (ATR-2026-00579 / OWASP MCP03:2025)."""
    report = await _scan(VULN_STDIO, ["recon.suspicious_descriptions"])
    hits = [f for f in report.findings if f.test_id == "recon.suspicious_descriptions"
            and not f.passed and "format_number" in f.target]
    assert hits, "line jumping en el parámetro 'value' de format_number no fue detectado"
    assert any("Line jumping" in f.title for f in hits)


async def test_excessive_permissions_flags_risky_keywords():
    report = await _scan(VULN_STDIO, ["recon.excessive_permissions"])
    assert "recon.excessive_permissions" in confirmed_ids(report)


async def test_schema_permissive_flags_unbounded_params():
    report = await _scan(VULN_STDIO, ["static.schema_permissive"])
    assert "static.schema_permissive" in confirmed_ids(report)


async def test_command_injection_confirmed_by_canary():
    report = await _scan(VULN_STDIO, ["dynamic.command_injection_confirmed"])
    findings = [f for f in report.findings if f.test_id == "dynamic.command_injection_confirmed" and not f.passed]
    assert findings, "el canario debería sobrevivir contra run_command (shell=True)"
    assert findings[0].severity.value == "critical"


async def test_path_traversal_confirmed_reads_real_passwd():
    report = await _scan(VULN_STDIO, ["dynamic.path_traversal_confirmed"])
    assert "dynamic.path_traversal_confirmed" in confirmed_ids(report)


async def test_fuzz_resources_detects_traversal_via_resource_template():
    report = await _scan(VULN_STDIO, ["dynamic.fuzz_resources"])
    assert "dynamic.fuzz_resources" in confirmed_ids(report)


async def test_injection_passthrough_detects_unsanitized_reflection():
    report = await _scan(VULN_STDIO, ["adv.injection_passthrough"])
    assert "adv.injection_passthrough" in confirmed_ids(report)


async def test_destructive_no_confirmation_flags_delete_all():
    report = await _scan(VULN_STDIO, ["adv.destructive_no_confirmation"])
    findings = [f for f in report.findings if f.test_id == "adv.destructive_no_confirmation"]
    delete_all = [f for f in findings if "delete_all_notes" in f.target]
    assert delete_all and not delete_all[0].passed


async def test_authz_object_level_detects_bola():
    report = await _scan(VULN_STDIO, ["auth.authz_object_level"])
    hits = [f for f in report.findings if f.test_id == "auth.authz_object_level" and not f.passed]
    assert hits, "BOLA en get_account_balance (account_id 1/2/3 devuelven cuentas distintas) no fue detectado"
    assert any("get_account_balance" in f.target for f in hits)


async def test_safe_server_no_authz_object_level_false_positive():
    # 'name' en fetch_item no matchea el patrón id-like -- no debería ni intentarlo.
    report = await _scan(SAFE_STDIO, ["auth.authz_object_level"])
    assert confirmed_ids(report) == set()


async def test_resource_object_level_detects_bola_via_resource_template():
    """Equivalente de auth.authz_object_level pero sobre 'resources/read' en vez de
    tools -- cubre la mitad de MCP10:2025 (Context Injection & Over-Sharing) que
    auth.authz_object_level, pensado solo para tools, no alcanza."""
    report = await _scan(VULN_STDIO, ["auth.resource_object_level"])
    hits = [f for f in report.findings if f.test_id == "auth.resource_object_level" and not f.passed]
    assert hits, "BOLA en account://{account_id}/profile (1/2/3 devuelven cuentas distintas) no fue detectado"
    assert any("account_id" in str(f.evidence.request) for f in hits)


async def test_safe_server_no_resource_object_level_false_positive():
    # el resource de safe_server.py valida ownership (solo 'self' devuelve datos reales,
    # cualquier otro id devuelve el MISMO 'forbidden' literal) -- no debería dispararse.
    report = await _scan(SAFE_STDIO, ["auth.resource_object_level"])
    assert confirmed_ids(report) == set()


async def test_exfiltration_chain_detects_reader_plus_sender():
    report = await _scan(VULN_STDIO, ["supplychain.exfiltration_chain"])
    assert "supplychain.exfiltration_chain" in confirmed_ids(report)


async def test_stateful_chain_exfil_confirms_real_execution_not_just_coexistence():
    """A diferencia de exfiltration_chain (heurístico, arriba), esto ejecuta de
    verdad la cadena: llama al lector, pasa un canario al emisor, y confirma que
    lo acepta -- debe salir confidence 'verified', no 'heuristic'."""
    report = await _scan(VULN_STDIO, ["adv.stateful_chain_exfil"])
    hits = [f for f in report.findings if f.test_id == "adv.stateful_chain_exfil" and not f.passed]
    assert hits, "la cadena read_note->fetch_webhook del fixture vulnerable debería confirmarse"
    assert all(f.confidence == "verified" for f in hits)
    assert all("->" in f.target for f in hits)


async def test_stateful_chain_exfil_no_false_positive_on_safe_server():
    report = await _scan(SAFE_STDIO, ["adv.stateful_chain_exfil"])
    assert confirmed_ids(report) == set()


async def test_rug_pull_detects_changed_tool_definition():
    baseline_report = await _scan(SAFE_STDIO, ["recon.enumerate"])
    baseline_dict = baseline_report.to_dict()

    import json
    import tempfile
    with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
        json.dump(baseline_dict, f)
        baseline_path = f.name

    try:
        config = ScanConfig(
            target_name="t", transport="stdio", connection=stdio_connection(RUGPULLED_STDIO),
            selected_tests=["adv.rug_pull"], baseline_path=baseline_path,
        )
        report = await run_scan(config)
    finally:
        os.remove(baseline_path)

    hits = [f for f in report.findings if f.test_id == "adv.rug_pull" and not f.passed]
    assert hits, "el cambio en la descripción de remove_item no fue detectado como rug pull"
    assert any("remove_item" in f.target for f in hits)
    assert all(f.confidence == "verified" for f in hits)


async def test_audit_logging_flags_missing_logging_capability():
    # FastMCP no declara 'logging' por default -- confirmado inspeccionando get_capabilities()
    # directamente contra el fixture antes de escribir este test.
    report = await _scan(VULN_STDIO, ["recon.audit_logging"])
    assert "recon.audit_logging" in confirmed_ids(report)


async def test_rug_pull_no_findings_without_baseline():
    report = await _scan(SAFE_STDIO, ["adv.rug_pull"])
    assert confirmed_ids(report) == set()


async def test_live_agent_injection_skips_gracefully_without_any_provider(monkeypatch):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    monkeypatch.delenv("OLLAMA_HOST", raising=False)
    report = await _scan(VULN_STDIO, ["adv.live_agent_injection"], allow_network_side_effects=True)
    findings = [f for f in report.findings if f.test_id == "adv.live_agent_injection"]
    assert findings and findings[0].passed
    assert "ANTHROPIC_API_KEY" in findings[0].description
    assert "OPENAI_API_KEY" in findings[0].description
    assert "OLLAMA_HOST" in findings[0].description


# --- negativos: safe_server.py (bien construido) ----------------------------

async def test_safe_server_no_schema_findings():
    report = await _scan(SAFE_STDIO, ["static.schema_permissive", "static.no_schema"])
    assert confirmed_ids(report) == set(), f"falsos positivos: {[f.title for f in report.findings if not f.passed]}"


async def test_safe_server_no_suspicious_descriptions():
    report = await _scan(SAFE_STDIO, ["recon.suspicious_descriptions", "recon.excessive_permissions"])
    assert confirmed_ids(report) == set()


async def test_safe_server_destructive_requires_confirm_param():
    report = await _scan(SAFE_STDIO, ["adv.destructive_no_confirmation"])
    findings = [f for f in report.findings if f.test_id == "adv.destructive_no_confirmation"]
    remove = [f for f in findings if "remove_item" in f.target]
    assert remove and remove[0].passed, "remove_item declara 'confirm', no debería confirmarse como hallazgo"


async def test_safe_server_no_secret_exposure():
    report = await _scan(SAFE_STDIO, ["supplychain.secret_exposure"])
    assert confirmed_ids(report) == set()


async def test_safe_server_no_command_injection():
    report = await _scan(SAFE_STDIO, ["dynamic.command_injection_confirmed"])
    assert confirmed_ids(report) == set()


# --- validating_server.py: rechaza input y lo cita en el error (patrón real de mcp.deepwiki.com) ---

async def test_validating_server_rejection_is_not_a_leak():
    """El server rechaza el payload y lo cita en un mensaje de validación normal
    ('Invalid repoName format: "../../../../etc/passwd"') -- no es un leak real de
    filesystem, solo eco del propio input rechazado. Encontrado como falso positivo
    corriendo Ares contra mcp.deepwiki.com."""
    report = await _scan(VALIDATING_STDIO, ["dynamic.fuzz_tools"])
    leaks = [f for f in report.findings if f.test_id == "dynamic.fuzz_tools"
             and not f.passed and "Leak" in f.title]
    assert leaks == [], f"falso positivo de leak: {[f.description for f in leaks]}"


async def test_validating_server_rejection_downgrades_injection_passthrough():
    """Cuando el payload de injection es RECHAZADO (is_error=true) y solo aparece
    citado en el mensaje de validación, el riesgo debe ser estrictamente MENOR que
    el caso 'aceptado/almacenado' -- esa distinción es la señal real de si hubo
    passthrough genuino o solo un eco de rechazo. No exigimos un band absoluto
    porque el rating combina varios factores (CVSS + impacto al negocio); lo que
    importa es que el ajuste por-instancia realmente mueva la aguja."""
    report = await _scan(VALIDATING_STDIO, ["adv.injection_passthrough"])
    findings = [f for f in report.findings if f.test_id == "adv.injection_passthrough" and not f.passed]
    assert findings, "el mensaje de rechazo debería igual generar un finding, citando el payload"
    assert all("citado en un error" in f.title for f in findings)

    from engine.core.risk import risk_for
    from engine.core.models import _RISK_RATING_TO_SEVERITY
    baseline_rank = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
    accepted_case_severity = _RISK_RATING_TO_SEVERITY[risk_for("adv.injection_passthrough", confidence="heuristic")["risk_rating"]]
    for f in findings:
        assert baseline_rank[f.severity.value] < baseline_rank[accepted_case_severity], (
            f"el caso rechazado ({f.severity.value}) debería pesar menos que el aceptado ({accepted_case_severity})"
        )


# --- transporte http (target_server_http.py) --------------------------------

async def test_cross_session_context_bleed_detects_real_leak(http_fixture_url):
    """target_server_http.py guarda notas en un dict GLOBAL (_notes = {}), sin aislar
    por credencial -- plantar con una identidad y leer con otra DEBE confirmar la fuga.
    Encontrado en vivo probando esto: con un solo canario (id==contenido), read_file
    fallando con 'no existe el archivo <canario>' daba falso positivo (puro eco del
    argumento) -- por eso el diseño real usa DOS canarios (id vs secreto)."""
    from engine.core.models import AuthConfig
    config = ScanConfig(
        target_name="http-test", transport="http", connection={"url": http_fixture_url},
        selected_tests=["auth.cross_session_context_bleed"],
        auth=AuthConfig(type="bearer", token="identity-a"),
        secondary_auth=AuthConfig(type="bearer", token="identity-b"),
    )
    report = await run_scan(config)
    hits = [f for f in report.findings if f.test_id == "auth.cross_session_context_bleed" and not f.passed]
    assert hits, "fuga cross-session vía save_note/read_note (estado global) no fue detectada"
    assert any(f.target == "read_note" for f in hits)
    # read_file/fetch_webhook pueden ecoar el canario_id en un mensaje de error -- esto NO
    # debe aparecer como hallazgo (sería el falso positivo que ya se encontró y corrigió).
    assert not any(f.target in ("read_file", "fetch_webhook") for f in hits)


async def test_cross_session_context_bleed_skips_cleanly_without_secondary_auth(http_fixture_url):
    config = ScanConfig(
        target_name="http-test", transport="http", connection={"url": http_fixture_url},
        selected_tests=["auth.cross_session_context_bleed"],
    )
    report = await run_scan(config)
    assert confirmed_ids(report) == set()


async def test_http_unauthenticated_access_confirmed(http_fixture_url):
    config = ScanConfig(
        target_name="http-test", transport="http", connection={"url": http_fixture_url},
        selected_tests=["auth.unauthenticated_access"],
    )
    report = await run_scan(config)
    assert "auth.unauthenticated_access" in confirmed_ids(report)


async def test_http_transport_security_flags_plain_http(http_fixture_url):
    config = ScanConfig(
        target_name="http-test", transport="http", connection={"url": http_fixture_url},
        selected_tests=["exposure.transport_security"],
    )
    report = await run_scan(config)
    assert "exposure.transport_security" in confirmed_ids(report)


async def test_http_secret_exposure_finds_fake_api_key(http_fixture_url):
    config = ScanConfig(
        target_name="http-test", transport="http", connection={"url": http_fixture_url},
        selected_tests=["supplychain.secret_exposure"],
    )
    report = await run_scan(config)
    assert "supplychain.secret_exposure" in confirmed_ids(report)


# --- SAST (opt-in, requiere semgrep instalado) -------------------------------

import shutil

_HAS_SEMGREP = shutil.which("semgrep") is not None


@pytest.mark.skipif(not _HAS_SEMGREP, reason="semgrep no instalado (pip install -e \".[sast]\")")
async def test_source_sast_finds_path_traversal_in_vuln_fixture():
    import os as _os
    source_dir = _os.path.dirname(VULN_STDIO)
    config = ScanConfig(
        target_name="test", transport="stdio", connection=stdio_connection(VULN_STDIO),
        selected_tests=["supplychain.source_sast"], source_path=source_dir,
    )
    report = await run_scan(config)
    hits = [f for f in report.findings if f.test_id == "supplychain.source_sast" and not f.passed]
    assert hits, "target_server.py tiene un path traversal real (read_file(path) -> open); el ruleset debería marcarlo"
    assert all(f.confidence == "verified" for f in hits)


@pytest.mark.skipif(not _HAS_SEMGREP, reason="semgrep no instalado (pip install -e \".[sast]\")")
async def test_source_sast_no_false_positive_on_safe_server():
    import os as _os
    source_dir = _os.path.dirname(SAFE_STDIO)
    config = ScanConfig(
        target_name="test", transport="stdio", connection=stdio_connection(SAFE_STDIO),
        selected_tests=["supplychain.source_sast"], source_path=source_dir,
    )
    report = await run_scan(config)
    assert confirmed_ids(report) == set()


# --- robustez del orquestador -------------------------------------------------

async def test_hung_test_is_cut_by_timeout_without_killing_the_scan():
    """Fail-closed: un test que nunca termina no debe colgar el scan entero --
    se corta a los test_timeout_s, queda registrado como error de ESE test, y
    el resto de los tests seleccionados igual corren."""
    import asyncio
    from engine.core.registry import register_test, _REGISTRY
    from engine.core.models import Category

    @register_test(
        id="test.__never_finishes__", name="fixture de test", category=Category.RECON,
        description="duerme para siempre, usado solo por este test unitario",
    )
    async def _hangs_forever(target, ctx):
        await asyncio.sleep(999)
        return []

    try:
        config = ScanConfig(
            target_name="test", transport="stdio", connection=stdio_connection(VULN_STDIO),
            selected_tests=["test.__never_finishes__", "recon.enumerate"],
            test_timeout_s=0.2,
        )
        report = await asyncio.wait_for(run_scan(config), timeout=10.0)
    finally:
        _REGISTRY.pop("test.__never_finishes__", None)

    assert any("timeout" in e.lower() for e in report.errors)
    assert "recon.enumerate" in {f.test_id for f in report.findings}  # el resto del scan sí corrió

    # antes de este fix el timeout quedaba SOLO en report.errors (texto libre que score/policy
    # nunca miran) -- un target que logra colgar un test terminaba con el mismo score/ALLOW
    # que uno limpio. Ahora tiene que quedar un Finding real de orchestrator.test_unresponsive,
    # confirmado (passed=False), para que sí pese en calculate_score/PolicyEngine.
    timeout_findings = [f for f in report.findings if f.test_id == "orchestrator.test_unresponsive"]
    assert len(timeout_findings) == 1
    assert timeout_findings[0].passed is False

    # reset_session_on_timeout=True por default: la sesión vieja (potencialmente envenenada,
    # o -- en stdio real -- con el subprocess todavía vivo) se cierra y se reabre una nueva
    # ANTES del siguiente test. recon.enumerate corriendo bien después del hang ya lo prueba
    # implícitamente (necesita una sesión viva), pero el mensaje explícito confirma que pasó
    # por el camino de reconexión y no por una sesión reciclada.
    assert any("sesión reconectada" in e for e in report.errors)
    assert timeout_findings[0].target == "test.__never_finishes__"
    assert report.score["score"] < 100


async def test_oversized_tool_description_is_capped_before_regex_analysis():
    """Un target hostil puede declarar una descripción de tool de varios MB para que los
    tests que la analizan con regex (secret_exposure, suspicious_descriptions, etc.) tarden
    muchísimo (confirmado empíricamente: ~57s para un solo test contra ~0.2s de baseline).
    engine.core.limits.cap_text tiene que haber actuado ANTES de que el blob le llegue a
    cualquier test -- se verifica acá contra el enumerado real, no reimplementando el cap."""
    import asyncio
    import time

    huge = "sk- gh_ xox AKIA password: " * 2_000_000  # varios MB

    from engine.core.registry import register_test, _REGISTRY
    from engine.core.models import Category

    @register_test(
        id="test.__huge_desc__", name="fixture de test", category=Category.RECON,
        description="fuerza una descripción de tool gigantesca sin necesitar un server real",
    )
    async def _report_huge_tools(target, ctx):
        ctx["tools"] = [{"name": "evil", "description": huge, "input_schema": {}}]
        return []

    try:
        config = ScanConfig(
            target_name="test", transport="stdio", connection=stdio_connection(SAFE_STDIO),
            selected_tests=["test.__huge_desc__", "supplychain.secret_exposure"],
        )
        t0 = time.monotonic()
        report = await asyncio.wait_for(run_scan(config), timeout=15.0)
        elapsed = time.monotonic() - t0
    finally:
        _REGISTRY.pop("test.__huge_desc__", None)

    assert elapsed < 10.0  # sin el cap, esto solo tardaba ~57s para un blob de este tamaño
    assert "supplychain.secret_exposure" in {f.test_id for f in report.findings}


async def test_circuit_breaker_stops_after_consecutive_timeouts():
    """Confirmado contra un target real (hostile_to_scanner.py, Campo-Tiro/ares-range/):
    un solo tool que nunca responde hacía que CADA test que lo toca pagara el timeout
    completo por separado -- 4 tests de la batería default ya se habían comido 4 minutos
    reales. A partir de max_consecutive_timeouts, el resto se tiene que saltar de una."""
    import asyncio
    from engine.core.registry import register_test, _REGISTRY
    from engine.core.models import Category

    for i in range(5):
        @register_test(
            id=f"test.__always_hangs_{i}__", name="fixture de test", category=Category.RECON,
            description="duerme para siempre, usado solo por este test unitario",
        )
        async def _hangs_forever(target, ctx):
            await asyncio.sleep(999)
            return []

    try:
        ids = [f"test.__always_hangs_{i}__" for i in range(5)] + ["recon.enumerate"]
        config = ScanConfig(
            target_name="test", transport="stdio", connection=stdio_connection(SAFE_STDIO),
            selected_tests=ids, test_timeout_s=0.2, max_consecutive_timeouts=2,
        )
        report = await asyncio.wait_for(run_scan(config), timeout=10.0)
    finally:
        for i in range(5):
            _REGISTRY.pop(f"test.__always_hangs_{i}__", None)

    # solo los primeros 2 (el límite) se intentaron realmente -- el resto, incluido
    # recon.enumerate al final de la lista, se saltó sin intentarlo.
    timeout_errors = [e for e in report.errors if "timeout" in e.lower() and "no terminó" in e]
    assert len(timeout_errors) == 2
    assert any("circuit breaker" in e for e in report.errors)
    assert "recon.enumerate" not in {f.test_id for f in report.findings}
    assert any(f.test_id == "orchestrator.target_unresponsive_sustained" for f in report.findings)


async def test_dns_failure_on_connect_never_crashes_the_process():
    """Regresión: un DNS que no resuelve (o cualquier falla real de conexión que
    ocurra DESPUÉS de que streamablehttp_client/ClientSession ya se entraron en
    MCPTarget._stack, ej. adentro de session.initialize()) dejaba recursos sin
    cerrar -- el cleanup se disparaba después, desde otra tarea, y el SDK mcp lo
    propaga como BaseExceptionGroup, que un `except Exception` normal no atrapa.
    Esto tumbaba el proceso ENTERO en vez de quedar como error de conexión
    manejado. run_scan debe completar siempre, nunca propagar la excepción."""
    config = ScanConfig(
        target_name="test", transport="http",
        connection={"url": "http://esto-no-resuelve.invalid/mcp"},
        selected_tests=["auth.unauthenticated_access", "recon.enumerate"],
    )
    report = await run_scan(config)  # no debe levantar excepción

    assert any("conexión inicial rechazada/fallida" in e for e in report.errors)
    # recon.enumerate necesita target real -> falla como error de ESE test, no del scan
    assert any(e.startswith("test 'recon.enumerate'") for e in report.errors)


async def test_audit_logging_does_not_false_positive_when_connection_failed():
    """Regresión: si la conexión inicial falla, recon.audit_logging NO debe
    confirmar 'sin logging' -- eso sería un falso positivo (no se pudo ni
    preguntar), no una observación real sobre el server."""
    config = ScanConfig(
        target_name="test", transport="http",
        connection={"url": "http://esto-no-resuelve.invalid/mcp"},
        selected_tests=["recon.audit_logging"],
    )
    report = await run_scan(config)
    assert "recon.audit_logging" not in confirmed_ids(report)
    hits = [f for f in report.findings if f.test_id == "recon.audit_logging"]
    assert hits and hits[0].passed
