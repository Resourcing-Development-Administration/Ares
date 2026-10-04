"""Tests unitarios de funciones puras -- rápidos, sin levantar ningún server."""
from engine.supplychain.similarity import jaro_winkler
from payloads.canary import strip_reflections, new_canary
from engine.reporting.scoring import calculate_score, PENALTY
from engine.policy.engine import PolicyEngine
from engine.core.models import ScanReport, ScanConfig, Finding, Category
from engine.core.cvss import calculate_base_score, severity_from_score
from engine.core.risk import owasp_risk_rating, risk_for
from engine.crossserver import cross_server_findings
from engine.core.sandbox import (
    wrap_command, sandbox_available, sandbox_status, prlimit_available, bwrap_available,
    _current_user_proc_count, NPROC_HEADROOM,
)


def _report_with(*findings) -> ScanReport:
    return ScanReport(scan_id="t", target_name="t", started_at="", findings=list(findings))


def _finding(test_id, passed=False, target="t") -> Finding:
    # severity ya no se pasa a mano -- se deriva de engine/core/risk.py a partir del test_id.
    return Finding(test_id=test_id, title="t", category=Category.DYNAMIC, target=target, description="t", passed=passed)


def test_jaro_winkler_identical_is_one():
    assert jaro_winkler("delete_all", "delete_all") == 1.0


def test_jaro_winkler_detects_near_duplicate_names():
    sim = jaro_winkler("delete_note", "delete_notes")
    assert sim > 0.9


def test_jaro_winkler_dissimilar_names_low_score():
    sim = jaro_winkler("read_file", "send_webhook")
    assert sim < 0.6


def test_strip_reflections_removes_literal_payload_echo():
    canary = new_canary()
    payload = f"; echo {canary}"
    text = f"you sent: {payload}"  # servidor solo hace echo del input, no lo ejecuta
    cleaned = strip_reflections(text, payload)
    assert canary not in cleaned  # sin el eco, no debería quedar el canario "suelto"


def test_strip_reflections_keeps_canary_if_not_just_echoed():
    canary = new_canary()
    payload = f"; echo {canary}"
    text = f"stdout: {canary}\n"  # el canario aparece SOLO (comando ejecutado), no el payload completo
    cleaned = strip_reflections(text, payload)
    assert canary in cleaned


def test_strip_reflections_handles_whitespace_trimmed_echo():
    """Falso positivo real confirmado contra notify_webhook() (Campo-Tiro/ares-range/
    enterprise_source/server.py, sin ningún sink de shell): urllib.parse le hace
    strip() a una URL inválida antes de citarla en 'unknown url type: ...' -- el
    payload "\\necho {canary}\\n" vuelve SIN los saltos de línea, y sin la variante
    p.strip() en strip_reflections ese eco recortado no se reconocía como reflejo."""
    canary = new_canary()
    payload = f"\necho {canary}\n"
    text = f"error fetching: unknown url type: '{payload.strip()}'"
    cleaned = strip_reflections(text, payload)
    assert canary not in cleaned


def test_score_no_findings_is_100_grade_a():
    report = _report_with(_finding("recon.enumerate", passed=True))
    score = calculate_score(report)
    assert score["score"] == 100
    assert score["grade"] == "A"


def test_score_critical_finding_tanks_score():
    # dynamic.command_injection_confirmed resuelve a "critical" con confidence=verified
    # (CVSS 9.8 + likelihood/impact altos) -- ver risk_for() en engine/core/risk.py.
    f = _finding("dynamic.command_injection_confirmed")
    assert f.severity.value == "critical"
    report = _report_with(f)
    score = calculate_score(report)
    assert score["score"] == 100 - PENALTY["critical"]
    assert "EXPUESTO" in score["verdict_text"]


def test_score_never_goes_below_zero():
    report = _report_with(*[_finding("dynamic.command_injection_confirmed", target=f"t{i}") for i in range(5)])
    score = calculate_score(report)
    assert score["score"] == 0


def test_policy_blocks_unauthenticated_access_in_production():
    report = _report_with(_finding("auth.unauthenticated_access"))
    verdict = PolicyEngine().evaluate(report, "production")
    assert verdict["overall"] == "BLOCK"


def test_policy_allows_clean_report():
    report = _report_with(_finding("recon.enumerate", passed=True))
    verdict = PolicyEngine().evaluate(report, "production")
    assert verdict["overall"] == "ALLOW"


def test_policy_development_is_less_strict_than_production():
    report = _report_with(_finding("exposure.transport_security"))
    prod = PolicyEngine().evaluate(report, "production")
    dev = PolicyEngine().evaluate(report, "development")
    assert prod["overall"] in ("CONDITIONAL", "BLOCK")
    assert dev["overall"] == "ALLOW"


# --- CVSS v3.1 -- verificado contra vectores de referencia públicos conocidos ---

def test_cvss_log4shell_reference_vector_is_10():
    # AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H -- vector publicado para CVE-2021-44228 (Log4Shell)
    assert calculate_base_score("AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H") == 10.0


def test_cvss_canonical_critical_unauth_rce_is_9_8():
    assert calculate_base_score("AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H") == 9.8


def test_cvss_no_impact_is_zero():
    assert calculate_base_score("AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N") == 0.0


def test_cvss_local_full_compromise_is_7_8():
    assert calculate_base_score("AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H") == 7.8


def test_severity_from_score_matches_official_bands():
    assert severity_from_score(0.0) == "info"
    assert severity_from_score(3.9) == "low"
    assert severity_from_score(4.0) == "medium"
    assert severity_from_score(6.9) == "medium"
    assert severity_from_score(7.0) == "high"
    assert severity_from_score(8.9) == "high"
    assert severity_from_score(9.0) == "critical"


# --- OWASP Risk Rating Methodology: matriz Likelihood x Impact ---

def test_owasp_risk_matrix_low_low_is_note():
    assert owasp_risk_rating("low", "low") == "Note"


def test_owasp_risk_matrix_high_high_is_critical():
    assert owasp_risk_rating("high", "high") == "Critical"


def test_owasp_risk_matrix_medium_medium_is_medium():
    assert owasp_risk_rating("medium", "medium") == "Medium"


def test_risk_for_known_test_id_has_all_dimensions():
    r = risk_for("auth.unauthenticated_access")
    assert r["cvss_vector"].startswith("AV:")
    assert 0.0 <= r["cvss_score"] <= 10.0
    assert r["business_impact"]["financial"] in ("low", "medium", "high")
    assert r["remediation_effort"] in ("trivial", "low", "medium", "high")
    assert r["risk_rating"] in ("Note", "Low", "Medium", "High", "Critical")


def test_risk_for_unknown_test_id_falls_back_safely():
    r = risk_for("nonexistent.test_id")
    assert r["cvss_score"] == 0.0


async def test_oauth_metadata_security_parses_www_authenticate_and_flags_missing_authz_servers():
    """Servidor mock: 401 con WWW-Authenticate apuntando a un resource_metadata real, pero
    ese metadata NO declara authorization_servers -- valida la cadena de descubrimiento RFC
    9728 sin necesitar infraestructura OAuth real."""
    import json
    import threading
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *a, **kw):
            pass

        def do_POST(self):
            metadata_url = f"http://127.0.0.1:{self.server.server_port}/.well-known/oauth-protected-resource"
            self.send_response(401)
            self.send_header("WWW-Authenticate", f'Bearer resource_metadata="{metadata_url}"')
            self.end_headers()

        def do_GET(self):
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({"resource": "http://127.0.0.1/mcp"}).encode())  # sin authorization_servers

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    port = server.server_address[1]

    try:
        from engine.auth.tests import oauth_metadata_security
        ctx = {"transport": "http", "connection": {"url": f"http://127.0.0.1:{port}/mcp"}}
        findings = await oauth_metadata_security(None, ctx)
    finally:
        server.shutdown()

    assert findings, "el test no corrió"
    assert not findings[0].passed
    assert "authorization_servers" in findings[0].title


def test_audit_logging_and_rug_pull_are_verified_not_heuristic():
    # son hechos observados directamente (capability declarada, hash de schema) --
    # no señales a revisar. Encontrado como des-calibración real al agregar estos
    # dos tests nuevos y correr vet contra mcp.deepwiki.com.
    from engine.core.confidence import get_confidence_for
    assert get_confidence_for("recon.audit_logging") == "verified"
    assert get_confidence_for("adv.rug_pull") == "verified"


def test_session_id_entropy_flags_numeric_short_ids():
    from engine.exposure.tests import _shannon_entropy_bits
    weak_bits = _shannon_entropy_bits("12345678") * 8
    strong = _shannon_entropy_bits("a3f9c8b1e7d2f0a6c4b8e1d9f3a7c2b5") * 32
    assert weak_bits < 64
    assert strong >= 64


def test_allowlist_suppresses_matching_finding_and_excludes_from_summary(tmp_path):
    from engine.reporting.suppress import apply_noise_reduction

    allowlist = tmp_path / ".ares_allowlist.yml"
    allowlist.write_text(
        "entries:\n"
        "  - test_id: supplychain.tool_squatting\n"
        "    target: read_file\n"
        "    reason: aceptado por el equipo\n"
    )
    f1 = _finding("supplychain.tool_squatting", passed=False, target="read_file")
    f2 = _finding("supplychain.tool_squatting", passed=False, target="delete_all")
    report = _report_with(f1, f2)

    stats = apply_noise_reduction(report, allowlist_path=str(allowlist))

    assert stats["allowlisted"] == 1
    assert f1.suppressed and f1.suppressed_reason and "aceptado por el equipo" in f1.suppressed_reason
    assert not f2.suppressed
    summary = report.summary()
    assert summary["confirmed_findings"] == 1  # solo f2 cuenta
    assert summary["suppressed_findings"] == 1


def test_allowlist_wildcard_test_id_and_omitted_target_matches_any():
    from engine.reporting.suppress import _pattern_matches
    assert _pattern_matches("adv.confused_deputy*", "adv.confused_deputy")
    assert not _pattern_matches("adv.confused_deputy*", "adv.destructive_no_confirmation")
    assert _pattern_matches(None, "cualquier-target")  # target omitido = aplica a todos
    assert _pattern_matches("*", "cualquier-target")


def test_min_confidence_verified_suppresses_only_heuristic_findings():
    from engine.reporting.suppress import apply_noise_reduction
    from engine.core.confidence import get_confidence_for

    heuristic_id = "supplychain.tool_squatting"
    verified_id = "auth.unauthenticated_access"
    assert get_confidence_for(heuristic_id) == "heuristic"
    assert get_confidence_for(verified_id) == "verified"

    f_heuristic = _finding(heuristic_id, passed=False)
    f_verified = _finding(verified_id, passed=False)
    report = _report_with(f_heuristic, f_verified)

    stats = apply_noise_reduction(report, min_confidence="verified")

    assert f_heuristic.suppressed
    assert not f_verified.suppressed
    assert stats["below_confidence_floor"] == 1
    assert report.summary()["confirmed_findings"] == 1


def test_suppressed_finding_never_gates_policy_verdict():
    from engine.reporting.suppress import apply_noise_reduction
    from engine.policy.engine import PolicyEngine

    f = _finding("auth.unauthenticated_access", passed=False)  # BLOCK por default en policy.yaml
    report = _report_with(f)
    apply_noise_reduction(report, min_confidence="verified")
    assert not f.suppressed  # es 'verified', no debería suprimirse con este piso -- sanity check

    f2 = _finding("supplychain.tool_squatting", passed=False)  # heurístico
    report2 = _report_with(f2)
    apply_noise_reduction(report2, min_confidence="verified")
    assert f2.suppressed
    verdict = PolicyEngine().evaluate(report2, "production")
    assert verdict["overall"] == "ALLOW"  # el único finding está suprimido -> no gatea
    assert verdict["by_finding"][0]["verdict"] == "SUPPRESSED"


def test_cross_server_detects_exact_name_collision_and_cross_server_chain():
    from engine.crossserver import analyze_cross_server

    reports = {
        "server_a": [
            {"name": "read_secret", "description": "reads a secret from disk"},
            {"name": "admin_delete", "description": "deletes everything"},
        ],
        "server_b": [
            {"name": "admin_delete", "description": "unrelated tool that happens to collide in name"},
            {"name": "send_webhook", "description": "posts data to an external webhook url"},
        ],
    }
    result = analyze_cross_server(reports)

    assert result["applicable"]
    shadow_kinds = {item["kind"] for item in result["tool_shadowing"]}
    assert "exact_name_collision" in shadow_kinds

    chain_pairs = {(c["tools"][0], c["tools"][1]) for c in result["cross_server_exfil_chains"]}
    assert ("read_secret", "send_webhook") in chain_pairs


def test_cross_server_not_applicable_with_single_server():
    from engine.crossserver import analyze_cross_server
    result = analyze_cross_server({"only_one": [{"name": "t", "description": ""}]})
    assert not result["applicable"]
    assert result["tool_shadowing"] == []


def test_credential_content_signatures_match_real_formats_not_noise():
    from payloads.canary import CREDENTIAL_CONTENT_SIGNATURES

    ssh_key = "-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1r...\n-----END OPENSSH PRIVATE KEY-----"
    aws_creds = "[default]\naws_access_key_id = AKIAFAKEEXAMPLE\naws_secret_access_key = fakefakefake"
    mcp_config = '{"mcpServers": {"other-server": {"url": "https://x", "headers": {"Authorization": "Bearer secret"}}}}'
    benign = "just a normal tool response, nothing sensitive about machines or passwords in general"

    def hits(text):
        return [label for sig, label in CREDENTIAL_CONTENT_SIGNATURES if sig in text]

    assert hits(ssh_key)
    assert hits(aws_creds)
    assert hits(mcp_config)
    assert not hits(benign)


def test_credential_harvest_payloads_target_known_sensitive_paths():
    from payloads.canary import credential_harvest_traversal_payloads
    payloads = credential_harvest_traversal_payloads()
    assert any("id_rsa" in p for p in payloads)
    assert any("mcp.json" in p or "claude_desktop_config" in p for p in payloads)
    assert any("aws" in p.lower() for p in payloads)


def test_aivss_only_computed_when_category_given():
    r_with = risk_for("adv.destructive_no_confirmation", confidence="verified", category="adversarial")
    r_without = risk_for("adv.destructive_no_confirmation", confidence="verified")
    assert r_with["aivss"] is not None
    assert r_without["aivss"] is None


def test_aivss_bounded_and_marked_as_approximation():
    r = risk_for("adv.destructive_no_confirmation", confidence="verified", category="adversarial")
    aivss = r["aivss"]
    assert 0.0 <= aivss["score"] <= 10.0
    assert aivss["is_approximation"] is True
    assert aivss["cvss_base"] == r["cvss_score"]


def test_aivss_amplifies_more_for_adversarial_than_static():
    # mismo CVSS base hipotético, pero adversarial tiene factores agénticos más altos que static
    # -- el score AIVSS de una categoría más "agéntica" debería ser mayor o igual, nunca menor.
    from engine.core.risk import aivss_for
    adversarial = aivss_for(cvss_base=5.0, category="adversarial", confidence="verified")
    static = aivss_for(cvss_base=5.0, category="static", confidence="verified")
    assert adversarial["score"] >= static["score"]


def test_aivss_dampens_heuristic_confidence_vs_verified():
    from engine.core.risk import aivss_for
    verified = aivss_for(cvss_base=5.0, category="adversarial", confidence="verified")
    heuristic = aivss_for(cvss_base=5.0, category="adversarial", confidence="heuristic")
    assert heuristic["score"] <= verified["score"]


def test_known_cve_check_matches_vulnerable_version_not_patched():
    from engine.static.known_cves import check_known_cves
    hits_old = check_known_cves("filesystem", "2025.6.0")
    assert any(h["cve"] == "CVE-2025-53109" for h in hits_old)
    hits_new = check_known_cves("filesystem", "2025.7.1")
    assert not any(h["cve"] == "CVE-2025-53109" for h in hits_new)
    assert check_known_cves("some-unrelated-server", "1.0.0") == []


def test_typosquatting_flags_near_match_not_exact_or_unrelated():
    from engine.static.typosquatting import check_typosquatting
    assert check_typosquatting("mcp-server-fetch") is None  # exacto, legítimo
    assert check_typosquatting("my-totally-custom-internal-tool") is None  # sin relación, no es sospechoso
    near = check_typosquatting("mcp-server-fetchh")  # typo de un caracter
    assert near is not None
    assert near["matched_against"] == "mcp-server-fetch"


def test_network_reachability_is_not_overrated_as_high():
    # exposure.network_reachability es contextual (clasifica blast radius), no un ataque en
    # sí -- encontrado como des-calibración real corriendo Ares contra mcp.deepwiki.com, donde
    # salía "High" solo por AV:N/AC:L inflando el likelihood de la matriz OWASP.
    r = risk_for("exposure.network_reachability", confidence="verified")
    assert r["risk_rating"] in ("Note", "Low", "Medium")


def test_sandbox_nproc_is_relative_not_absolute():
    """Regresión directa de un bug real: la primera versión de esto fijaba --nproc=64
    (absoluto) y RLIMIT_NPROC es un tope sobre el TOTAL de procesos/threads que YA tiene
    el usuario en todo el host -- tumbó la suite de tests entera (59 procesos del user
    en una shell vacía, antes de que Ares lance nada). El default tiene que ser relativo
    a lo que ya hay, nunca un número absoluto adivinado."""
    if not prlimit_available():
        return  # sin prlimit en este host -- no aplica, wrap_command se degrada aparte
    base = _current_user_proc_count()
    assert base is not None and base > 0

    command, args = wrap_command("python3", ["server.py"], nproc=None)
    # command/args pueden venir envueltos también por bwrap (capa externa) -- el --nproc=
    # de prlimit queda DENTRO de args igual, nested o no.
    nproc_arg = next(a for a in args if a.startswith("--nproc="))
    limit = int(nproc_arg.split("=")[1])
    # tiene que ser bastante más alto que lo que YA está corriendo (sino rompe de entrada),
    # y no un valor mágico desconectado de la realidad del host.
    assert limit >= base + 1
    assert limit == base + NPROC_HEADROOM


def test_sandbox_wrap_command_layers_compose_correctly():
    """bwrap envuelve a prlimit (no al revés): con las dos capas disponibles, el
    comando externo tiene que ser bwrap y 'prlimit' tiene que aparecer DENTRO de sus
    args -- confirma que la composición es bwrap(namespaces) -> prlimit(rlimits) ->
    comando real, no al revés ni solo una de las dos perdida."""
    command, args = wrap_command("python3", ["server.py"])
    layers = sandbox_status()
    if layers["bwrap"]:
        assert command == "bwrap"
        if layers["prlimit"]:
            assert "prlimit" in args
        assert "python3" in args and "server.py" in args
    elif layers["prlimit"]:
        assert command == "prlimit"
    else:
        assert (command, args) == ("python3", ["server.py"])


def test_sandbox_network_cutoff_is_conditional_on_allow_network():
    """--unshare-net (bwrap) tiene que estar SOLO cuando allow_network=False (default) --
    confirmado empíricamente que corta TODA la red del subprocess, incluido loopback
    hacia el host. Con allow_network=True (mismo flag que --allow-network ya usa para
    otros side-effects de red reales) no debe aparecer, para no romper servers que
    legítimamente necesitan salir a red ni los tests que dependen de eso (adv.ssrf_exfil)."""
    if not bwrap_available():
        return
    _, args_blocked = wrap_command("python3", ["server.py"], allow_network=False)
    _, args_allowed = wrap_command("python3", ["server.py"], allow_network=True)
    assert "--unshare-net" in args_blocked
    assert "--unshare-net" not in args_allowed
    # las otras capas de namespace siempre deben seguir activas independientemente de la red
    for args in (args_blocked, args_allowed):
        assert "--unshare-pid" in args
        assert "--unshare-ipc" in args


def test_sandbox_restores_script_path_shadowed_by_tmp_tmpfs(tmp_path):
    """Bug real encontrado probando esto mismo: `--tmpfs /tmp` (necesario para que el
    target tenga un /tmp propio y escribible) tapa con un tmpfs VACÍO cualquier cosa
    que ya hubiera en /tmp -- incluido un script de prueba servido desde ahí (ej. el
    scratchpad de una sesión de Claude Code, que vive bajo /tmp/claude-.../). Sin este
    fix, el subprocess ni siquiera podía encontrar su propio archivo ('No such file or
    directory') apenas bwrap estaba disponible."""
    if not bwrap_available():
        return
    # tmp_path de pytest cae bajo /tmp en Linux -- mismo escenario real que encontró el bug
    script = tmp_path / "server.py"
    script.write_text("print('hola')")
    assert str(script).startswith("/tmp")

    _, args = wrap_command("python3", [str(script)])
    # el --ro-bind puntual del script tiene que aparecer DESPUÉS del --tmpfs /tmp en la
    # lista (bwrap aplica binds en orden; el de más atrás gana en la misma ruta).
    idx_tmpfs = args.index("--tmpfs")
    ro_bind_indices = [i for i, a in enumerate(args) if a == "--ro-bind" and args[i + 1] == str(script)]
    assert ro_bind_indices, f"falta un --ro-bind puntual para {script} en {args}"
    assert ro_bind_indices[0] > idx_tmpfs


def test_cross_server_findings_produce_real_scoreable_findings():
    """Regresión directa de un gap real: antes de esto, MCP09:2025 (Shadow MCP Servers)
    solo existía como un dict suelto que cmd_full imprimía en terminal -- nunca pasaba
    por calculate_score/PolicyEngine/SARIF, ni siquiera cuando el propio código ya
    marca severity='critical' para directive_cross_reference. Acá se verifica que
    cross_server_findings() SÍ produce Finding reales, que SÍ mueven el score."""
    reports = {
        "server-a": [{"name": "delete_all", "description": "Deletes everything."}],
        "server-b": [{"name": "delete_all", "description": "Also deletes everything."}],
    }
    findings = cross_server_findings(reports)
    assert any(f.test_id == "crossserver.tool_shadowing" and not f.passed for f in findings)

    report = ScanReport(scan_id="t", target_name="(correlación cross-server)", started_at="", findings=findings)
    score = calculate_score(report)
    assert score["score"] < 100  # el shadowing SÍ tiene que pesar en el score, no quedar afuera

    policy = PolicyEngine().evaluate(report, "production")
    assert policy["overall"] in ("CONDITIONAL", "BLOCK")  # nunca ALLOW con un hallazgo confirmado real


def test_cross_server_findings_empty_below_two_servers():
    assert cross_server_findings({"solo-uno": []}) == []


def test_every_registered_test_has_framework_coverage():
    """'Que ninguno se nos escape': todo test_id REALMENTE registrado (no solo los
    que alguien se acordó de taguear) tiene que resolver al menos un framework via
    get_frameworks_for() -- si alguien suma un test nuevo y se olvida de frameworks.py,
    esto lo agarra acá en vez de en una auditoría manual."""
    import engine.orchestrator  # fuerza el import de todos los módulos de test, autoregistro
    from engine.core.registry import all_tests
    from engine.core.frameworks import get_frameworks_for

    missing = [tid for tid in all_tests() if not get_frameworks_for(tid)]
    assert missing == [], f"test(s) sin ningún tag de framework: {missing}"


def test_required_string_params_order_matters_for_id_vs_content_split():
    """auth.cross_session_context_bleed asume que el PRIMER parámetro string requerido es
    el identificador y el resto es contenido -- confirma que el helper preserva el orden
    de declaración del schema (no un set/dict desordenado) y filtra lo no-requerido/no-string."""
    from engine.auth.tests import _required_string_params
    schema = {
        "properties": {
            "name": {"type": "string"},
            "content": {"type": "string"},
            "optional_note": {"type": "string"},
            "count": {"type": "integer"},
        },
        "required": ["name", "content"],
    }
    assert _required_string_params(schema) == ["name", "content"]


def test_all_framework_map_tags_resolve_without_keyerror():
    """Cualquier typo en una key de ATLAS_TECHNIQUES/OWASP_MCP/OWASP_LLM/OWASP_API
    referenciada desde FRAMEWORK_MAP tiene que explotar ACÁ, en CI, no en medio de un
    scan real de un usuario."""
    from engine.core.frameworks import FRAMEWORK_MAP, get_frameworks_for
    for tid in FRAMEWORK_MAP:
        tags = get_frameworks_for(tid)
        assert tags, f"{tid} resuelve a una lista vacía"
        for tag in tags:
            assert tag.get("id") or tag["framework"] == "ATLAS"  # tácticas ATLAS sin ID puntual son válidas
            assert tag.get("name")
            assert tag.get("url", "").startswith("http")
