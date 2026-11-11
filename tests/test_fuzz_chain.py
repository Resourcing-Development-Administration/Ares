"""
Tests de los detectores de fuzzing de protocolo, cadenas multi-step y de las correcciones
anti-falso-positivo (rate limit, SSRF, squatting, known-CVE...). Cada detector tiene un caso
POSITIVO (fixture deliberadamente vulnerable) y uno NEGATIVO (fixture correcto) -- sin el negativo
un detector que dispara siempre pasaría los tests.
"""
import os
import socket
import subprocess
import sys
import time

import pytest

from engine.core.models import ScanConfig
from engine.orchestrator import run_scan

FIX = os.path.join(os.path.dirname(os.path.abspath(__file__)), "fixtures")


def failed(report, test_id):
    return [f for f in report.findings if f.test_id == test_id and not f.passed]


def stdio_conn(script, mode):
    return {"command": sys.executable, "args": [os.path.join(FIX, script)], "env": {"ARES_FIXTURE_MODE": mode}}


async def scan_stdio(script, mode, tests, **kw):
    cfg = ScanConfig(target_name="t", transport="stdio", connection=stdio_conn(script, mode),
                     selected_tests=tests, test_timeout_s=90, **kw)
    return await run_scan(cfg)


# --- protocol.jsonrpc_malformed_fuzz ------------------------------------------------------------

async def test_malformed_fuzz_detects_crash_and_reproduces():
    r = await scan_stdio("rawjsonrpc_server.py", "crash", ["protocol.jsonrpc_malformed_fuzz"])
    hits = failed(r, "protocol.jsonrpc_malformed_fuzz")
    assert hits and any("se cae" in f.title for f in hits)
    assert all(f.confidence == "verified" for f in hits if "se cae" in f.title)


async def test_malformed_fuzz_detects_hang_on_batch():
    r = await scan_stdio("rawjsonrpc_server.py", "hang", ["protocol.batch_cancel_robustness"])
    hits = failed(r, "protocol.batch_cancel_robustness")
    assert hits and any("deja de responder" in f.title for f in hits)


async def test_malformed_fuzz_detects_traceback_leak_as_heuristic():
    r = await scan_stdio("rawjsonrpc_server.py", "leak", ["protocol.jsonrpc_malformed_fuzz"])
    hits = failed(r, "protocol.jsonrpc_malformed_fuzz")
    assert hits and any("filtra" in f.title for f in hits)
    assert all(f.confidence == "heuristic" for f in hits if "filtra" in f.title)


async def test_malformed_fuzz_no_false_positive_on_good_server():
    r = await scan_stdio("rawjsonrpc_server.py", "good",
                         ["protocol.jsonrpc_malformed_fuzz", "protocol.batch_cancel_robustness"])
    assert not failed(r, "protocol.jsonrpc_malformed_fuzz")
    assert not failed(r, "protocol.batch_cancel_robustness")


async def test_malformed_fuzz_no_false_positive_on_sdk_server():
    """El server FastMCP del propio SDK maneja todo: no debe salir nada."""
    r = await scan_stdio("safe_server.py", "good", ["protocol.jsonrpc_malformed_fuzz", "protocol.batch_cancel_robustness"])
    assert not failed(r, "protocol.jsonrpc_malformed_fuzz")
    assert not failed(r, "protocol.batch_cancel_robustness")


# --- protocol.session_replay (http) ---------------------------------------------------------------

def _free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@pytest.fixture
def raw_http(request):
    mode = request.param
    port = _free_port()
    env = {**os.environ, "ARES_FIXTURE_MODE": mode}
    p = subprocess.Popen([sys.executable, os.path.join(FIX, "rawhttp_server.py"), str(port)], env=env,
                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    t = time.monotonic()
    while time.monotonic() - t < 10:
        try:
            socket.create_connection(("127.0.0.1", port), timeout=0.3).close()
            break
        except OSError:
            time.sleep(0.1)
    yield f"http://127.0.0.1:{port}/mcp"
    p.kill(); p.wait()


async def _scan_http(url, tests):
    from engine.protocol import rawrpc  # noqa: F401  (asegura import)
    cfg = ScanConfig(target_name="t", transport="http", connection={"url": url}, selected_tests=tests, test_timeout_s=60)
    return await run_scan(cfg)


@pytest.mark.parametrize("raw_http", ["lax"], indirect=True)
async def test_session_replay_detects_lax_server(raw_http):
    from engine.protocol.fuzz_tests import session_replay
    from engine.protocol import rawrpc
    class T:  # target mínimo: el test solo usa transport y _resolved_headers
        transport = "http"
        def _resolved_headers(self): return {}
    ctx = {"transport": "http", "connection": {"url": raw_http}}
    out = await session_replay(T(), ctx)
    titles = " | ".join(f.title for f in out if not f.passed)
    assert "inventado" in titles and "sin Mcp-Session-Id" in titles and "terminada con DELETE" in titles


@pytest.mark.parametrize("raw_http", ["strict"], indirect=True)
async def test_session_replay_no_false_positive_on_strict_server(raw_http):
    from engine.protocol.fuzz_tests import session_replay
    class T:
        transport = "http"
        def _resolved_headers(self): return {}
    out = await session_replay(T(), {"transport": "http", "connection": {"url": raw_http}})
    assert all(f.passed for f in out), [f.title for f in out if not f.passed]


# --- adv.multistep_chain / adv.stored_injection_roundtrip ------------------------------------------

async def test_multistep_chain_confirms_3_and_4_tool_chains():
    r = await scan_stdio("chain_server.py", "vulnerable", ["adv.multistep_chain"])
    hits = failed(r, "adv.multistep_chain")
    assert hits, "read_inventory -> format_text -> send_report debería confirmarse"
    assert all(f.confidence == "verified" for f in hits)
    assert any(f.target.count("->") >= 2 for f in hits)


async def test_multistep_chain_no_false_positive_when_data_does_not_flow():
    """Misma fuente y mismo emisor, pero los intermedios NO devuelven el dato: no hay cadena."""
    r = await scan_stdio("chain_server.py", "safe", ["adv.multistep_chain"])
    assert not failed(r, "adv.multistep_chain")


async def test_stored_injection_roundtrip_detects_unsanitized_store():
    r = await scan_stdio("chain_server.py", "vulnerable", ["adv.stored_injection_roundtrip"])
    hits = failed(r, "adv.stored_injection_roundtrip")
    assert hits and hits[0].target == "save_note->get_notes"


async def test_stored_injection_roundtrip_no_false_positive_when_reader_does_not_echo():
    r = await scan_stdio("chain_server.py", "safe", ["adv.stored_injection_roundtrip"])
    assert not failed(r, "adv.stored_injection_roundtrip")


# --- anti-falsos-positivos --------------------------------------------------------------------------

async def test_rate_limit_not_applicable_to_stdio():
    r = await scan_stdio("safe_server.py", "good", ["dynamic.rate_limit"])
    assert not failed(r, "dynamic.rate_limit")


def test_squat_kind_flags_real_squats_not_prefix_families():
    from engine.supplychain.similarity import squat_kind
    assert squat_kind("read_file", "read_fiel") == "typo"
    assert squat_kind("read_file", "readFile") == "separator"
    assert squat_kind("read_file", "reаd_file") == "homoglyph"   # 'а' cirílica
    for a, b in [("get_level", "set_level"), ("mcpgoat_get_level", "mcpgoat_set_level"),
                 ("read_collector", "read_project_file"), ("search_notes", "search_note"),
                 ("get_user", "delete_user")]:
        assert squat_kind(a, b) is None, (a, b)


def test_known_cve_requires_exact_official_name_and_calver():
    from engine.static.known_cves import check_known_cves, check_known_cves_detailed
    assert check_known_cves("vulnerable-mcp-server-filesystem-workspace-actions", "0.1.0") == []
    assert check_known_cves("github-tools", "1.0.0") == []
    assert check_known_cves("secure-filesystem-server", "0.2.0") == []            # versión no comparable
    assert check_known_cves_detailed("secure-filesystem-server", "0.2.0")["indeterminate"]
    assert check_known_cves("secure-filesystem-server", "2025.6.0")                # CalVer anterior al fix


async def test_ssrf_not_flagged_when_error_only_echoes_the_url():
    """target_server.read_file solo abre archivos locales: su error cita la URL ('computeMetadata')
    pero no hizo ninguna conexión. Antes salía como 'Posible SSRF' (falso positivo)."""
    from conftest import VULN_STDIO
    cfg = ScanConfig(target_name="t", transport="stdio", connection={"command": sys.executable, "args": [VULN_STDIO]},
                     selected_tests=["adv.ssrf_exfil"], allow_network_side_effects=True, test_timeout_s=120)
    r = await run_scan(cfg)
    assert "read_file" not in {f.target for f in failed(r, "adv.ssrf_exfil")}
