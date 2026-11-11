"""
Tests del módulo de APIs (REST + GraphQL). Cada detector tiene un caso positivo (fixture
vulnerable) y uno negativo (fixture seguro) -- mismo criterio que test_fuzz_chain.py.
"""
import os
import socket
import subprocess
import sys
import time

import pytest

from engine.api.runner import run_api_scan

FIX = os.path.join(os.path.dirname(os.path.abspath(__file__)), "fixtures")


def _free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@pytest.fixture
def rest_api(request):
    mode = request.param
    port = _free_port()
    env = {**os.environ, "ARES_FIXTURE_MODE": mode}
    p = subprocess.Popen([sys.executable, os.path.join(FIX, "rest_api_server.py"), str(port)], env=env,
                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    t0 = time.monotonic()
    while time.monotonic() - t0 < 10:
        try:
            socket.create_connection(("127.0.0.1", port), timeout=0.3).close()
            break
        except OSError:
            time.sleep(0.1)
    yield f"http://127.0.0.1:{port}"
    p.kill(); p.wait()


def failed(report, test_id):
    return [f for f in report.findings if f.test_id == test_id and not f.passed]


ALL_REST = ["api.sensitive_paths", "api.security_headers", "api.cors", "api.auth_required", "api.bola",
            "api.verbose_errors", "api.method_tampering", "api.mass_assignment", "api.jwt"]
JWT_NONE = "eyJhbGciOiJub25lIn0.eyJzdWIiOiJhbGljZSJ9."


@pytest.mark.parametrize("rest_api", ["vulnerable"], indirect=True)
async def test_rest_detectors_fire_on_vulnerable_fixture(rest_api):
    report = await run_api_scan(base_url=rest_api, spec_source=f"{rest_api}/openapi.json",
                                selected_tests=ALL_REST, auth_a={"Authorization": "Bearer alice-token"},
                                jwt=JWT_NONE)
    hit = {f.test_id for f in report.findings if not f.passed}
    for tid in ["api.sensitive_paths", "api.cors", "api.auth_required", "api.bola", "api.jwt",
                "api.mass_assignment", "api.method_tampering"]:
        assert tid in hit, f"{tid} no disparó contra el fixture vulnerable"


@pytest.mark.parametrize("rest_api", ["safe"], indirect=True)
async def test_rest_detectors_no_false_positive_on_safe_fixture(rest_api):
    report = await run_api_scan(base_url=rest_api, spec_source=f"{rest_api}/openapi.json",
                                selected_tests=ALL_REST, auth_a={"Authorization": "Bearer alice-token"})
    hit = {f.test_id for f in report.findings if not f.passed}
    assert hit == set(), f"falso positivo contra el fixture seguro: {hit}"


@pytest.mark.parametrize("rest_api", ["vulnerable"], indirect=True)
async def test_bola_confirms_cross_user_access(rest_api):
    report = await run_api_scan(base_url=rest_api, spec_source=f"{rest_api}/openapi.json",
                                selected_tests=["api.bola"], auth_a={"Authorization": "Bearer alice-token"})
    hits = failed(report, "api.bola")
    assert hits and all(f.confidence == "verified" for f in hits)
