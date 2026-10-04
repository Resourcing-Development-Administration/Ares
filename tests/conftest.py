import os
import socket
import subprocess
import sys
import time

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
VULN_STDIO = os.path.join(ROOT, "target_server.py")
VULN_HTTP = os.path.join(ROOT, "target_server_http.py")
SAFE_STDIO = os.path.join(ROOT, "tests", "fixtures", "safe_server.py")
RUGPULLED_STDIO = os.path.join(ROOT, "tests", "fixtures", "safe_server_rugpulled.py")
VALIDATING_STDIO = os.path.join(ROOT, "tests", "fixtures", "validating_server.py")

HTTP_HOST, HTTP_PORT = "127.0.0.1", 8765
HTTP_URL = f"http://{HTTP_HOST}:{HTTP_PORT}/mcp"


def _wait_for_port(host: str, port: int, timeout: float = 10.0):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            with socket.create_connection((host, port), timeout=0.3):
                return
        except OSError:
            time.sleep(0.1)
    raise RuntimeError(f"{host}:{port} nunca abrió (fixture HTTP no arrancó)")


@pytest.fixture(scope="session")
def http_fixture_url():
    """Levanta target_server_http.py una vez por sesión de test y lo apaga al final."""
    proc = subprocess.Popen(
        [sys.executable, VULN_HTTP],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    try:
        _wait_for_port(HTTP_HOST, HTTP_PORT)
        yield HTTP_URL
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()


def stdio_connection(script_path: str) -> dict:
    return {"command": sys.executable, "args": [script_path]}
