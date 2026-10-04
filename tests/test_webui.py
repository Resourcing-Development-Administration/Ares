"""
Regresión directa de un bug real: `app = FastAPI(dependencies=[Depends(require_token)])`
con `require_token(request: Request, ...)` rompía TODO WebSocket (/ws/scan, /ws/full) con
un 500 en el handshake -- "require_token() missing 1 required positional argument:
'request'" -- incluso con ARES_DASHBOARD_TOKEN sin configurar, porque FastAPI intenta
resolver esa dependency también en el scope de un WebSocket, donde no existe un objeto
Request HTTP. Se encontró probando esto en vivo, nunca con el test suite -- por eso existe
este archivo: un gate de auth que nunca se probó contra un WebSocket real es un gate que
puede estar silenciosamente roto para la mitad de las rutas del dashboard.

Fix: `@app.middleware("http")` en vez de `dependencies=[Depends(...)]` a nivel app --
Starlette nunca aplica middleware HTTP al upgrade de un WebSocket, así que el gate de
WebSocket queda como el chequeo manual (`websocket_token_ok`) al principio de cada
`@app.websocket(...)`, no "defensa en profundidad" sobre algo que ya protegía la ruta.
"""
import webui.app as appmod
from fastapi.testclient import TestClient


def test_websocket_handshake_succeeds_without_token_configured(monkeypatch):
    """El bug real: esto solía tirar 500 en el handshake SIEMPRE, con o sin
    ARES_DASHBOARD_TOKEN -- la causa era la Depends(require_token) a nivel app,
    no el valor del token."""
    monkeypatch.setattr(appmod, "DASHBOARD_TOKEN", None)
    client = TestClient(appmod.app)
    with client.websocket_connect("/ws/scan") as ws:
        ws.close()


def test_websocket_rejected_without_token_when_configured(monkeypatch):
    monkeypatch.setattr(appmod, "DASHBOARD_TOKEN", "s3cr3t")
    client = TestClient(appmod.app)
    try:
        with client.websocket_connect("/ws/scan"):
            assert False, "no debería conectar sin token"
    except Exception:
        pass  # el handshake debe fallar (close/reject), no completarse


def test_websocket_accepted_with_correct_token_in_query(monkeypatch):
    monkeypatch.setattr(appmod, "DASHBOARD_TOKEN", "s3cr3t")
    client = TestClient(appmod.app)
    with client.websocket_connect("/ws/scan?token=s3cr3t") as ws:
        ws.close()


def test_http_route_401_without_token_when_configured(monkeypatch):
    monkeypatch.setattr(appmod, "DASHBOARD_TOKEN", "s3cr3t")
    client = TestClient(appmod.app)
    r = client.get("/api/tests")
    assert r.status_code == 401


def test_http_route_200_with_correct_token(monkeypatch):
    monkeypatch.setattr(appmod, "DASHBOARD_TOKEN", "s3cr3t")
    client = TestClient(appmod.app)
    r = client.get("/api/tests", headers={"X-Ares-Token": "s3cr3t"})
    assert r.status_code == 200


def test_http_route_200_without_any_token_when_not_configured(monkeypatch):
    monkeypatch.setattr(appmod, "DASHBOARD_TOKEN", None)
    client = TestClient(appmod.app)
    r = client.get("/api/tests")
    assert r.status_code == 200
