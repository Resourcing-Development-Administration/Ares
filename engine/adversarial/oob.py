"""
Listener HTTP local mínimo para confirmar SSRF por callback real (out-of-band):
en vez de solo inferir "probablemente se conectó" por patrones en la respuesta
(heurística), le damos al target una URL con un token único; si ese token
llega de vuelta como un hit HTTP real a este listener, la explotación queda
VERIFICADA, no inferida.

Opt-in vía --oob-callback-host HOST:PUERTO -- HOST:PUERTO debe ser alcanzable
por el server bajo prueba (mismo host, misma red interna, o una IP/puerto
públicos si el target puede salir a Internet). Sin esa red real, esto no
sirve de nada y ade rlo es responsabilidad de quien corre el scan.

Deliberadamente NO usa ningún servicio externo de "collaborator" (Burp
Collaborator, interactsh, etc.) -- es un listener propio, local, sin
dependencia de terceros.
"""
from __future__ import annotations
import secrets
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


class _Handler(BaseHTTPRequestHandler):
    def log_message(self, *a, **kw):
        pass  # silencioso, no ensuciar la consola del scan

    def _record(self):
        token = self.path.strip("/").split("/")[0]
        self.server.oob_hits.setdefault(token, []).append({
            "remote_addr": self.client_address[0],
            "path": self.path,
            "at": time.time(),
        })
        self.send_response(204)
        self.end_headers()

    def do_GET(self):
        self._record()

    def do_POST(self):
        self._record()


class OOBListener:
    def __init__(self, bind_host: str = "0.0.0.0", port: int = 0):
        self._server = ThreadingHTTPServer((bind_host, port), _Handler)
        self._server.oob_hits = {}
        self.port = self._server.server_address[1]
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)

    def __enter__(self) -> "OOBListener":
        self._thread.start()
        return self

    def __exit__(self, *exc):
        self._server.shutdown()
        self._server.server_close()

    def new_token(self) -> str:
        return f"ares{secrets.token_hex(8)}"

    def callback_url(self, public_host: str, token: str) -> str:
        return f"http://{public_host}/{token}"

    def hits_for(self, token: str) -> list[dict]:
        return self._server.oob_hits.get(token, [])
