"""
API REST mínima para probar engine/api/rest_tests.py. Dos modos (env ARES_FIXTURE_MODE):
  vulnerable -> BOLA real, CORS refleja cualquier Origin con credentials, JWT alg=none aceptado,
                sin rate limit, mass assignment, .env servido, error verboso con traceback.
  safe       -> ownership validado, CORS con allowlist, alg=none rechazado, rate limit, sin mass
                assignment, sin archivos sensibles, error genérico.
Uso: python rest_api_server.py <puerto>
"""
import base64, json, os, sys, time, traceback
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

MODE = os.environ.get("ARES_FIXTURE_MODE", "vulnerable")
SECRET = "ares-fixture-secret"
USERS = {"1": {"id": "1", "name": "alice", "email": "alice@example.com", "balance": 100},
         "2": {"id": "2", "name": "bob", "email": "bob@example.com", "balance": 50}}
VALID_TOKEN = "Bearer alice-token"
_hits: dict = {}

OPENAPI = {
    "openapi": "3.0.0", "info": {"title": "fixture", "version": "1"},
    "paths": {
        "/users/{id}": {"get": {"summary": "obtener usuario", "parameters": [
            {"name": "id", "in": "path", "required": True, "schema": {"type": "string"}}]}},
        "/users/{id}/update": {"post": {"summary": "actualizar usuario", "parameters": [
            {"name": "id", "in": "path", "required": True, "schema": {"type": "string"}}],
            "requestBody": {"content": {"application/json": {"schema": {"type": "object",
                "properties": {"name": {"type": "string"}}}}}}}},
        "/login": {"post": {"summary": "login", "security": []}},
        "/search": {"get": {"summary": "buscar (publico a proposito)", "security": [], "parameters": [
            {"name": "q", "in": "query", "required": False, "schema": {"type": "string"}}]}},
        "/admin/stats": {"get": {"summary": "estadisticas internas (requiere auth)"}},
    },
}


def _b64(d): return base64.urlsafe_b64encode(json.dumps(d).encode()).decode().rstrip("=")


class H(BaseHTTPRequestHandler):
    def log_message(self, *a): pass

    def _send(self, code, body=None, headers=None, raw=False):
        data = body if raw else (json.dumps(body).encode() if body is not None else b"")
        self.send_response(code)
        if not raw:
            self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        for k, v in (headers or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(data)

    def _auth_user(self):
        auth = self.headers.get("Authorization", "")
        if auth == VALID_TOKEN:
            return USERS["1"]
        if auth.startswith("Bearer ") and "." in auth:
            # algún JWT: en modo vulnerable, aceptar si alg=none sin validar firma
            try:
                parts = auth[7:].split(".")
                header = json.loads(base64.urlsafe_b64decode(parts[0] + "=="))
                if MODE == "vulnerable" and header.get("alg") == "none":
                    return USERS["1"]
            except Exception:
                pass
        return None

    def do_GET(self):
        origin = self.headers.get("Origin")
        cors_headers = {}
        if origin:
            if MODE == "vulnerable":
                cors_headers = {"Access-Control-Allow-Origin": origin, "Access-Control-Allow-Credentials": "true"}
            elif origin in ("https://allowed.example",):
                cors_headers = {"Access-Control-Allow-Origin": origin}

        if self.path in ("/.env",):
            if MODE == "vulnerable":
                return self._send(200, raw=True, body=b"DB_PASSWORD=supersecret\nAWS_SECRET_ACCESS_KEY=x\n")
            return self._send(404)

        if self.path.startswith("/openapi.json"):
            return self._send(200, OPENAPI)

        if self.path.startswith("/users/"):
            uid = self.path.split("/users/")[1].split("/")[0].split("?")[0]
            user = self._auth_user()
            if MODE == "vulnerable":
                if not user:
                    return self._send(401, {"error": "unauthorized"})
                target = USERS.get(uid)
                return self._send(200, target, cors_headers) if target else self._send(404)
            else:
                if not user:
                    return self._send(401, {"error": "unauthorized"})
                if uid != user["id"]:
                    return self._send(403, {"error": "forbidden: not your resource"})
                return self._send(200, user, cors_headers)

        if self.path.startswith("/search"):
            from urllib.parse import urlparse, parse_qs
            q = (parse_qs(urlparse(self.path).query).get("q") or [""])[0]
            if "'" in q and MODE == "vulnerable":
                try:
                    raise ValueError("bad query")
                except Exception:
                    tb = traceback.format_exc()
                    return self._send(500, raw=True, body=(tb + "\n  File \"/home/deploy/app/db.py\", line 42").encode())
            return self._send(200, {"results": []}, cors_headers)

        if self.path.startswith("/admin/stats"):
            user = self._auth_user()
            if MODE == "vulnerable":
                return self._send(200, {"total_users": len(USERS)}, cors_headers)  # sin chequear auth: BFLA real
            if not user:
                return self._send(401, {"error": "unauthorized"})
            return self._send(200, {"total_users": len(USERS)}, cors_headers)

        return self._send(404, {"error": "not found"})

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        raw = self.rfile.read(length) if length else b""
        try:
            body = json.loads(raw) if raw else {}
        except Exception:
            body = {}

        if self.path.startswith("/login"):
            return self._send(200, {"token": VALID_TOKEN})

        if self.path.startswith("/users/") and self.path.endswith("/update"):
            uid = self.path.split("/users/")[1].split("/")[0]
            user = self._auth_user()
            if not user:
                return self._send(401, {"error": "unauthorized"})
            if MODE == "vulnerable":
                USERS.setdefault(uid, {}).update(body)  # bindea el body entero: mass assignment real
                return self._send(200, USERS[uid])
            else:
                allowed = {"name"}
                USERS[user["id"]].update({k: v for k, v in body.items() if k in allowed})
                return self._send(200, USERS[user["id"]])

        return self._send(404)

    def do_TRACE(self):
        if MODE == "vulnerable":
            return self._send(200, raw=True, body=b"TRACE ok")
        return self._send(501)


ThreadingHTTPServer(("127.0.0.1", int(sys.argv[1])), H).serve_forever()
