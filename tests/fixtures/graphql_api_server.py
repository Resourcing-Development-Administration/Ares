"""
Endpoint GraphQL minimo para probar engine/api/graphql_tests.py de punta a punta -- antes de
esto, ningun test ejercitaba _probe_graphql/graphql_tests.py contra un fixture real (solo REST
tenia cobertura en rest_api_server.py). Dos modos (env ARES_FIXTURE_MODE), mismo criterio que
rest_api_server.py:
  vulnerable -> introspeccion sin auth, sugerencias de campo ("did you mean"), batching por
                alias sin limite, queries sensibles (me/users) responden sin auth, mutations
                ejecutables por GET.
  safe       -> introspeccion requiere auth, sin sugerencias, alias limitados a 5, me/users
                requieren auth, GET rechazado (405).
Uso: python graphql_api_server.py <puerto>
"""
import json
import os
import re
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs

MODE = os.environ.get("ARES_FIXTURE_MODE", "vulnerable")

SCHEMA_TYPES = [
    {"name": "Query", "kind": "OBJECT", "fields": [
        {"name": "__typename", "args": []}, {"name": "me", "args": []},
        {"name": "users", "args": []}, {"name": "admin", "args": []},
        {"name": "comment", "args": []},
    ]},
    {"name": "User", "kind": "OBJECT", "fields": [{"name": "id", "args": []}, {"name": "name", "args": []}]},
    # "replies" matcheable por el hint de campo recursivo de _probe_graphql (regex repl(y|ies)).
    {"name": "Comment", "kind": "OBJECT", "fields": [{"name": "id", "args": []}, {"name": "replies", "args": []}]},
]
_ALIAS_RE = re.compile(r"a(\d+):\s*__typename")
_SINGLE_FIELD_RE = re.compile(r"^\{\s*(\w+)\s*\{\s*__typename\s*\}\s*\}$")


def _handle(query: str, has_auth: bool) -> dict:
    q = (query or "").strip()
    if "__schema" in q:
        if MODE == "vulnerable" or has_auth:
            return {"data": {"__schema": {"queryType": {"name": "Query"}, "mutationType": None, "types": SCHEMA_TYPES}}}
        return {"errors": [{"message": "introspection disabled"}]}
    if "ares_nonexistent_field_zz" in q:
        if MODE == "vulnerable":
            return {"errors": [{"message": 'Cannot query field "ares_nonexistent_field_zz" on type "Query". Did you mean "users"?'}]}
        return {"errors": [{"message": 'Cannot query field "ares_nonexistent_field_zz" on type "Query".'}]}
    aliases = _ALIAS_RE.findall(q)
    if aliases:
        keep = aliases if MODE == "vulnerable" else aliases[:5]
        return {"data": {f"a{n}": "Query" for n in keep}}
    m = _SINGLE_FIELD_RE.match(q)
    if m:
        field = m.group(1)
        if MODE == "vulnerable" and field == "me":
            return {"data": {"me": {"__typename": "User"}}}
        if MODE == "vulnerable" and field == "users":
            return {"data": {"users": [{"__typename": "User"}]}}
        return {"data": {field: None}}
    if q == "{ __typename }":
        return {"data": {"__typename": "Query"}}
    return {"data": {}}


class H(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def _send(self, code, body):
        data = json.dumps(body).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0) or 0)
        raw = self.rfile.read(length) if length else b"{}"
        try:
            body = json.loads(raw or b"{}")
        except Exception:
            body = {}
        if not self.path.startswith("/graphql"):
            self._send(404, {"error": "not found"})
            return
        has_auth = bool(self.headers.get("Authorization"))
        self._send(200, _handle(body.get("query"), has_auth))

    def do_GET(self):
        if not self.path.startswith("/graphql"):
            self._send(404, {"error": "not found"})
            return
        if MODE != "vulnerable":
            self._send(405, {"error": "method not allowed"})
            return
        qs = parse_qs(urlparse(self.path).query)
        query = (qs.get("query") or [""])[0]
        has_auth = bool(self.headers.get("Authorization"))
        self._send(200, _handle(query, has_auth))


def main():
    port = int(sys.argv[1])
    ThreadingHTTPServer(("127.0.0.1", port), H).serve_forever()


if __name__ == "__main__":
    main()
