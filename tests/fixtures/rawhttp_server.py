"""
Server HTTP mínimo escrito a mano para probar protocol.session_replay.
ARES_FIXTURE_MODE: lax (no valida Mcp-Session-Id, DELETE no invalida) | strict (valida todo).
Uso: python rawhttp_server.py <puerto>
"""
import json, os, secrets, sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

MODE = os.environ.get("ARES_FIXTURE_MODE", "lax")
SESSIONS: set = set()


class H(BaseHTTPRequestHandler):
    def log_message(self, *a): pass

    def _send(self, code, obj=None, headers=None):
        body = json.dumps(obj).encode() if obj is not None else b""
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        for k, v in (headers or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def _valid(self):
        if MODE == "lax":
            return True, None
        sid = self.headers.get("Mcp-Session-Id")
        if not sid:
            return False, 400
        return (sid in SESSIONS), 404

    def do_DELETE(self):
        sid = self.headers.get("Mcp-Session-Id")
        if MODE == "strict":
            SESSIONS.discard(sid)
        self._send(200)

    def do_POST(self):
        try:
            msg = json.loads(self.rfile.read(int(self.headers.get("Content-Length", 0))))
        except Exception:
            return self._send(400, {"jsonrpc": "2.0", "id": None, "error": {"code": -32700, "message": "Parse error"}})
        if not isinstance(msg, dict) or not isinstance(msg.get("method"), str):
            return self._send(400, {"jsonrpc": "2.0", "id": None, "error": {"code": -32600, "message": "Invalid Request"}})
        m, i = msg["method"], msg.get("id")
        if m == "initialize":
            sid = secrets.token_hex(16)
            SESSIONS.add(sid)
            return self._send(200, {"jsonrpc": "2.0", "id": i, "result": {
                "protocolVersion": "2025-06-18", "capabilities": {"tools": {}},
                "serverInfo": {"name": "rawhttp-fixture", "version": "1"}}}, {"Mcp-Session-Id": sid})
        ok, code = self._valid()
        if not ok:
            return self._send(code, {"jsonrpc": "2.0", "id": i, "error": {"code": -32000, "message": "bad session"}})
        if m.startswith("notifications/"):
            return self._send(202)
        if m == "ping":
            return self._send(200, {"jsonrpc": "2.0", "id": i, "result": {}})
        if m == "tools/list":
            return self._send(200, {"jsonrpc": "2.0", "id": i, "result": {"tools": [
                {"name": "echo_text", "description": "echo", "inputSchema": {"type": "object", "properties": {"text": {"type": "string", "maxLength": 50}}, "required": ["text"]}}]}})
        if m == "tools/call":
            return self._send(200, {"jsonrpc": "2.0", "id": i, "result": {"content": [{"type": "text", "text": "ok"}]}})
        self._send(200, {"jsonrpc": "2.0", "id": i, "error": {"code": -32601, "message": "Method not found"}})


ThreadingHTTPServer(("127.0.0.1", int(sys.argv[1])), H).serve_forever()
