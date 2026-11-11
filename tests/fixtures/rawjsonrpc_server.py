"""
Server stdio escrito A MANO (sin SDK) para probar el fuzzing de protocolo de Ares.
MODE (env ARES_FIXTURE_MODE):
  good  -> maneja todo: JSON inválido => error -32700, nunca se cae ni se cuelga.
  crash -> JSON inválido provoca una excepción no manejada (el proceso muere).
  hang  -> un lote (array) entra en un bucle infinito.
  leak  -> el error de JSON inválido incluye un traceback con rutas absolutas.
"""
import json, os, sys, traceback

MODE = os.environ.get("ARES_FIXTURE_MODE", "good")
TOOLS = [{"name": "echo_text", "description": "Devuelve el texto.", "inputSchema": {
    "type": "object", "properties": {"text": {"type": "string", "maxLength": 100}}, "required": ["text"]}}]


def reply(obj):
    sys.stdout.write(json.dumps(obj) + "\n"); sys.stdout.flush()


def err(i, code, msg): reply({"jsonrpc": "2.0", "id": i, "error": {"code": code, "message": msg}})


def handle(m):
    if not isinstance(m, dict):
        return err(None, -32600, "Invalid Request")
    i, method = m.get("id"), m.get("method")
    if not isinstance(method, str):
        return err(i, -32600, "Invalid Request")
    if method == "initialize":
        return reply({"jsonrpc": "2.0", "id": i, "result": {"protocolVersion": "2025-06-18", "capabilities": {"tools": {}},
                                                              "serverInfo": {"name": "raw-fixture", "version": "1"}}})
    if method.startswith("notifications/"):
        return
    if method == "ping":
        return reply({"jsonrpc": "2.0", "id": i, "result": {}})
    if method == "tools/list":
        return reply({"jsonrpc": "2.0", "id": i, "result": {"tools": TOOLS}})
    if method == "tools/call":
        p = m.get("params")
        if not isinstance(p, dict) or not isinstance(p.get("arguments") or {}, dict):
            return err(i, -32602, "Invalid params")
        return reply({"jsonrpc": "2.0", "id": i, "result": {"content": [{"type": "text", "text": str((p.get("arguments") or {}).get("text", ""))[:100]}]}})
    err(i, -32601, "Method not found")


for line in sys.stdin:
    line = line.strip()
    if not line:
        continue
    try:
        msg = json.loads(line)
    except Exception:
        if MODE == "crash":
            raise SystemExit(3)
        if MODE == "leak":
            err(None, -32700, "Parse error: " + traceback.format_exc().replace("\n", " | ") + " at /home/deploy/app/server/main.py")
            continue
        err(None, -32700, "Parse error")
        continue
    if isinstance(msg, list):
        if MODE == "hang":
            while True:
                pass
        for e in msg:
            handle(e)
        continue
    handle(msg)
