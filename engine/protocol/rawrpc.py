"""
Canal JSON-RPC CRUDO contra el target, sin pasar por el SDK de MCP.

Por qué existe: el SDK (mcp.ClientSession) valida y normaliza TODO lo que envía -- es imposible
mandarle un frame malformado, un batch, un id con tipo raro o un Mcp-Session-Id inventado. Para
fuzzear el protocolo hay que hablar JSON-RPC a mano, en una conexión PROPIA (stdio: un segundo
subproceso del mismo comando, con el mismo sandbox; http: peticiones httpx directas con las mismas
credenciales). Así un crash provocado acá no mata la sesión principal del resto de los tests.

Todas las lecturas tienen timeout y tope de bytes: el target es hostil por definición.
"""
from __future__ import annotations
import asyncio
import contextlib
import json
import os
import signal
import time
import uuid
from dataclasses import dataclass, field
from typing import Optional

import httpx

MAX_READ_BYTES = 2_000_000       # tope de lo que se acepta del target en una respuesta
DEFAULT_TIMEOUT_S = 4.0
PROTOCOL_VERSION = "2025-06-18"


@dataclass
class Reply:
    """Resultado de enviar UN frame crudo."""
    messages: list = field(default_factory=list)   # objetos JSON-RPC parseados (dict/list)
    raw: str = ""                                    # texto crudo recibido (truncado)
    status: Optional[int] = None                     # solo http
    headers: dict = field(default_factory=dict)      # solo http
    timed_out: bool = False                          # no llegó ninguna respuesta a tiempo
    closed: bool = False                             # el canal murió (proceso salió / conexión rechazada)
    error: str = ""                                  # excepción de transporte, si hubo


def _parse_sse(text: str) -> list:
    out = []
    for block in text.replace("\r\n", "\n").split("\n\n"):
        data = "\n".join(l[5:].lstrip() for l in block.split("\n") if l.startswith("data:"))
        if data:
            with contextlib.suppress(Exception):
                out.append(json.loads(data))
    return out


def _flatten(msgs: list) -> list[dict]:
    flat = []
    for m in msgs:
        if isinstance(m, list):
            flat.extend(x for x in m if isinstance(x, dict))
        elif isinstance(m, dict):
            flat.append(m)
    return flat


class RawStdio:
    """Segundo subproceso del mismo comando, hablando JSON-RPC delimitado por saltos de línea."""

    kind = "stdio"

    def __init__(self, connection: dict):
        self.connection = connection
        self.proc: Optional[asyncio.subprocess.Process] = None
        self._queue: asyncio.Queue = asyncio.Queue()
        self._tasks: list[asyncio.Task] = []
        self.stderr_tail = b""

    async def start(self):
        from mcp.client.stdio import get_default_environment
        from engine.core.sandbox import wrap_command, DEFAULT_MEM_MB, DEFAULT_CPU_S, DEFAULT_NOFILE
        command = self.connection["command"]
        args = list(self.connection.get("args", []))
        sb = self.connection.get("sandbox") or {}
        env = {**get_default_environment(), **(self.connection.get("env") or {})}
        if sb.get("enabled", True):
            command, args = wrap_command(
                command, args, mem_mb=sb.get("mem_mb", DEFAULT_MEM_MB), cpu_s=sb.get("cpu_s", DEFAULT_CPU_S),
                nproc=sb.get("nproc"), nofile=sb.get("nofile", DEFAULT_NOFILE),
                allow_network=sb.get("allow_network", False),
                home=env.get("HOME"), mask_credentials=sb.get("mask_credentials", True),
            )
        self.proc = await asyncio.create_subprocess_exec(
            command, *args, env=env, stdin=asyncio.subprocess.PIPE, stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE, start_new_session=True, limit=MAX_READ_BYTES,
        )
        self._tasks = [asyncio.create_task(self._read_stdout()), asyncio.create_task(self._drain_stderr())]

    async def _read_stdout(self):
        try:
            while True:
                try:
                    line = await self.proc.stdout.readline()
                except ValueError:
                    continue  # línea > limit: asyncio ya descartó ese tramo; seguimos leyendo (no es EOF)
                if not line:
                    break
                await self._queue.put(line[:MAX_READ_BYTES])
        except Exception:
            pass
        finally:
            await self._queue.put(None)  # EOF

    async def _drain_stderr(self):
        with contextlib.suppress(Exception):
            while True:
                chunk = await self.proc.stderr.read(4096)
                if not chunk:
                    break
                self.stderr_tail = (self.stderr_tail + chunk)[-4096:]

    def alive(self) -> bool:
        return self.proc is not None and self.proc.returncode is None

    async def send(self, raw: bytes, wait_for_id=None, timeout: float = DEFAULT_TIMEOUT_S, settle: float = 0.4,
                   accept_null: bool = True) -> Reply:
        """Envía `raw` (+ salto de línea). Si `wait_for_id` no es None, espera la respuesta con ese id
        (o cualquier respuesta con id null) hasta `timeout`. Si es None (notificación / frame que no
        debería responder), solo junta lo que llegue en `settle` segundos -- el silencio NO es un fallo."""
        r = Reply()
        if not self.alive():
            r.closed = True
            return r
        try:
            self.proc.stdin.write(raw + b"\n")
            await asyncio.wait_for(self.proc.stdin.drain(), timeout=timeout)
        except Exception as e:
            r.closed, r.error = True, str(e)
            return r
        deadline = time.monotonic() + (timeout if wait_for_id is not None else settle)
        while True:
            left = deadline - time.monotonic()
            if left <= 0:
                r.timed_out = wait_for_id is not None
                break
            try:
                line = await asyncio.wait_for(self._queue.get(), timeout=left)
            except asyncio.TimeoutError:
                r.timed_out = wait_for_id is not None
                break
            if line is None:
                r.closed = True
                await self._queue.put(None)
                break
            r.raw += line.decode("utf-8", "replace")[:MAX_READ_BYTES]
            try:
                obj = json.loads(line)
            except Exception:
                continue
            r.messages.append(obj)
            flat = _flatten([obj])
            ids = (wait_for_id, None) if accept_null else (wait_for_id,)
            if wait_for_id is not None and any(m.get("id") in ids and ("result" in m or "error" in m) for m in flat):
                break
            if wait_for_id is None:
                continue
        return r

    async def close(self):
        if self.proc and self.proc.returncode is None:
            with contextlib.suppress(Exception):
                os.killpg(self.proc.pid, signal.SIGKILL)
        for t in self._tasks:
            t.cancel()
        if self.proc:
            with contextlib.suppress(Exception):
                await asyncio.wait_for(self.proc.wait(), timeout=3)


class RawHttp:
    """Peticiones httpx directas al endpoint MCP (streamable-http), con las mismas credenciales
    que la sesión principal, controlando cada header (incluido Mcp-Session-Id)."""

    kind = "http"

    def __init__(self, connection: dict, headers: dict, verify):
        self.url = connection["url"]
        self.base_headers = dict(headers or {})
        self.client = httpx.AsyncClient(verify=verify, timeout=DEFAULT_TIMEOUT_S, follow_redirects=False)
        self.session_id: Optional[str] = None
        self.protocol_version = PROTOCOL_VERSION
        self.use_session = True
        self._dead = False

    async def start(self):
        return None

    def alive(self) -> bool:
        return not self._dead

    def _headers(self, extra: Optional[dict], with_session: bool) -> dict:
        h = {"Content-Type": "application/json", "Accept": "application/json, text/event-stream",
             "MCP-Protocol-Version": self.protocol_version, **self.base_headers}
        if with_session and self.session_id:
            h["Mcp-Session-Id"] = self.session_id
        if extra:
            h.update(extra)
        return h

    async def send(self, raw: bytes, wait_for_id=None, timeout: float = DEFAULT_TIMEOUT_S, settle: float = 0.4,
                   extra_headers: Optional[dict] = None, with_session: bool = True, method: str = "POST") -> Reply:
        r = Reply()
        try:
            resp = await self.client.request(method, self.url, content=raw if method == "POST" else None,
                                             headers=self._headers(extra_headers, with_session), timeout=timeout)
        except httpx.TimeoutException as e:
            r.timed_out, r.error = True, f"timeout: {e}"
            return r
        except (httpx.ConnectError, httpx.RemoteProtocolError, httpx.ReadError) as e:
            r.closed, r.error = True, f"{type(e).__name__}: {e}"
            self._dead = isinstance(e, httpx.ConnectError)
            return r
        except Exception as e:
            r.error = f"{type(e).__name__}: {e}"
            return r
        r.status = resp.status_code
        r.headers = {k.lower(): v for k, v in resp.headers.items()}
        text = resp.text[:MAX_READ_BYTES]
        r.raw = text
        ctype = r.headers.get("content-type", "")
        if "text/event-stream" in ctype:
            r.messages = _parse_sse(text)
        else:
            with contextlib.suppress(Exception):
                r.messages = [json.loads(text)]
        return r

    async def close(self):
        with contextlib.suppress(Exception):
            await self.client.aclose()


# ---------------------------------------------------------------------------------------------
# helpers de más alto nivel, comunes a stdio/http

def rpc(method: str, params=None, id_=None) -> bytes:
    msg = {"jsonrpc": "2.0", "method": method}
    if params is not None:
        msg["params"] = params
    if id_ is not None:
        msg["id"] = id_
    return json.dumps(msg).encode()


def new_id() -> str:
    return "ares-" + uuid.uuid4().hex[:8]


async def open_channel(target, connection: dict):
    """Abre un canal crudo y completa el handshake `initialize` + `notifications/initialized`.
    Devuelve (canal, init_result_dict) o (None, motivo) si no se pudo (transporte no soportado
    -- p.ej. sse legado -- o el handshake falló)."""
    transport = getattr(target, "transport", None) or connection.get("transport")
    if transport == "stdio":
        ch = RawStdio(connection)
    elif transport == "http":
        from engine.core.tls import verify_source
        ch = RawHttp(connection, target._resolved_headers(), verify_source(connection))
    else:
        return None, f"transporte '{transport}' sin canal crudo (solo stdio y http)"
    try:
        await ch.start()
        rid = new_id()
        init = {"protocolVersion": PROTOCOL_VERSION, "capabilities": {},
                "clientInfo": {"name": "ares-rawrpc", "version": "1"}}
        rep = await ch.send(rpc("initialize", init, rid), wait_for_id=rid, timeout=10)
        res = next((m for m in _flatten(rep.messages) if m.get("id") == rid and "result" in m), None)
        if res is None:
            await ch.close()
            return None, f"el handshake crudo no obtuvo respuesta válida (status={rep.status}, error={rep.error or 'n/a'})"
        result = res["result"]
        if isinstance(ch, RawHttp):
            ch.session_id = rep.headers.get("mcp-session-id")
            ch.protocol_version = result.get("protocolVersion", PROTOCOL_VERSION)
        await ch.send(rpc("notifications/initialized"), wait_for_id=None)
        return ch, result
    except Exception as e:
        with contextlib.suppress(Exception):
            await ch.close()
        return None, f"{type(e).__name__}: {e}"


async def healthy(ch, timeout: float = 6.0) -> tuple[bool, str]:
    """¿El canal sigue respondiendo después de un caso? ping debe devolver result o error JSON-RPC
    con ese id -- cualquiera de los dos prueba que el server sigue vivo y procesando."""
    if not ch.alive():
        return False, "crash"
    rid = new_id()
    if isinstance(ch, RawStdio):
        rep = await ch.send(rpc("ping", None, rid), wait_for_id=rid, timeout=timeout, accept_null=False)
    else:
        rep = await ch.send(rpc("ping", None, rid), wait_for_id=rid, timeout=timeout)
    if any(m.get("id") == rid for m in _flatten(rep.messages)):
        return True, "ok"
    if rep.closed or not ch.alive():
        return False, "crash"
    if rep.status is not None and rep.status < 500 and not rep.timed_out and rep.messages == []:
        # http que responde algo (400/404...) sin cuerpo JSON-RPC: vivo, solo no habla JSON-RPC en ese caso
        return True, "ok"
    return False, "hang" if rep.timed_out else "no-response"
