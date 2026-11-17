"""
Traffic Proxy — grabación de tráfico HTTP entre el agente y el target.
Implementa un proxy HTTP transparente en :8788 (configurable).

No requiere mitmproxy. Usa httpx + asyncio para interceptar y registrar
todas las peticiones que pasan por él.

Los registros se guardan en reports/traffic/<scan_id>/*.jsonl

Uso:
    proxy = TrafficProxy(port=8788, scan_id="abc123", reports_dir="reports/")
    await proxy.start()
    # configurar HTTPS_PROXY=http://localhost:8788 en el entorno de los tools
    await proxy.stop()
    traffic = proxy.get_traffic()
"""
from __future__ import annotations
import asyncio
import json
import logging
import os
import time
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from typing import AsyncIterator

_log = logging.getLogger(__name__)


@dataclass
class TrafficEntry:
    id: int
    method: str
    url: str
    request_headers: dict
    request_body: str | None
    status_code: int | None
    response_headers: dict
    response_body: str | None
    duration_ms: float
    timestamp: str
    scan_id: str
    error: str | None = None


class TrafficProxy:
    """Proxy HTTP de grabación para inspección de tráfico de tools.

    Escucha en localhost:{port} y reenvía las peticiones al destino real,
    grabando cada par request/response.
    """

    def __init__(
        self,
        port: int = 8788,
        scan_id: str = "unknown",
        reports_dir: str = "reports",
        max_body_bytes: int = 64 * 1024,
    ) -> None:
        self._port = port
        self._scan_id = scan_id
        self._reports_dir = reports_dir
        self._max_body = max_body_bytes
        self._entries: list[TrafficEntry] = []
        self._counter = 0
        self._server: asyncio.Server | None = None
        self._traffic_dir = os.path.join(reports_dir, "traffic", scan_id)
        self._log_path = os.path.join(self._traffic_dir, "traffic.jsonl")

    @property
    def port(self) -> int:
        return self._port

    @property
    def proxy_url(self) -> str:
        return f"http://localhost:{self._port}"

    async def start(self) -> None:
        os.makedirs(self._traffic_dir, exist_ok=True)
        self._server = await asyncio.start_server(
            self._handle_connection, "127.0.0.1", self._port,
        )

    async def stop(self) -> None:
        if self._server:
            self._server.close()
            await self._server.wait_closed()
            self._server = None

    def get_traffic(self) -> list[TrafficEntry]:
        return list(self._entries)

    def get_summary(self) -> dict:
        total = len(self._entries)
        errors = sum(1 for e in self._entries if e.error)
        status_counts: dict[int, int] = {}
        for e in self._entries:
            if e.status_code:
                status_counts[e.status_code] = status_counts.get(e.status_code, 0) + 1
        avg_ms = sum(e.duration_ms for e in self._entries) / total if total else 0
        return {
            "total_requests": total,
            "errors": errors,
            "avg_duration_ms": round(avg_ms, 1),
            "status_codes": status_counts,
            "log_path": self._log_path,
        }

    async def _handle_connection(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ) -> None:
        import httpx

        try:
            # leer la primera línea HTTP
            first_line = await reader.readline()
            if not first_line:
                writer.close()
                return
            parts = first_line.decode("latin-1").strip().split(" ", 2)
            if len(parts) < 2:
                writer.close()
                return
            method, url = parts[0], parts[1]

            # CONNECT (HTTPS tunneling) — forwarding transparente con logging de metadata
            if method == "CONNECT":
                # Consumir los headers de la petición CONNECT antes de establecer el tunnel
                while True:
                    line = await reader.readline()
                    if line in (b"\r\n", b"\n", b""):
                        break
                # Parsear host:port de la URL del CONNECT
                if ":" in url:
                    _host, _port_str = url.rsplit(":", 1)
                    try:
                        _port = int(_port_str)
                    except ValueError:
                        _port = 443
                else:
                    _host, _port = url, 443
                await self._handle_connect(reader, writer, _host, _port)
                return

            # leer headers
            headers: dict[str, str] = {}
            while True:
                line = await reader.readline()
                if line in (b"\r\n", b"\n", b""):
                    break
                decoded = line.decode("latin-1").strip()
                if ":" in decoded:
                    k, v = decoded.split(":", 1)
                    headers[k.strip().lower()] = v.strip()

            # leer body si existe
            body_bytes = b""
            content_length = int(headers.get("content-length", 0))
            if content_length > 0:
                body_bytes = await reader.read(min(content_length, self._max_body))

            # reenviar al servidor real
            self._counter += 1
            entry_id = self._counter
            started = time.monotonic()
            timestamp = datetime.now(timezone.utc).isoformat()

            response_headers: dict[str, str] = {}
            status_code: int | None = None
            response_body: str | None = None
            error: str | None = None

            try:
                async with httpx.AsyncClient(timeout=30) as client:
                    req_headers = {k: v for k, v in headers.items()
                                   if k not in ("host", "content-length")}
                    resp = await client.request(
                        method, url,
                        headers=req_headers,
                        content=body_bytes or None,
                        follow_redirects=True,
                    )
                    status_code = resp.status_code
                    response_headers = dict(resp.headers)
                    resp_body_bytes = resp.content[:self._max_body]
                    try:
                        response_body = resp_body_bytes.decode("utf-8", errors="replace")
                    except Exception:
                        response_body = repr(resp_body_bytes[:200])

                    # enviar respuesta al cliente original
                    http_resp = (
                        f"HTTP/1.1 {resp.status_code} OK\r\n"
                        + "".join(f"{k}: {v}\r\n" for k, v in resp.headers.items())
                        + "\r\n"
                    ).encode("latin-1")
                    writer.write(http_resp + resp.content)
                    await writer.drain()

            except Exception as e:
                error = str(e)
                writer.write(b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n")
                await writer.drain()

            duration_ms = (time.monotonic() - started) * 1000
            entry = TrafficEntry(
                id=entry_id, method=method, url=url,
                request_headers=headers,
                request_body=body_bytes.decode("utf-8", errors="replace") if body_bytes else None,
                status_code=status_code,
                response_headers=response_headers,
                response_body=response_body,
                duration_ms=round(duration_ms, 1),
                timestamp=timestamp,
                scan_id=self._scan_id,
                error=error,
            )
            self._entries.append(entry)
            self._append_log(entry)

        except Exception:
            pass
        finally:
            try:
                writer.close()
            except Exception:
                pass

    async def _handle_connect(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        host: str,
        port: int,
    ) -> None:
        """Tunnel CONNECT para HTTPS — forwarding transparente con logging de metadata."""
        try:
            # Conectar al destino real
            dest_reader, dest_writer = await asyncio.open_connection(host, port)
            # Confirmar el tunnel al cliente
            writer.write(b"HTTP/1.1 200 Connection established\r\n\r\n")
            await writer.drain()

            # Registrar metadata del tunnel (host, port, timestamp)
            self._log_connect(host, port)

            # Forward bidireccional transparente
            await asyncio.gather(
                self._pipe(reader, dest_writer),
                self._pipe(dest_reader, writer),
                return_exceptions=True,
            )
        except Exception as e:
            _log.debug("CONNECT tunnel error %s:%s: %s", host, port, e)
        finally:
            try:
                writer.close()
            except Exception:
                pass

    async def _pipe(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ) -> None:
        """Copia datos entre reader y writer hasta EOF."""
        try:
            while True:
                data = await reader.read(65536)
                if not data:
                    break
                writer.write(data)
                await writer.drain()
        except (ConnectionResetError, BrokenPipeError, asyncio.IncompleteReadError):
            pass
        finally:
            try:
                writer.close()
            except Exception:
                pass

    def _log_connect(self, host: str, port: int) -> None:
        """Registra metadata de un tunnel CONNECT como TrafficEntry."""
        self._counter += 1
        timestamp = datetime.now(timezone.utc).isoformat()
        entry = TrafficEntry(
            id=self._counter,
            method="CONNECT",
            url=f"{host}:{port}",
            request_headers={},
            request_body=None,
            status_code=200,
            response_headers={},
            response_body="TLS tunnel — bodies no interceptados (forwarding transparente)",
            duration_ms=0.0,
            timestamp=timestamp,
            scan_id=self._scan_id,
            error=None,
        )
        self._entries.append(entry)
        self._append_log(entry)

    def _append_log(self, entry: TrafficEntry) -> None:
        try:
            with open(self._log_path, "a", encoding="utf-8") as fh:
                fh.write(json.dumps(asdict(entry), ensure_ascii=False) + "\n")
        except Exception:
            pass
