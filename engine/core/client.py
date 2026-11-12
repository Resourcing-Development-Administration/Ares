"""
Wrapper sobre el SDK oficial de MCP para conectarse a un servidor target
via stdio o vía HTTP/SSE, y exponer una interfaz simple usada por todos
los módulos de test.
"""
from __future__ import annotations
import asyncio
import contextlib
import os
import time
from typing import Any, Optional

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client
from mcp.shared.context import RequestContext
from mcp import types as mcp_types
from mcp.types import SamplingCapability
from engine.core.limits import cap_text, MAX_TEXT_FOR_ANALYSIS, MAX_RESPONSE_CONTENT
from engine.core.sandbox import wrap_command, sandbox_available, sandbox_status, DEFAULT_MEM_MB, DEFAULT_CPU_S, DEFAULT_NOFILE

try:
    from mcp.client.sse import sse_client
    HAS_SSE = True
except ImportError:
    HAS_SSE = False

try:
    from mcp.client.streamable_http import streamablehttp_client
    HAS_HTTP = True
except ImportError:
    HAS_HTTP = False


class _StderrTail:
    """errlog= de stdio_client. OJO: el SDK no le hace .write() línea a línea -- en POSIX lo
    pasa TAL CUAL como stderr= de asyncio.create_subprocess_exec, que necesita un file real con
    .fileno() (confirmado: un objeto Python de solo-.write() revienta con "AttributeError:
    '_StderrTail' object has no attribute 'fileno'" al spawnear). Por eso esto envuelve un
    tempfile real (fd real) y lee su cola a pedido -- ver MCPTarget.stderr_tail."""

    def __init__(self, keep: int = 4000):
        import tempfile
        self._keep = keep
        self._file = tempfile.TemporaryFile(mode="w+b")

    def fileno(self) -> int:
        return self._file.fileno()

    def tail(self) -> str:
        try:
            self._file.flush()
            self._file.seek(0, 2)  # fin, para saber el tamaño total
            size = self._file.tell()
            self._file.seek(max(0, size - self._keep))
            return self._file.read().decode("utf-8", "replace")
        except (ValueError, OSError):
            return ""  # ya cerrado -- best-effort, nunca levantar desde acá

    def close(self) -> None:
        try:
            self._file.close()
        except OSError:
            pass


class MCPTarget:
    """
    Representa la conexión activa contra el servidor MCP bajo prueba.
    Uso:
        async with MCPTarget(config) as target:
            tools = await target.list_tools()
            result = await target.call_tool("foo", {"x": 1})
    """

    def __init__(self, transport: str, connection: dict):
        self.transport = transport
        self.connection = connection
        self._stack = contextlib.AsyncExitStack()
        self.session: Optional[ClientSession] = None
        self.call_log: list[dict] = []   # log crudo de cada request/response, usado como evidencia
        self.request_delay_ms: int = connection.get("request_delay_ms", 0)
        self.capabilities = None
        self.server_info = None
        self._get_session_id = None
        # Verbose: si el orquestador setea esto, cada llamada real (list_tools,
        # call_tool, read_resource...) se reenvía en vivo, además de quedar en
        # call_log -- para "ver todo lo que se está ejecutando" mientras corre,
        # no solo el resumen de al final de cada test.
        self.progress_cb = None
        self.current_test_id: Optional[str] = None
        self.sandboxed: bool = False  # True solo si transport=="stdio" y alguna capa (prlimit/bwrap) envolvió el comando
        self.sandbox_layers: dict = {"prlimit": False, "bwrap": False}
        # Captura de cada sampling/elicitation request que el SERVER le pide al cliente --
        # ver engine/protocol/tests.py. Declaramos soporte de sampling en el initialize
        # (sampling_capabilities=SamplingCapability() más abajo) para que un server que
        # SÍ lo use no se autolimite por creer que el cliente no lo soporta; sin esto,
        # Ares jamás vería esta superficie -- quedaría indistinguible de "el server nunca
        # pide sampling" cuando en realidad podría ser "el server nunca lo intenta porque
        # cree que no hay con quién hablar". Ambos callbacks RECHAZAN el pedido siempre
        # (nunca le dan al server una respuesta real que pueda usar) -- el objetivo es
        # observar qué pide y con qué prompt, no completar nada en su nombre.
        self.sampling_requests: list[dict] = []
        self.elicitation_requests: list[dict] = []
        # último stderr del subprocess stdio -- ver _StderrTail/stderr_tail más abajo. El SDK de
        # MCP solo vuelca esto a sys.stderr por default (se pierde en --no-file / ni llega al
        # reporte); confirmado en campo que ESTO es justo donde queda la causa real de un
        # "Connection closed" (ej. V8 "Failed to reserve virtual memory for CodeRange" --
        # RLIMIT_AS insuficiente para un runtime JIT real -- en vez de un problema del target).
        self._errlog: Optional[_StderrTail] = None

    async def __aenter__(self) -> "MCPTarget":
        # Si algo falla a mitad de camino (ej. session.initialize() con un DNS que no
        # resuelve o un TLS roto, DESPUÉS de que streamablehttp_client/ClientSession ya
        # se entraron con éxito en self._stack), __aenter__ nunca retorna -- y como nunca
        # retorna, quien nos llama (stack.enter_async_context(MCPTarget(...)) en
        # orchestrator.py) tampoco llega a registrar nuestro __aexit__. Sin este
        # try/except, self._stack queda con recursos vivos que NADIE cierra jamás acá
        # mismo: el cleanup termina disparándose después, durante el garbage collection al
        # cerrar el event loop, típicamente desde una tarea distinta a la que los abrió --
        # eso es lo que produce el "Attempted to exit cancel scope in a different task" y
        # tumba el proceso entero en vez de quedar como un error de conexión manejado.
        try:
            if self.transport == "stdio":
                command = self.connection["command"]
                args = self.connection.get("args", [])
                # aislamiento de proceso REAL (RLIMIT + namespaces, no cosmético -- ver
                # engine/core/sandbox.py): sin esto, el subprocess del target corre con los
                # mismos recursos, procesos visibles y red del host que el propio Ares.
                # default-on; --no-sandbox (sandbox.enabled=False) lo desactiva.
                sandbox_cfg = self.connection.get("sandbox") or {}
                if sandbox_cfg.get("enabled", True):
                    command, args = wrap_command(
                        command, args,
                        mem_mb=sandbox_cfg.get("mem_mb", DEFAULT_MEM_MB),
                        cpu_s=sandbox_cfg.get("cpu_s", DEFAULT_CPU_S),
                        nproc=sandbox_cfg.get("nproc"),  # None = calculado dinámicamente (ver sandbox.wrap_command)
                        nofile=sandbox_cfg.get("nofile", DEFAULT_NOFILE),
                        # mismo flag que ya gatea cualquier otro side-effect de red saliente
                        # real (SSRF a metadata endpoints, OSV.dev) -- reusado acá para
                        # levantar el --unshare-net del sandbox cuando el usuario ya aceptó
                        # ese riesgo, en vez de inventar un flag nuevo para lo mismo.
                        allow_network=sandbox_cfg.get("allow_network", False),
                        # HOME EFECTIVO del subprocess (el mismo que calcula el SDK en
                        # stdio_client: get_default_environment() salvo que connection['env']
                        # lo pise) -- credential_mask_bind_args() lo necesita para saber dónde
                        # buscar ~/.ssh, ~/.aws, etc. del lado del target.
                        home=(self.connection.get("env") or {}).get("HOME") or os.path.expanduser("~"),
                        mask_credentials=sandbox_cfg.get("mask_credentials", True),
                    )
                    self.sandboxed = sandbox_available()
                    self.sandbox_layers = sandbox_status()
                else:
                    self.sandboxed = False
                    self.sandbox_layers = {"prlimit": False, "bwrap": False}
                params = StdioServerParameters(
                    command=command,
                    args=args,
                    env=self.connection.get("env"),
                )
                # errlog propio (no sys.stderr, el default del SDK): si stdio_client() mismo
                # revienta (el subprocess crashea apenas arranca -- ej. V8 sin memoria virtual
                # suficiente para su CodeRange), self._errlog YA tiene lo que el proceso llegó a
                # escribir antes de morir -- se lee vía self.stderr_tail (property) desde el
                # `except` de más abajo, no solo en el camino feliz.
                self._errlog = _StderrTail()
                read, write = await self._stack.enter_async_context(stdio_client(params, errlog=self._errlog))
            elif self.transport == "sse":
                if not HAS_SSE:
                    raise RuntimeError("mcp sse client no disponible en esta versión del SDK")
                read, write = await self._stack.enter_async_context(
                    sse_client(self.connection["url"], headers=self._resolved_headers() or None,
                               **self._tls_kwargs(sse_client))
                )
            elif self.transport == "http":
                if not HAS_HTTP:
                    raise RuntimeError("mcp streamable http client no disponible en esta versión del SDK")
                read, write, get_session_id = await self._stack.enter_async_context(
                    streamablehttp_client(self.connection["url"], headers=self._resolved_headers() or None,
                                          **self._tls_kwargs(streamablehttp_client))
                )
                self._get_session_id = get_session_id
            else:
                raise ValueError(f"transporte no soportado: {self.transport}")

            self.session = await self._stack.enter_async_context(ClientSession(
                read, write,
                sampling_callback=self._on_sampling_request,
                elicitation_callback=self._on_elicitation_request,
                sampling_capabilities=SamplingCapability(),
            ))
            init_result = await self.session.initialize()
            self.capabilities = init_result.capabilities
            self.server_info = init_result.serverInfo
            return self
        except BaseException:
            await self._stack.aclose()
            raise

    @property
    def stderr_tail(self) -> str:
        """Últimos ~4000 chars que el subprocess stdio escribió a stderr (solo transporte
        stdio; "" en http/sse). Disponible aunque la conexión haya fallado."""
        return self._errlog.tail() if self._errlog else ""

    def get_session_id(self) -> Optional[str]:
        """Mcp-Session-Id devuelto por el server, solo disponible en transporte http."""
        return self._get_session_id() if self._get_session_id else None

    def get_capabilities(self) -> dict:
        try:
            return self.capabilities.model_dump(exclude_none=True)
        except Exception:
            return {}

    async def __aexit__(self, *exc):
        # best-effort: el scan YA TERMINÓ (o ya falló) cuando esto corre -- un error AL CERRAR
        # (ej. el SDK streamable-http cancelando su propio stream GET en pleno cleanup) nunca debe
        # tumbar el proceso. Confirmado contra MCPGoat nivel 'difficult' (que desestabiliza el
        # transporte a propósito): self._stack.aclose() podía levantar un BaseExceptionGroup
        # (mezclado con un CancelledError, no-Exception) que escapaba entero fuera de run_scan,
        # DESPUÉS de que los 44+ tests ya habían corrido bien -- mismo patrón que __aenter__, acá
        # aplicado al cierre en vez de a la apertura.
        try:
            await self._stack.aclose()
        except* BaseException:
            pass
        if self._errlog is not None:
            self._errlog.close()  # best-effort; si __aenter__ nunca completó, el tempfile
                                    # queda para que el GC/el SO lo recicle -- no vale la pena
                                    # tracking extra para ese caso, corto-vivido por diseño (CLI)

    async def _on_sampling_request(
        self, context: RequestContext, params: mcp_types.CreateMessageRequestParams,
    ) -> mcp_types.CreateMessageResult | mcp_types.ErrorData:
        """El server nos pide que le hagamos completar un prompt con un LLM real
        (sampling/createMessage). Se captura entero (mensajes, systemPrompt, modelPreferences)
        como evidencia -- esto es exactamente lo que un agente real vería y, sin
        aprobación humana de por medio, podría devolverle al server sin que nadie lo
        audite -- y se RECHAZA siempre (nunca le damos al server una completion real que
        pueda usar para actuar)."""
        entry = {
            "messages": [m.model_dump(exclude_none=True) for m in (params.messages or [])],
            "system_prompt": params.systemPrompt,
            "model_preferences": params.modelPreferences.model_dump(exclude_none=True) if params.modelPreferences else None,
            "include_context": params.includeContext,
            "tools_offered": bool(getattr(params, "tools", None)),
        }
        self.sampling_requests.append(entry)
        if self.progress_cb:
            self.progress_cb({"type": "sampling_request", "test_id": self.current_test_id, **entry})
        return mcp_types.ErrorData(
            code=mcp_types.INVALID_REQUEST,
            message="Rechazado por Ares (escáner automatizado, sin humano ni LLM real detrás de esta sesión).",
        )

    async def _on_elicitation_request(
        self, context: RequestContext, params: mcp_types.ElicitRequestParams,
    ) -> mcp_types.ElicitResult | mcp_types.ErrorData:
        """El server nos pide que le saquemos un dato al USUARIO en vivo (elicitation/create)
        -- mismo criterio que sampling: se captura el pedido completo (qué pregunta, qué
        schema de datos pide) como evidencia, y se declina siempre."""
        schema = getattr(params, "requestedSchema", None)
        entry = {
            "message": getattr(params, "message", None),
            "requested_schema": schema.model_dump(exclude_none=True) if hasattr(schema, "model_dump") else schema,
        }
        self.elicitation_requests.append(entry)
        if self.progress_cb:
            self.progress_cb({"type": "elicitation_request", "test_id": self.current_test_id, **entry})
        return mcp_types.ElicitResult(action="decline")

    def _tls_kwargs(self, client_fn) -> dict:
        """kwargs TLS para el cliente http/sse del SDK MCP cuando hay una CA custom
        (connection['ca_bundle']). Se inyecta vía `httpx_client_factory`: un callable
        que arma el httpx.AsyncClient con `verify=<ruta CA>`, de modo que la cadena del
        server se valide contra esa CA interna SIN desactivar la verificación.

        Guardado por compatibilidad: si esta versión del SDK no acepta
        `httpx_client_factory`, se omite (y el scan sigue, con el trust store por
        defecto -- queda registrado por los tests de exposición si el TLS no valida).
        """
        from engine.core.tls import verify_source
        verify = verify_source(self.connection)
        if verify is True:  # trust store por defecto -> el SDK ya lo usa, no hace falta factory
            return {}
        try:
            import inspect
            if "httpx_client_factory" not in inspect.signature(client_fn).parameters:
                return {}
        except (ValueError, TypeError):
            return {}

        import httpx

        def _factory(headers=None, timeout=None, auth=None):
            kwargs: dict = {"follow_redirects": True, "verify": verify}
            if headers is not None:
                kwargs["headers"] = headers
            kwargs["timeout"] = timeout if timeout is not None else httpx.Timeout(30.0)
            if auth is not None:
                kwargs["auth"] = auth
            return httpx.AsyncClient(**kwargs)

        return {"httpx_client_factory": _factory}

    def _resolved_headers(self) -> dict:
        """Combina connection['headers'] explícitos con connection['auth'] (AuthConfig o dict
        {type, token, header_name}) para transporte http/sse. Auth pisa headers si hay conflicto
        de 'Authorization', ya que representa la credencial "oficial" de la corrida."""
        headers = dict(self.connection.get("headers") or {})
        auth = self.connection.get("auth")
        if auth is not None:
            to_headers = getattr(auth, "to_headers", None)
            if callable(to_headers):
                headers.update(to_headers())
            elif isinstance(auth, dict) and auth.get("type") not in (None, "none"):
                if auth.get("type") == "bearer" and auth.get("token"):
                    headers["Authorization"] = f"Bearer {auth['token']}"
                elif auth.get("type") in ("apikey", "custom") and auth.get("token"):
                    headers[auth.get("header_name") or "X-API-Key"] = auth["token"]
        return headers

    def _log(self, kind: str, request: Any, response: Any = None, error: str = None, elapsed_ms: float = None):
        entry = {
            "kind": kind,
            "request": request,
            "response": response,
            "error": error,
            "elapsed_ms": elapsed_ms,
        }
        self.call_log.append(entry)
        if self.progress_cb:
            try:
                self.progress_cb({"type": "tool_call", "test_id": self.current_test_id, **entry})
            except Exception:
                pass  # un consumer roto del callback nunca debe tumbar el scan

    async def list_tools(self) -> list[dict]:
        t0 = time.monotonic()
        result = await self.session.list_tools()
        elapsed = (time.monotonic() - t0) * 1000
        tools = [
            {
                "name": t.name,
                # cap_text: un target hostil puede declarar una descripción de varios MB para
                # que los ~15 tests que la analizan con regex (recon.suspicious_descriptions,
                # supplychain.secret_exposure/malicious_patterns, static.*, crossserver...)
                # exploten en tiempo de CPU -- confirmado empíricamente (ver engine/core/limits.py).
                "description": cap_text(t.description or "", self.connection.get("max_text_for_analysis", MAX_TEXT_FOR_ANALYSIS)),
                "input_schema": t.inputSchema or {},
            }
            for t in result.tools
        ]
        self._log("list_tools", {}, tools, elapsed_ms=elapsed)
        return tools

    async def list_resources(self) -> list[dict]:
        try:
            result = await self.session.list_resources()
            res = [{"uri": str(r.uri), "name": r.name, "description": r.description or ""} for r in result.resources]
            self._log("list_resources", {}, res)
            return res
        except Exception as e:
            self._log("list_resources", {}, None, error=str(e))
            return []

    async def list_resource_templates(self) -> list[dict]:
        try:
            result = await self.session.list_resource_templates()
            templates = [
                {"uri_template": t.uriTemplate, "name": t.name, "description": t.description or ""}
                for t in result.resourceTemplates
            ]
            self._log("list_resource_templates", {}, templates)
            return templates
        except Exception as e:
            self._log("list_resource_templates", {}, None, error=str(e))
            return []

    async def list_prompts(self) -> list[dict]:
        try:
            result = await self.session.list_prompts()
            pr = [{"name": p.name, "description": p.description or ""} for p in result.prompts]
            self._log("list_prompts", {}, pr)
            return pr
        except Exception as e:
            self._log("list_prompts", {}, None, error=str(e))
            return []

    async def call_tool(self, name: str, arguments: dict) -> dict:
        """
        Llama a un tool y NUNCA levanta excepción hacia arriba por errores del server:
        devuelve siempre un dict normalizado {ok, content, is_error, raw_error, elapsed_ms}
        para que los módulos de fuzzing puedan iterar sin romperse.
        """
        if self.request_delay_ms:
            await asyncio.sleep(self.request_delay_ms / 1000)
        t0 = time.monotonic()
        try:
            result = await self.session.call_tool(name, arguments)
            elapsed = (time.monotonic() - t0) * 1000
            # cap_text: un tool hostil puede devolver cientos de MB en un solo content block
            # (confirmado con huge_response en Campo-Tiro) -- sin esto, cada byte se concatena,
            # se vuelve a copiar en el log de evidencia, y después se le corren leak-patterns
            # encima en dynamic.fuzz_tools/fuzz_resources sin ningún límite.
            content_text = cap_text(_extract_text(result), self.connection.get("max_response_content", MAX_RESPONSE_CONTENT))
            out = {
                "ok": True,
                "content": content_text,
                "is_error": getattr(result, "isError", False),
                "raw_error": None,
                "elapsed_ms": elapsed,
            }
            self._log("call_tool", {"name": name, "arguments": arguments}, out, elapsed_ms=elapsed)
            return out
        except Exception as e:
            elapsed = (time.monotonic() - t0) * 1000
            out = {"ok": False, "content": "", "is_error": True, "raw_error": str(e), "elapsed_ms": elapsed}
            self._log("call_tool", {"name": name, "arguments": arguments}, out, error=str(e), elapsed_ms=elapsed)
            return out

    async def read_resource(self, uri: str) -> dict:
        t0 = time.monotonic()
        try:
            result = await self.session.read_resource(uri)
            elapsed = (time.monotonic() - t0) * 1000
            texts = []
            for c in result.contents:
                texts.append(getattr(c, "text", None) or getattr(c, "blob", "<binary>"))
            out = {"ok": True, "content": cap_text("\n".join(str(t) for t in texts), self.connection.get("max_response_content", MAX_RESPONSE_CONTENT)), "elapsed_ms": elapsed}
            self._log("read_resource", {"uri": uri}, out, elapsed_ms=elapsed)
            return out
        except Exception as e:
            out = {"ok": False, "content": "", "raw_error": str(e)}
            self._log("read_resource", {"uri": uri}, out, error=str(e))
            return out


def _extract_text(result) -> str:
    parts = []
    for item in getattr(result, "content", []) or []:
        text = getattr(item, "text", None)
        if text is not None:
            parts.append(text)
        else:
            parts.append(str(item))
    return "\n".join(parts)
