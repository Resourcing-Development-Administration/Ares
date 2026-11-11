"""
Fuzzing a nivel PROTOCOLO (JSON-RPC / transporte MCP) -- el hueco que el roadmap tenía anotado
como pendiente: frames malformados, lotes, cancelaciones y replay de Mcp-Session-Id.

Tres tests, todos sobre un canal crudo PROPIO (engine/protocol/rawrpc.py), nunca sobre la sesión
principal, así un crash provocado acá no arrastra a los demás tests:

  protocol.jsonrpc_malformed_fuzz   JSON roto, tipos inválidos, ids raros, anidamiento profundo,
                                    números gigantes, unicode inválido, params del tipo equivocado.
  protocol.batch_cancel_robustness  lotes (válidos, mixtos, de 500), cancelaciones (de un request en
                                    vuelo, de un id inexistente, de `initialize`), `initialize` doble.
  protocol.session_replay           (solo http) Mcp-Session-Id: request sin sesión, sesión inventada,
                                    sesión ya terminada con DELETE.

Cómo se evitan los falsos positivos (decisión de diseño, no un detalle):
  * SOLO se reporta lo OBSERVADO: el proceso/servidor murió, dejó de responder a un `ping`
    posterior, devolvió un 5xx, o filtró un traceback/path. "No contestó a un frame inválido" NO
    es un hallazgo (la spec permite ignorarlo) ni lo es "no contestó a una notificación".
  * Un crash/hang se CONFIRMA reproduciéndolo en un canal nuevo antes de reportarlo: si un caso
    mató al server por una causa externa (límite de memoria del sandbox, un OOM del host) y no se
    repite, se descarta como flaky.
  * Un server stateless (sin Mcp-Session-Id) no es sujeto de las pruebas de sesión.
"""
from __future__ import annotations
import json
import re
import time

from engine.core.models import Finding, Evidence, Category
from engine.core.registry import register_test
from engine.core.risk import build_vector, base_vector_for
from engine.core.limits import cap_text
from engine.core.schema_utils import minimal_valid_args
from engine.protocol import rawrpc
from engine.protocol.rawrpc import rpc, new_id, open_channel, healthy, _flatten

_LEAK = [
    (re.compile(r"Traceback \(most recent call last\)"), "stack trace de Python"),
    (re.compile(r"\n\s+at [\w.$<>]+ \(.*?:\d+:\d+\)"), "stack trace de Node.js"),
    (re.compile(r"/(home|usr|var|opt|srv|root)/[\w./-]{6,}"), "path absoluto del filesystem"),
    (re.compile(r"[A-Za-z]:\\\\[\w\\\\.-]{6,}"), "path absoluto de Windows"),
]
_MAX_RESTARTS = 3


# ---------------------------------------------------------------------------------------------
# infraestructura común

class _Probe:
    """Corre una lista de casos sobre un canal crudo y clasifica lo observado."""

    def __init__(self, target, ctx):
        self.target, self.ctx = target, ctx
        self.connection = ctx["connection"]
        self.ch = None
        self.crashes: list[dict] = []
        self.hangs: list[dict] = []
        self.leaks: list[dict] = []
        self.http5xx: list[dict] = []
        self.cases_run = 0
        self.restarts = 0
        self.aborted = ""
        self.skipped_reason = ""
        self.deadline = time.monotonic() + 45  # el test entero tiene 60s (test_timeout_s): dejar margen

    async def open(self) -> bool:
        self.ch, info = await open_channel(self.target, self.connection)
        if self.ch is None:
            self.skipped_reason = str(info)
            return False
        return True

    async def close(self):
        if self.ch:
            await self.ch.close()

    async def _reopen(self) -> bool:
        await self.ch.close()
        self.ch, info = await open_channel(self.target, self.connection)
        self.restarts += 1
        if self.ch is None:
            self.aborted = f"no se pudo reabrir el canal tras el caso: {info}"
            return False
        return True

    async def _one(self, name: str, raw: bytes, expect_id) -> tuple[str, "rawrpc.Reply"]:
        t0 = time.monotonic()
        rep = await self.ch.send(raw, wait_for_id=expect_id)
        ok, why = await healthy(self.ch)
        rep_elapsed = time.monotonic() - t0
        if ok:
            return "ok", rep
        return why, rep

    async def run(self, cases: list[tuple[str, bytes, object]]):
        for name, raw, expect_id in cases:
            if not self.ch or self.aborted:
                break
            if time.monotonic() > self.deadline:
                self.aborted = f"presupuesto de tiempo agotado tras {self.cases_run}/{len(cases)} casos"
                break
            self.cases_run += 1
            verdict, rep = await self._one(name, raw, expect_id)

            if verdict in ("crash", "hang", "no-response"):
                # confirmar: reabrir (stdio) y reproducir el MISMO caso una vez. Si no se repite,
                # fue flaky (límite del sandbox, el host) y NO se reporta.
                evidence_tail = ""
                if isinstance(self.ch, rawrpc.RawStdio):
                    evidence_tail = cap_text(self.ch.stderr_tail.decode("utf-8", "replace"), 600)
                    rc = self.ch.proc.returncode if self.ch.proc else None
                    if rc is not None:
                        evidence_tail = f"exit_code={rc}\n" + evidence_tail
                    if not await self._reopen():
                        self.crashes.append({"case": name, "kind": verdict, "confirmed": False, "tail": evidence_tail})
                        break
                    verdict2, _ = await self._one(name, raw, expect_id)
                    confirmed = verdict2 in ("crash", "hang", "no-response")
                    if confirmed and not await self._reopen():
                        pass
                    elif not confirmed:
                        continue  # flaky: descartado
                else:
                    confirmed = True  # http: no se puede "reiniciar" el server; lo observado vale
                bucket = self.crashes if verdict == "crash" else self.hangs
                bucket.append({"case": name, "kind": verdict, "confirmed": confirmed, "tail": evidence_tail,
                                "frame": cap_text(raw.decode("utf-8", "replace"), 160)})
                if isinstance(self.ch, rawrpc.RawHttp):
                    self.aborted = "el server HTTP dejó de responder; se detienen las pruebas de este test"
                    break
                if self.restarts >= _MAX_RESTARTS:
                    self.aborted = f"{_MAX_RESTARTS} reinicios del canal: se detienen las pruebas"
                    break
                continue

            if rep.status is not None and rep.status >= 500:
                self.http5xx.append({"case": name, "status": rep.status, "body": cap_text(rep.raw, 200)})
            for rx, label in _LEAK:
                if rx.search(rep.raw or ""):
                    self.leaks.append({"case": name, "label": label,
                                       "excerpt": cap_text(rep.raw, 240)})
                    break

    # -- findings -------------------------------------------------------------------------

    def findings(self, test_id: str, subject: str) -> list[Finding]:
        out: list[Finding] = []
        is_http = isinstance(self.ch, rawrpc.RawHttp) or self.connection.get("url")
        # http: el atacante es remoto y anónimo -> AV:N; stdio: quien controla stdin ya ejecuta el proceso
        # (AV:L) -> mucho menos grave. Mismo hecho observado, distinta explotabilidad.
        av = "N" if is_http else "L"

        if self.crashes:
            cases = ", ".join(c["case"] for c in self.crashes)
            out.append(Finding(
                test_id=test_id,
                title=f"El server se cae al recibir {subject} ({len(self.crashes)} caso(s))",
                category=Category.PROTOCOL, target="server",
                cvss_vector_override=build_vector(base_vector_for(test_id), AV=av, A="H"),
                confidence_override="verified",
                description=(f"El proceso/servidor dejó de existir tras recibir: {cases}. "
                              + ("Reproducido en un canal nuevo. " if any(c["confirmed"] for c in self.crashes) else "")
                              + "Un frame malformado no debería poder tumbar el server: es una denegación de "
                                "servicio con una sola petición."),
                evidence=Evidence(request={"casos": self.crashes[:5]}, notes=f"{self.cases_run} casos corridos"),
                passed=False,
                remediation="Envolver el parseo/dispatch de mensajes en un manejador que devuelva un error "
                             "JSON-RPC (-32700/-32600) en vez de dejar propagar la excepción; limitar profundidad "
                             "y tamaño del JSON entrante.",
                references=["https://www.jsonrpc.org/specification#error_object"],
            ))
        if self.hangs:
            cases = ", ".join(c["case"] for c in self.hangs)
            out.append(Finding(
                test_id=test_id,
                title=f"El server deja de responder tras recibir {subject} ({len(self.hangs)} caso(s))",
                category=Category.PROTOCOL, target="server",
                cvss_vector_override=build_vector(base_vector_for(test_id), AV=av, A="H"),
                confidence_override="verified",
                description=(f"Tras recibir: {cases}, el server siguió vivo pero NO respondió a un `ping` "
                              f"posterior en 6s (colgado/bloqueado). Denegación de servicio con una sola petición."),
                evidence=Evidence(request={"casos": self.hangs[:5]}),
                passed=False,
                remediation="Aplicar límites de tamaño/profundidad/tiempo al procesamiento de cada mensaje "
                             "y no bloquear el bucle de lectura con trabajo CPU-bound.",
            ))
        if self.http5xx:
            cases = ", ".join(sorted({f"{c['case']}→{c['status']}" for c in self.http5xx})[:8])
            out.append(Finding(
                test_id=test_id,
                title=f"Error 5xx no controlado ante {subject} ({len(self.http5xx)} caso(s))",
                category=Category.PROTOCOL, target="server",
                cvss_vector_override=build_vector(base_vector_for(test_id), AV="N", A="N", C="N", I="N"),
                confidence_override="verified",
                description=(f"El endpoint respondió HTTP 5xx ({cases}) en vez de un error JSON-RPC/4xx: una "
                              f"excepción no manejada en el manejo del mensaje. No tumbó al server, pero es "
                              f"validación de entrada ausente."),
                evidence=Evidence(request={"casos": self.http5xx[:5]}),
                passed=False,
                remediation="Responder 400 con un error JSON-RPC para cualquier frame inválido.",
            ))
        if self.leaks:
            labels = sorted({l["label"] for l in self.leaks})
            out.append(Finding(
                test_id=test_id,
                title=f"El error ante {subject} filtra {', '.join(labels)}",
                category=Category.PROTOCOL, target="server",
                cvss_vector_override=build_vector(base_vector_for(test_id), AV="N", A="N", C="L", I="N"),
                confidence_override="heuristic",
                description=(f"La respuesta de error a {len({l['case'] for l in self.leaks})} caso(s) incluyó "
                              f"{', '.join(labels)}. Revela estructura interna (rutas, dependencias) que ayuda a "
                              f"un atacante a armar el siguiente paso."),
                evidence=Evidence(request={"casos": self.leaks[:3]}),
                passed=False,
                remediation="Devolver mensajes de error genéricos al cliente y registrar el detalle solo en el server.",
            ))
        if not out:
            note = f" ({self.aborted})" if self.aborted else ""
            out.append(Finding(
                test_id=test_id, title=f"Sin fallos ante {subject}", category=Category.PROTOCOL, target="server",
                description=f"Se enviaron {self.cases_run} caso(s) sobre un canal crudo; el server siguió "
                             f"respondiendo a `ping` después de cada uno, sin 5xx ni filtración de internos{note}.",
                passed=True,
            ))
        return out


def _na(test_id: str, why: str) -> list[Finding]:
    return [Finding(test_id=test_id, title="No aplicable a este transporte/target", category=Category.PROTOCOL,
                    target="server", description=why, passed=True)]


async def _safe_tool(ctx, target):
    from engine.dynamic.tests import _pick_burst_tool
    tools = ctx.get("tools") or await target.list_tools()
    return _pick_burst_tool(tools)


# ---------------------------------------------------------------------------------------------
# 1. JSON-RPC malformado

def _malformed_cases(tool: dict | None) -> list[tuple[str, bytes, object]]:
    rid = new_id
    j = lambda o: json.dumps(o).encode()  # noqa: E731
    cases: list[tuple[str, bytes, object]] = [
        ("json_truncado", b'{"jsonrpc":"2.0","id":1,"method":', None),
        ("bytes_basura", b"\x00\x01\x02garbage\xff\xfe", None),
        ("objeto_vacio", b"{}", None),
        ("array_vacio", b"[]", None),
        ("literal_null", b"null", None),
        ("jsonrpc_1.0", j({"jsonrpc": "1.0", "id": 7, "method": "ping"}), 7),
        ("sin_method", j({"jsonrpc": "2.0", "id": 8}), 8),
        ("method_numerico", j({"jsonrpc": "2.0", "id": 9, "method": 123}), 9),
        ("method_objeto", j({"jsonrpc": "2.0", "id": 10, "method": {"a": 1}}), 10),
        ("method_inexistente", j({"jsonrpc": "2.0", "id": 11, "method": "ares/no_existe"}), 11),
        ("method_100k", j({"jsonrpc": "2.0", "id": 12, "method": "m" * 100_000}), 12),
        ("method_nulo_embebido", j({"jsonrpc": "2.0", "id": 13, "method": "ping\x00x"}), 13),
        ("id_objeto", j({"jsonrpc": "2.0", "id": {"a": 1}, "method": "ping"}), None),
        ("id_float", j({"jsonrpc": "2.0", "id": 1.5, "method": "ping"}), 1.5),
        ("id_largo_10k", j({"jsonrpc": "2.0", "id": "x" * 10_000, "method": "ping"}), "x" * 10_000),
        ("id_entero_5000_digitos", b'{"jsonrpc":"2.0","id":' + b"1" * 5000 + b',"method":"ping"}', None),
        ("numero_1e999", b'{"jsonrpc":"2.0","id":1e999,"method":"ping"}', None),
        ("anidado_3000", b"[" * 3000 + b"]" * 3000, None),
        ("anidado_60000_sin_cerrar", b"[" * 60_000, None),
        ("params_string", j({"jsonrpc": "2.0", "id": 14, "method": "tools/list", "params": "x"}), 14),
        ("params_array_en_tools_call", j({"jsonrpc": "2.0", "id": 15, "method": "tools/call", "params": [1, 2]}), 15),
        ("tools_call_name_numerico", j({"jsonrpc": "2.0", "id": 16, "method": "tools/call", "params": {"name": 5}}), 16),
        ("tools_call_name_inexistente", j({"jsonrpc": "2.0", "id": 17, "method": "tools/call", "params": {"name": "ares_no_existe"}}), 17),
        ("tools_call_name_10k", j({"jsonrpc": "2.0", "id": 18, "method": "tools/call", "params": {"name": "n" * 10_000}}), 18),
        ("resources_read_uri_numerico", j({"jsonrpc": "2.0", "id": 19, "method": "resources/read", "params": {"uri": 5}}), 19),
        ("surrogate_suelto", b'{"jsonrpc":"2.0","id":20,"method":"\\ud800ping"}', 20),
        ("claves_duplicadas", b'{"jsonrpc":"2.0","id":21,"id":22,"method":"ping","method":"tools/list"}', None),
        ("utf8_invalido", b'{"jsonrpc":"2.0","id":23,"method":"\xc3\x28"}', 23),
    ]
    if tool:
        n = tool["name"]
        for label, args in (("string", "x"), ("array", [1]), ("null", None), ("numero", 3)):
            i = 100 + len(cases)
            cases.append((f"tools_call_arguments_{label}",
                          j({"jsonrpc": "2.0", "id": i, "method": "tools/call", "params": {"name": n, "arguments": args}}), i))
        i = 400
        cases.append(("tools_call_arguments_anidado_2000",
                      b'{"jsonrpc":"2.0","id":400,"method":"tools/call","params":{"name":' + json.dumps(n).encode()
                      + b',"arguments":' + b'{"a":' * 2000 + b"1" + b"}" * 2000 + b"}}", i))
    return cases


@register_test(
    id="protocol.jsonrpc_malformed_fuzz",
    level=2,
    name="Fuzzing de protocolo: JSON-RPC malformado (el server no debe caerse ni colgarse)",
    category=Category.PROTOCOL,
    description="Sobre un canal JSON-RPC crudo propio (stdio: segundo subproceso; http: peticiones directas) envía "
                 "~35 frames inválidos -- JSON truncado, bytes basura, tipos erróneos en method/id/params, ids de "
                 "10k, enteros de 5000 dígitos, anidamiento de 60000 niveles, unicode inválido, arguments del tipo "
                 "equivocado -- y después de cada uno verifica con un `ping` que el server sigue vivo y atendiendo. "
                 "Reporta solo lo observado (crash/hang reproducidos, 5xx, tracebacks); no reporta que un frame "
                 "inválido 'no haya sido contestado'.",
)
async def jsonrpc_malformed_fuzz(target, ctx) -> list[Finding]:
    tid = "protocol.jsonrpc_malformed_fuzz"
    probe = _Probe(target, ctx)
    if not await probe.open():
        return _na(tid, f"No se pudo abrir un canal JSON-RPC crudo: {probe.skipped_reason}")
    try:
        await probe.run(_malformed_cases(await _safe_tool(ctx, target)))
        return probe.findings(tid, "JSON-RPC malformado")
    finally:
        await probe.close()


# ---------------------------------------------------------------------------------------------
# 2. lotes, cancelaciones, initialize doble

def _batch_cancel_cases(tool: dict | None) -> list[tuple[str, bytes, object]]:
    j = lambda o: json.dumps(o).encode()  # noqa: E731
    ping = lambda i: {"jsonrpc": "2.0", "id": i, "method": "ping"}  # noqa: E731
    cases: list[tuple[str, bytes, object]] = [
        ("batch_3_pings", j([ping(1), ping(2), ping(3)]), 1),
        ("batch_500_pings", j([ping(i) for i in range(1000, 1500)]), 1000),
        ("batch_mixto_con_invalidos", j([ping(30), 1, "x", {}, None, ping(31)]), 30),
        ("batch_con_initialize", j([{"jsonrpc": "2.0", "id": 40, "method": "initialize",
                                      "params": {"protocolVersion": rawrpc.PROTOCOL_VERSION, "capabilities": {},
                                                 "clientInfo": {"name": "x", "version": "1"}}}, ping(41)]), 40),
        ("batch_anidado", j([[ping(50)], [[ping(51)]]]), None),
        ("initialize_doble", j({"jsonrpc": "2.0", "id": 60, "method": "initialize",
                                 "params": {"protocolVersion": rawrpc.PROTOCOL_VERSION, "capabilities": {},
                                            "clientInfo": {"name": "x", "version": "1"}}}), 60),
        ("cancel_id_inexistente", rpc("notifications/cancelled", {"requestId": 987654, "reason": "ares"}), None),
        ("cancel_id_objeto", rpc("notifications/cancelled", {"requestId": {"a": 1}}), None),
        ("cancel_sin_requestId", rpc("notifications/cancelled", {}), None),
        ("cancel_params_string", rpc("notifications/cancelled", "x"), None),
        ("cancel_de_initialize", rpc("notifications/cancelled", {"requestId": 0, "reason": "ares"}), None),
        ("progress_basura", rpc("notifications/progress", {"progressToken": {"x": 1}, "progress": "NaN"}), None),
        ("roots_list_changed_espurio", rpc("notifications/roots/list_changed"), None),
    ]
    if tool:
        args = minimal_valid_args(tool.get("input_schema") or {})
        call = {"jsonrpc": "2.0", "id": 70, "method": "tools/call", "params": {"name": tool["name"], "arguments": args}}
        # request en vuelo + cancelación inmediata (carrera real) -- se manda como UN lote de dos líneas
        cases.append(("tools_call_y_cancel_inmediato",
                      j(call) + b"\n" + rpc("notifications/cancelled", {"requestId": 70, "reason": "ares"}), None))
        cases.append(("tools_call_duplicado_mismo_id",
                      j({**call, "id": 71}) + b"\n" + j({**call, "id": 71}), 71))
    return cases


@register_test(
    id="protocol.batch_cancel_robustness",
    level=2,
    name="Fuzzing de protocolo: lotes JSON-RPC, cancelaciones e initialize duplicado",
    category=Category.PROTOCOL,
    description="Envía lotes (válidos, de 500, mixtos con elementos inválidos, anidados, con initialize), "
                 "notificaciones de cancelación (de un request en vuelo, de un id inexistente, de `initialize`, "
                 "con tipos erróneos) y un `initialize` repetido; verifica que el server siga vivo y atendiendo. "
                 "Los lotes los permite o los rechaza cada revisión de la spec -- ambas conductas son válidas -- "
                 "así que solo se reporta crash/hang/5xx/filtración, nunca 'no soporta batch'.",
)
async def batch_cancel_robustness(target, ctx) -> list[Finding]:
    tid = "protocol.batch_cancel_robustness"
    probe = _Probe(target, ctx)
    if not await probe.open():
        return _na(tid, f"No se pudo abrir un canal JSON-RPC crudo: {probe.skipped_reason}")
    try:
        await probe.run(_batch_cancel_cases(await _safe_tool(ctx, target)))
        return probe.findings(tid, "lotes/cancelaciones/initialize duplicado")
    finally:
        await probe.close()


# ---------------------------------------------------------------------------------------------
# 3. replay / validación de Mcp-Session-Id (http)

@register_test(
    id="protocol.session_replay",
    level=2,
    name="Fuzzing de protocolo: validación y replay de Mcp-Session-Id (http)",
    category=Category.PROTOCOL,
    description="Con una sesión legítima ya abierta, prueba si el server (a) atiende requests SIN Mcp-Session-Id, "
                 "(b) acepta un Mcp-Session-Id INVENTADO, (c) sigue aceptando una sesión ya TERMINADA con DELETE "
                 "(replay). Un server stateless (que nunca emite Mcp-Session-Id) queda fuera: no hay sesión que "
                 "validar. La entropía del id la mide exposure.session_id_entropy.",
)
async def session_replay(target, ctx) -> list[Finding]:
    tid = "protocol.session_replay"
    if ctx.get("transport") != "http":
        return _na(tid, "Solo aplica a streamable-http: stdio no usa Mcp-Session-Id.")
    ch, info = await open_channel(target, ctx["connection"])
    if ch is None:
        return _na(tid, f"No se pudo abrir un canal HTTP crudo: {info}")
    findings: list[Finding] = []
    try:
        if not ch.session_id:
            return _na(tid, "El server no emitió Mcp-Session-Id (modo stateless): no hay sesión que validar.")

        def served(rep) -> bool:
            """¿El server SIRVIÓ el request (resultado real, no un error)?"""
            return rep.status == 200 and any("result" in m for m in _flatten(rep.messages))

        def probe_list():
            rid = new_id()
            return rid, rpc("tools/list", {}, rid)

        # control: con la sesión legítima SÍ debe servir; si no, las pruebas negativas no significan nada
        rid, raw = probe_list()
        base = await ch.send(raw, wait_for_id=rid)
        if not served(base):
            return _na(tid, f"La sesión legítima no pudo listar tools por el canal crudo (status={base.status}): "
                             f"las pruebas negativas no serían concluyentes.")

        sid = ch.session_id
        evid = lambda rep, **k: Evidence(request=k, response={"status": rep.status, "body": cap_text(rep.raw, 200)})  # noqa: E731

        # (a) sin Mcp-Session-Id
        rid, raw = probe_list()
        rep = await ch.send(raw, wait_for_id=rid, with_session=False)
        if served(rep):
            findings.append(Finding(
                test_id=tid, title="El server atiende requests sin Mcp-Session-Id pese a haberlo emitido",
                category=Category.PROTOCOL, target="server",
                cvss_vector_override=build_vector(base_vector_for(tid), AC="H", C="L"),
                confidence_override="heuristic",
                description="Tras `initialize` el server asignó un Mcp-Session-Id, pero respondió `tools/list` "
                             "(200 + result) a una petición SIN ese header. La spec indica responder 400: sin "
                             "vincular cada request a una sesión, el estado/contexto por sesión no está aislado.",
                evidence=evid(rep, header_omitido="Mcp-Session-Id"), passed=False,
                remediation="Rechazar con 400 todo request (salvo initialize) que no traiga un Mcp-Session-Id válido.",
                references=["https://modelcontextprotocol.io/specification/2025-06-18/basic/transports#session-management"],
            ))

        # (b) sesión inventada
        forged = "ares-forged-" + new_id()
        saved, ch.session_id = ch.session_id, forged
        rid, raw = probe_list()
        rep = await ch.send(raw, wait_for_id=rid)
        ch.session_id = saved
        if served(rep):
            findings.append(Finding(
                test_id=tid, title="El server acepta un Mcp-Session-Id inventado",
                category=Category.PROTOCOL, target="server",
                cvss_vector_override=build_vector(base_vector_for(tid), AC="L", C="L"),
                confidence_override="verified",
                description=f"Se envió `tools/list` con Mcp-Session-Id='{forged}' (nunca emitido por el server) "
                             f"y fue atendido (200 + result). La spec exige 404 para sesiones desconocidas: "
                             f"el server no valida el id, así que cualquiera puede operar sin haber negociado sesión.",
                evidence=evid(rep, session_id_enviado=forged), passed=False,
                remediation="Mantener una tabla de sesiones activas y responder 404 a cualquier id que no esté en ella.",
            ))

        # (c) replay tras DELETE
        dele = await ch.send(b"", method="DELETE")
        if dele.status in (200, 202, 204):
            rid, raw = probe_list()
            rep = await ch.send(raw, wait_for_id=rid)
            if served(rep):
                findings.append(Finding(
                    test_id=tid, title="Una sesión terminada con DELETE sigue siendo aceptada (replay)",
                    category=Category.PROTOCOL, target="server",
                    cvss_vector_override=build_vector(base_vector_for(tid), AC="L", C="L"),
                    confidence_override="verified",
                    description="El server confirmó la terminación de la sesión (DELETE → "
                                 f"{dele.status}), pero el mismo Mcp-Session-Id siguió sirviendo `tools/list`. "
                                 "Un id filtrado o capturado queda válido para siempre, aunque el cliente "
                                 "legítimo ya haya cerrado la sesión.",
                    evidence=evid(rep, delete_status=dele.status), passed=False,
                    remediation="Invalidar el id en el servidor al recibir DELETE (y por expiración), respondiendo 404 después.",
                ))
        if not findings:
            findings.append(Finding(
                test_id=tid, title="Mcp-Session-Id validado correctamente", category=Category.PROTOCOL, target="server",
                description="El server rechazó requests sin sesión y con sesión inventada"
                             + (", y dejó de aceptar la sesión tras DELETE." if dele.status in (200, 202, 204)
                                 else f" (DELETE no soportado: {dele.status}; replay tras cierre no evaluable)."),
                passed=True,
            ))
        return findings
    finally:
        await ch.close()
