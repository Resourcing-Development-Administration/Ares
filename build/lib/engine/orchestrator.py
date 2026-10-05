from __future__ import annotations
import asyncio
import contextlib
import platform
import traceback
import uuid
from datetime import datetime, timezone

from engine import __version__ as ARES_VERSION
from engine.core.models import ScanConfig, ScanReport, Finding, Evidence, Category
from engine.core.client import MCPTarget
from engine.core.registry import all_tests
from engine.reporting.scoring import calculate_score
from engine.reporting.suppress import apply_noise_reduction
from engine.policy.engine import PolicyEngine
from engine.baseline import load_baseline_tools
from engine.core.sandbox import sandbox_status

# importar módulos para que se autoregistren en el registry
import engine.recon.tests        # noqa: F401
import engine.static.tests       # noqa: F401
import engine.dynamic.tests      # noqa: F401
import engine.adversarial.tests  # noqa: F401
import engine.adversarial.chain_tests  # noqa: F401
import engine.adversarial.live_agent_tests  # noqa: F401
import engine.auth.tests         # noqa: F401
import engine.exposure.tests     # noqa: F401
import engine.supplychain.tests  # noqa: F401


async def run_scan(config: ScanConfig, progress_cb=None) -> ScanReport:
    """
    progress_cb: callable opcional (event: dict) -> None, para que la API
    pueda emitir eventos en vivo por WebSocket mientras corre el scan.
    """
    def emit(event: dict):
        if progress_cb:
            progress_cb(event)

    report = ScanReport(
        scan_id=str(uuid.uuid4())[:8],
        target_name=config.target_name,
        started_at=datetime.now(timezone.utc).isoformat(),
        ares_version=ARES_VERSION,
    )

    registry = all_tests()
    selected = config.selected_tests or [tid for tid, (meta, _) in registry.items() if meta.default_enabled]

    unknown = [tid for tid in selected if tid not in registry]
    for u in unknown:
        report.errors.append(f"test_id desconocido, ignorado: {u}")
    selected = [tid for tid in selected if tid in registry]

    emit({"type": "scan_started", "scan_id": report.scan_id, "tests_selected": selected})

    connection = dict(config.connection)
    if config.auth is not None:
        connection["auth"] = config.auth
    if config.request_delay_ms:
        connection["request_delay_ms"] = config.request_delay_ms
    connection["sandbox"] = {
        "enabled": config.sandbox_subprocess, "mem_mb": config.sandbox_mem_mb,
        "cpu_s": config.sandbox_cpu_s, "nproc": config.sandbox_nproc, "nofile": config.sandbox_nofile,
        "allow_network": config.allow_network_side_effects,
    }
    if config.max_text_for_analysis is not None:
        connection["max_text_for_analysis"] = config.max_text_for_analysis
    if config.max_response_content is not None:
        connection["max_response_content"] = config.max_response_content

    if config.transport == "stdio" and config.sandbox_subprocess:
        layers = sandbox_status()
        _os_hint = "este host no es Linux (Windows/macOS no tienen 'prlimit'/'bwrap', ver sección 2.0b del manual)" \
            if platform.system() != "Linux" else "este host no tiene util-linux/bubblewrap instalados"
        if not layers["prlimit"]:
            report.errors.append(
                f"aislamiento de recursos solicitado pero 'prlimit' no está disponible ({_os_hint}) -- "
                "el subprocess del target corre SIN límites de memoria/CPU/procesos/FDs a nivel OS. "
                "Mitigado parcialmente por engine/core/limits.py (lo que Ares LEE), pero no por esto "
                "(lo que el proceso del target puede CONSUMIR)."
            )
        if not layers["bwrap"]:
            report.errors.append(
                f"aislamiento de namespaces solicitado pero 'bwrap' (bubblewrap) no está disponible "
                f"({_os_hint}) -- el subprocess del target comparte PID/IPC/red con Ares: PUEDE ver, "
                "señalizar (kill/ptrace) procesos del host, y si no se pasó --allow-network, igual"
                "tiene red real (el corte de red depende de bwrap). Instalar bubblewrap cierra esto."
            )

    # La conexión inicial puede FALLAR/ser RECHAZADA legítimamente (ej. un server bien
    # asegurado devuelve 401 sin credenciales). Eso no debe abortar el scan entero -- varios
    # tests (auth.unauthenticated_access, auth.oauth_metadata_security, exposure.*) están
    # diseñados justamente para analizar ese escenario, y no necesitan una sesión MCP viva
    # (usan su propio cliente HTTP). Tests que sí necesitan `target` fallarán individualmente
    # y quedan registrados como error de ESE test, sin tumbar los demás.
    target = None
    connect_error = None
    stack = contextlib.AsyncExitStack()
    async with stack:
        try:
            target = await stack.enter_async_context(MCPTarget(config.transport, connection))
        except* Exception as eg:
            # falla de conexión/DNS/TLS real (no un 401 limpio del server) -- el SDK mcp la
            # propaga desde un anyio TaskGroup interno como BaseExceptionGroup (mezclada con
            # un CancelledError de una tarea hermana cancelada), que un `except Exception`
            # normal NO atrapa en Python 3.11+ -- por eso hace falta `except*` (PEP 654) acá:
            # sin esto, un DNS que no resuelve o un TLS roto tumbaba el proceso ENTERO en vez
            # de quedar como error de conexión, como promete el comentario de arriba.
            e = eg.exceptions[0]
            connect_error = str(e)
            report.errors.append(f"conexión inicial rechazada/fallida (no aborta el scan): {e}")
            emit({"type": "connection_error", "error": str(e)})
        except* BaseException as eg:
            # red de seguridad: lo que sobra del mismo grupo (CancelledError/GeneratorExit
            # del cleanup interno de la tarea cancelada) tampoco debe escapar.
            if connect_error is None:
                connect_error = str(eg.exceptions[0])
                report.errors.append(f"conexión inicial rechazada/fallida (no aborta el scan): {connect_error}")
                emit({"type": "connection_error", "error": connect_error})

        if target is not None and config.verbose:
            target.progress_cb = emit

        ctx = {
            "max_fuzz_cases_per_tool": config.max_fuzz_cases_per_tool,
            "source_path": config.source_path,
            "transport": config.transport,
            "connection": connection,
            "oob_callback_host": config.oob_callback_host,
            "baseline_tools": load_baseline_tools(config.baseline_path) if config.baseline_path else [],
            "connection_error": connect_error,
            "live_agent_provider": config.live_agent_provider,
            "package_name": config.package_name,
            "secondary_auth": config.secondary_auth,
        }

        consecutive_timeouts = 0
        for test_id in selected:
            meta, func = registry[test_id]
            if meta.requires_network and not config.allow_network_side_effects:
                report.errors.append(
                    f"test '{test_id}' se saltó: requiere allow_network_side_effects=true "
                    f"(hace conexiones salientes reales, ej. SSRF a metadata endpoints)."
                )
                continue

            # circuit breaker: confirmado empíricamente que un solo tool que nunca responde
            # hace que CADA test que lo toca se cuelgue el timeout completo por separado --
            # 4 tests ya se habían comido 4 minutos reales contra el mismo target antes de
            # este fix. A partir de max_consecutive_timeouts, el resto se salta de una sola
            # vez (queda como error + un Finding agregado, no se pierde silenciosamente).
            if config.max_consecutive_timeouts and consecutive_timeouts >= config.max_consecutive_timeouts:
                remaining = selected[selected.index(test_id):]
                report.errors.append(
                    f"circuit breaker: {consecutive_timeouts} timeouts consecutivos -- se saltearon "
                    f"{len(remaining)} tests restantes ({', '.join(remaining)}) sin intentarlos. El "
                    f"target parece no responder de forma sostenida (colgado, deadlock, o resistiendo "
                    f"el análisis a propósito). Ajustable con ScanConfig.max_consecutive_timeouts (0 = sin límite)."
                )
                report.findings.append(Finding(
                    test_id="orchestrator.target_unresponsive_sustained",
                    title="El servidor dejó de responder de forma sostenida -- scan incompleto",
                    category=Category.DYNAMIC,
                    target="server",
                    description=(
                        f"{consecutive_timeouts} tests seguidos no terminaron en {config.test_timeout_s}s "
                        f"cada uno. En vez de seguir pagando el timeout completo test por test, el resto "
                        f"de la batería ({len(remaining)} tests) se saltó de una. Esta corrida está "
                        f"INCOMPLETA -- no es un veredicto de 'limpio' sobre lo que no se llegó a probar."
                    ),
                    evidence=Evidence(notes=f"tests saltados: {remaining}"),
                    passed=False,
                    remediation="Investigar por qué el server dejó de responder de forma sostenida antes "
                                 "de confiar en cualquier score de esta corrida. Re-ejecutar aislado con "
                                 "--test-timeout-s más alto, o contra una instancia fresca del server.",
                ))
                emit({"type": "circuit_breaker", "skipped": remaining})
                break

            if target is not None:
                target.current_test_id = test_id

            emit({"type": "test_started", "test_id": test_id, "name": meta.name})
            try:
                findings = await asyncio.wait_for(func(target, ctx), timeout=config.test_timeout_s)
                consecutive_timeouts = 0
                report.findings.extend(findings)
                emit({
                    "type": "test_finished", "test_id": test_id,
                    "findings_count": len(findings),
                    "confirmed": sum(1 for f in findings if not f.passed),
                })
            except asyncio.TimeoutError:
                consecutive_timeouts += 1
                # fail-closed: un test colgado (ej. un tool del target que nunca responde) NO debe
                # tumbar el scan entero -- se registra como error de ESE test y se sigue con el resto.
                report.errors.append(
                    f"test '{test_id}' no terminó en {config.test_timeout_s}s (timeout) -- se saltó, "
                    f"el resto del scan continúa. Ajustable con ScanConfig.test_timeout_s."
                )
                emit({"type": "test_error", "test_id": test_id, "error": "timeout", "timeout": True})
                # Esto NO es solo un error operativo: antes quedaba únicamente en report.errors
                # (texto libre), que score/policy jamás miran -- confirmado empíricamente que un
                # server con un tool que nunca responde (hang_forever) termina el scan con
                # score 100/A y policy ALLOW, exactamente igual que un server limpio, porque el
                # único test que lo hubiera detectado nunca llegó a producir un finding. Un target
                # que logra que un test de Ares no complete es, como mínimo, tan sospechoso como
                # uno que falla una prueba -- se convierte en un Finding real para que SÍ pese en
                # el veredicto, en vez de perderse en una lista de errores que nadie gatea.
                report.findings.append(Finding(
                    test_id="orchestrator.test_unresponsive",
                    title=f"El servidor no respondió a tiempo durante '{test_id}'",
                    category=Category.DYNAMIC,
                    target=test_id,
                    description=(
                        f"El test '{test_id}' no terminó en {config.test_timeout_s}s y se cortó "
                        f"(fail-closed) para no colgar el resto del scan. Esto reduce la cobertura real "
                        f"de esta corrida (las vulnerabilidades que ese test buscaba no se pudieron "
                        f"confirmar NI descartar) y es, en sí mismo, una señal de riesgo: un server mal "
                        f"implementado (deadlock, I/O bloqueante) o uno que deliberadamente intenta "
                        f"evadir el análisis colgando las pruebas que lo comprometerían produce "
                        f"exactamente este síntoma."
                    ),
                    evidence=Evidence(notes=f"timeout={config.test_timeout_s}s"),
                    passed=False,
                    remediation="Si el server es propio: revisar por qué esa ruta no responde bajo los "
                                 "inputs que Ares envía (deadlock, llamada bloqueante, recursión). Si es "
                                 "de terceros: tratar la corrida como INCOMPLETA, no como limpia -- "
                                 "re-ejecutar ese test aislado (--tests) con --test-timeout-s más alto "
                                 "antes de confiar en el score.",
                ))
                if config.reset_session_on_timeout and target is not None:
                    # la sesión que acaba de colgar un test puede quedar en un estado envenenado
                    # (pipe con un mensaje a medio parsear) y, en stdio, el SUBPROCESO del target
                    # sigue vivo -- reusarlo para el resto de los tests arrastra ese estado Y deja
                    # al host consumiendo recursos de un proceso hostil durante todo el resto del
                    # scan, no solo durante el test que lo disparó. Cerrar y reabrir es más caro
                    # que seguir con la misma sesión, pero confirmado que es lo correcto: un test
                    # que empieza desde una sesión limpia no hereda el estado del que acaba de colgar.
                    old_target = target
                    try:
                        await old_target.__aexit__(None, None, None)
                    except Exception:
                        pass  # best-effort -- lo que importa es no REUSAR la sesión vieja, no que el cierre sea prolijo
                    try:
                        target = await stack.enter_async_context(MCPTarget(config.transport, connection))
                        report.errors.append(f"sesión reconectada tras el timeout de '{test_id}'.")
                    except* Exception as eg:
                        target = None
                        connect_error = str(eg.exceptions[0])
                        report.errors.append(f"no se pudo reconectar tras el timeout de '{test_id}': {connect_error}")
                    except* BaseException as eg:
                        target = None
                        if connect_error is None:
                            connect_error = str(eg.exceptions[0])
            except Exception as e:
                # caso especial y MUY común: la conexión inicial falló (target is None) y este
                # test, a diferencia de auth.*/exposure.* (que chequean `target is None` antes de
                # tocarlo), asume una sesión viva -- explota con un AttributeError genérico
                # ('NoneType' object has no attribute 'list_tools'/'call_tool'/...). Confirmado
                # en un scan real: 15 tests distintos dejaban 15 tracebacks completos e idénticos
                # en espíritu en report.errors, puro ruido para quien tiene que leer el reporte.
                # Un mensaje claro y de una línea alcanza -- la causa raíz (la conexión) ya quedó
                # registrada una sola vez más arriba.
                if target is None and isinstance(e, AttributeError) and "NoneType" in str(e):
                    report.errors.append(
                        f"test '{test_id}' se saltó: no hay conexión activa con el target "
                        f"({connect_error or 'ver error de conexión más arriba'})."
                    )
                else:
                    tb = traceback.format_exc()
                    report.errors.append(f"test '{test_id}' falló con excepción: {e}\n{tb}")
                emit({"type": "test_error", "test_id": test_id, "error": str(e)})

        report.tools_enumerated = ctx.get("tools", [])
        report.resources_enumerated = ctx.get("resources", [])
        report.prompts_enumerated = ctx.get("prompts", [])

    noise_stats = apply_noise_reduction(report, config.allowlist_path, config.min_confidence)
    if noise_stats["allowlisted"] or noise_stats["below_confidence_floor"]:
        emit({"type": "noise_reduction", **noise_stats})

    report.finished_at = datetime.now(timezone.utc).isoformat()
    report.score = calculate_score(report)
    report.policy_verdict = PolicyEngine().evaluate(report, config.environment)
    emit({"type": "scan_finished", "summary": report.summary(), "score": report.score, "policy": report.policy_verdict})
    return report
