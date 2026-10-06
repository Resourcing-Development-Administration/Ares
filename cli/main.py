"""
Uso:
  python cli/main.py list-tests
  python cli/main.py discover
  python cli/main.py scan --command "python" --args "target_server.py" --out reporte.html
  python cli/main.py scan --transport http --url http://host/mcp --auth-token TOKEN --auth-type bearer \
      --compare-auth --environment production --sarif-out reporte.sarif --out reporte.html
  python cli/main.py scan --config ~/.config/Claude/claude_desktop_config.json --out reporte.html
"""
from __future__ import annotations
import argparse
import asyncio
import json
import re
import sys
import os
import uuid
from datetime import datetime, timezone

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import httpx
from rich.console import Console
from rich.markup import escape as _rich_escape
from rich.table import Table

from engine.core.models import ScanConfig, AuthConfig, ScanReport
from engine.reporting.scoring import calculate_score
from engine.policy.engine import PolicyEngine
from engine.core.registry import list_meta, all_tests
from engine.orchestrator import run_scan
from engine.compare import run_auth_comparison
from engine.reporting.html_report import save_html_report
from engine.reporting.sarif import save_sarif_report
from engine.reporting.redact import redact_report
from engine.reporting.suppress import default_allowlist_path
from engine.baseline import diff_against_baseline
from engine.core.tls import resolve_ca_bundle, ca_bundle_source
from engine.discovery.local_configs import discover_mcp_servers
from engine.crossserver import analyze_cross_server, cross_server_findings
from engine import __version__ as ARES_VERSION
from engine.supplychain.rule_sources import fetch_gitleaks_patterns, save_cache, cache_info
from engine.core.framework_watch import check_for_updates, save_baseline, oldest_baseline_age_days

console = Console()


def cmd_list_tests(args):
    table = Table(title="Tests disponibles")
    table.add_column("ID")
    table.add_column("Categoría")
    table.add_column("Nombre")
    table.add_column("Default")
    table.add_column("Red externa")
    for meta in sorted(list_meta(), key=lambda m: (m.category.value, m.id)):
        table.add_row(
            meta.id, meta.category.value, meta.name,
            "✅" if meta.default_enabled else "❌ (opt-in)",
            "⚠️ sí" if meta.requires_network else "no",
        )
    console.print(table)


def cmd_discover(args):
    servers = discover_mcp_servers()
    if not servers:
        console.print("[yellow]No se encontraron configs de clientes MCP conocidos en esta máquina.[/yellow]")
        return
    table = Table(title="Servidores MCP configurados localmente")
    table.add_column("Cliente")
    table.add_column("Servidor")
    table.add_column("Comando/URL")
    table.add_column("Config")
    for s in servers:
        target = s["url"] or f"{s['command']} {' '.join(s.get('args') or [])}"
        table.add_row(s["client"], s["server_name"], target, s["config_path"])
    console.print(table)
    console.print(
        "\n[dim]Para escanear todos: [/dim]python cli/main.py scan --config <ruta_del_config_de_arriba>"
    )


def cmd_serve(args):
    import uvicorn
    if args.host not in ("127.0.0.1", "localhost", "::1"):
        console.print(f"[bold red]⚠ bindeando a {args.host} (no localhost) — el dashboard puede lanzar "
                       f"procesos locales y abrir conexiones salientes reales; no lo expongas a redes "
                       f"no confiables sin auth/proxy encima.[/bold red]")
    token = args.token or os.environ.get("ARES_DASHBOARD_TOKEN")
    if token:
        os.environ["ARES_DASHBOARD_TOKEN"] = token  # webui/app.py lo lee al importarse -- setear ANTES de uvicorn.run
        console.print("[green]Gate de token activo[/green] -- cada request necesita el header "
                       "[bold]X-Ares-Token[/bold] o [bold]?token=...[/bold] en la URL.")
    elif args.host not in ("127.0.0.1", "localhost", "::1"):
        console.print("[yellow]Sin --token/ARES_DASHBOARD_TOKEN: el dashboard queda abierto a quien "
                       "llegue a este host/puerto, sin ningún gate.[/yellow]")
    console.print(f"[green]Ares dashboard:[/green] http://{args.host}:{args.port}")
    uvicorn.run("webui.app:app", host=args.host, port=args.port, reload=False, log_level="warning")


def cmd_update_rules(args):
    console.print("[cyan]Consultando gitleaks.toml (raw.githubusercontent.com, público, sin API key)...[/cyan]")
    try:
        patterns = asyncio.run(fetch_gitleaks_patterns())
    except Exception as e:
        console.print(f"[red]Falló la actualización: {e}[/red]")
        sys.exit(1)
    save_cache(patterns, source="gitleaks")
    info = cache_info()
    console.print(f"[green]Listo:[/green] {info['count']} patrones de secretos cacheados en {info['path']}")
    console.print("[dim]Se usan automáticamente en supplychain.secret_exposure en el próximo scan. "
                  "Este comando es la única parte de Ares que consulta una fuente pública para "
                  "'mantenerse actualizada'; los scans en sí no llaman a esto solos.[/dim]")


def cmd_check_frameworks(args):
    """Avisa si alguno de los frameworks externos citados en frameworks.py (OWASP MCP/LLM/API
    Top 10, MITRE ATLAS) cambió desde la última vez que se corrió esto -- NUNCA actualiza
    mapeos ni descarga nada para aplicar (a diferencia de update-rules): es pura alerta para
    que un humano decida si hace falta revisar/sumar algo. Ver engine/core/framework_watch.py."""
    console.print("[cyan]Consultando la señal de versión pública de cada framework (GitHub API, sin token)...[/cyan]")
    try:
        results = asyncio.run(check_for_updates())
    except Exception as e:
        console.print(f"[red]Falló la consulta: {e}[/red]")
        sys.exit(1)

    table = Table(title="Frameworks de seguridad externos -- estado de versión")
    table.add_column("Framework")
    table.add_column("Estado")
    table.add_column("Ref. actual")
    table.add_column("Ref. cacheada")
    table.add_column("Ares asume")

    any_alert = False
    for r in results:
        if r["status"] == "error":
            table.add_row(r["label"], "[yellow]no se pudo verificar[/yellow]", "-", "-", f"[dim]{r['error'][:60]}[/dim]")
            continue
        if r["status"] == "baseline_set":
            style, label = "dim", "baseline (primera corrida)"
        elif r["status"] == "POSIBLE_ACTUALIZACION":
            style, label = "bold red", "⚠ POSIBLE ACTUALIZACIÓN"
            any_alert = True
        else:
            style, label = "green", "sin cambios"
        table.add_row(
            r["label"], f"[{style}]{label}[/{style}]",
            r["current_ref"], r.get("cached_ref") or "(ninguna)", r["tracked_as"],
        )
    console.print(table)

    if any_alert:
        console.print(
            "\n[bold red]Al menos un framework cambió su versión públicamente desde el último "
            "check.[/bold red] Esto NO significa que Ares esté desactualizado -- significa que vale "
            "la pena revisar manualmente si el cambio afecta engine/core/frameworks.py o algún test. "
            "Corré con [bold]--ack[/bold] para aceptar el estado actual como nuevo baseline (deja de "
            "avisar sobre ESTE cambio puntual)."
        )
    elif not any(r["status"] == "error" for r in results):
        console.print("[dim]Sin novedades respecto al último check.[/dim]")

    if args.ack:
        save_baseline(results)
        console.print("[green]Baseline actualizado.[/green]")

    # --fail-if-stale: pensado para CI -- sin esta flag, el comando SIEMPRE sale con
    # código 0 (uso interactivo normal: avisar es suficiente, no hay "build" que fallar).
    # Con la flag, un pipeline puede exigir que alguien haya corrido esto hace poco Y que
    # no haya quedado un cambio sin revisar -- "nadie corrió esto en los últimos N días"
    # es una señal tan útil como "cambió algo", porque un pipeline que nunca lo corre
    # nunca se entera de nada. Se evalúa DESPUÉS de un --ack en la misma invocación (si
    # se pasan juntos, el --ack de hoy ya cuenta como corrida reciente).
    if args.fail_if_stale is not None:
        exit_code = 1 if any_alert else 0
        age = oldest_baseline_age_days()
        if age is None:
            console.print("[red]--fail-if-stale: nunca se corrió --ack -- sin baseline.[/red]")
            exit_code = 1
        elif age > args.fail_if_stale:
            console.print(f"[red]--fail-if-stale: el baseline más viejo tiene {age:.1f} días "
                           f"(límite: {args.fail_if_stale}).[/red]")
            exit_code = 1
        if exit_code:
            sys.exit(exit_code)


def _parse_headers(raw: list[str]) -> dict:
    headers = {}
    for h in raw or []:
        if ":" not in h:
            continue
        k, v = h.split(":", 1)
        headers[k.strip()] = v.strip()
    return headers


def _build_auth(args) -> AuthConfig | None:
    if not args.auth_token:
        return None
    return AuthConfig(type=args.auth_type, token=args.auth_token, header_name=args.auth_header_name)


def _build_secondary_auth(args) -> AuthConfig | None:
    """Segunda identidad/tenant, para auth.cross_session_context_bleed -- completamente
    independiente de --auth-token (la primaria). Sin --auth-token-b, el test se saltea
    solo (ver auth/tests.py), no hace falta chequear nada más acá."""
    token = getattr(args, "auth_token_b", None)
    if not token:
        return None
    return AuthConfig(type=getattr(args, "auth_type_b", "bearer") or "bearer",
                       token=token, header_name=getattr(args, "auth_header_name_b", None))


def _truncate(value, n: int = 200) -> str:
    s = value if isinstance(value, str) else repr(value)
    s = s.replace("\n", " ")
    return s if len(s) <= n else s[:n] + "…"


def _make_progress(label: str = "", verbose: bool = False):
    def progress(event):
        t = event["type"]
        tags = [label] if label else []
        if "phase" in event:
            tags.append(event["phase"])
        # escapar: "[nombre-del-target] " es texto literal, no markup de rich -- sin esto,
        # rich lo interpreta como un tag de estilo desconocido y lo descarta en silencio
        prefix = _rich_escape(f"[{'/'.join(tags)}] ") if tags else ""
        if t == "test_started":
            console.print(f"{prefix}[cyan]▶ corriendo[/cyan] {event['test_id']} — {event['name']}")
        elif t == "tool_call":
            if not verbose:
                return
            # escapar SIEMPRE lo que viene del target -- un request/response real de MCP
            # suele traer '[' y ']' (reprs de listas/dicts), que rich interpretaría como
            # markup y comería en silencio si no se escapa.
            req = _rich_escape(_truncate(event["request"]))
            err = f" [red]error: {_rich_escape(_truncate(event['error'], 120))}[/red]" if event.get("error") else ""
            elapsed = f" ({event['elapsed_ms']:.1f}ms)" if event.get("elapsed_ms") else ""
            console.print(f"{prefix}    [dim]→ {event['kind']}({req}){elapsed}[/dim]{err}")
            if event.get("response") is not None and not event.get("error"):
                resp = _rich_escape(_truncate(event["response"]))
                console.print(f"{prefix}      [dim]← {resp}[/dim]")
        elif t == "test_finished":
            mark = "🔴" if event["confirmed"] else "🟢"
            console.print(f"{prefix}  {mark} {event['findings_count']} findings, {event['confirmed']} confirmados")
        elif t == "test_error":
            timeout_tag = " (timeout)" if event.get("timeout") else ""
            console.print(f"{prefix}  [red]✖ error en {event['test_id']}: {event['error']}{timeout_tag}[/red]")
        elif t == "connection_error":
            console.print(f"{prefix}[bold red]Error de conexión: {event['error']}[/bold red]")
        elif t == "noise_reduction":
            console.print(f"{prefix}  [dim]· reducción de ruido: {event['allowlisted']} suprimido(s) por allowlist, "
                           f"{event['below_confidence_floor']} por piso de confidence[/dim]")
        elif t == "scan_finished":
            s = event["summary"]
            console.print(f"\n{prefix}[bold]Resumen:[/bold] {s['confirmed_findings']} hallazgos confirmados de {s['total_tests_run']} tests")
            console.print(f"  por severidad: {s['by_severity']}")
            if event.get("score"):
                sc = event["score"]
                console.print(f"  [bold]Score:[/bold] {sc['score']}/100 (grade {sc['grade']}) — {sc['verdict_text']}")
            if event.get("policy"):
                console.print(f"  [bold]Policy verdict:[/bold] {event['policy']['overall']}")
    return progress


def _resolve_allowlist(args) -> str | None:
    explicit = getattr(args, "allowlist", None)
    if explicit:
        return explicit
    auto = default_allowlist_path()
    if auto:
        console.print(f"[dim]Usando allowlist auto-detectada: {auto}[/dim]")
    return auto


def _resolve_ca_bundle_arg(args):
    """Resuelve --ca-bundle (con fallback a SSL_CERT_FILE) y avisa de qué fuente salió.
    Sale con error claro si la ruta dada no existe, en vez de caer en silencio al trust
    store por defecto y reportar un falso 'TLS roto'."""
    try:
        ca = resolve_ca_bundle(getattr(args, "ca_bundle", None))
    except ValueError as e:
        console.print(f"[red]{e}[/red]")
        sys.exit(1)
    if ca:
        src = ca_bundle_source(getattr(args, "ca_bundle", None))
        console.print(f"[green]CA custom para validar TLS:[/green] {ca} "
                      f"[dim](de {'--ca-bundle' if src == 'flag' else 'SSL_CERT_FILE'})[/dim]")
    return ca


def _build_config(args, target_name: str, transport: str, connection: dict) -> ScanConfig:
    selected = args.tests.split(",") if args.tests else []
    connection = dict(connection)
    auth = _build_auth(args)
    headers = _parse_headers(args.header)
    if headers:
        # merge, no reemplazo -- 'connection' puede traer headers propios de un server
        # descubierto vía --config/discover (ej. una API key en claude_desktop_config.json);
        # pisarlos con connection["headers"] = headers los descartaba en silencio. Mismo
        # criterio que _full_one() (más abajo) y webui/app.py::_build_config() -- los tres
        # caminos deben mezclar headers de la misma forma.
        connection.setdefault("headers", {}).update(headers)
    return ScanConfig(
        target_name=target_name,
        transport=transport,
        connection=connection,
        selected_tests=selected,
        max_fuzz_cases_per_tool=args.max_fuzz_cases,
        allow_network_side_effects=args.allow_network,
        auth=auth,
        environment=args.environment,
        source_path=args.source_path,
        ca_bundle=_resolve_ca_bundle_arg(args),
        trust_presented_cert=getattr(args, "trust_presented_cert", False),
        request_delay_ms=args.request_delay_ms,
        oob_callback_host=args.oob_callback_host,
        baseline_path=getattr(args, "baseline", None),
        allowlist_path=_resolve_allowlist(args),
        min_confidence=getattr(args, "min_confidence", "heuristic"),
        live_agent_provider=getattr(args, "live_agent_provider", "auto"),
        package_name=getattr(args, "package_name", None),
        test_timeout_s=getattr(args, "test_timeout_s", 60.0),
        verbose=getattr(args, "verbose", False),
        max_consecutive_timeouts=getattr(args, "max_consecutive_timeouts", 3),
        sandbox_subprocess=not getattr(args, "no_sandbox", False),
        sandbox_mem_mb=getattr(args, "sandbox_mem_mb", 512),
        sandbox_cpu_s=getattr(args, "sandbox_cpu_s", 120),
        sandbox_nproc=getattr(args, "sandbox_nproc", None),
        sandbox_nofile=getattr(args, "sandbox_nofile", 256),
        max_text_for_analysis=getattr(args, "max_text_for_analysis", None),
        max_response_content=getattr(args, "max_response_content", None),
        reset_session_on_timeout=not getattr(args, "no_session_reset", False),
        secondary_auth=_build_secondary_auth(args),
    )


def _write_reports(report, out_html: str, sarif_path: str | None):
    safe_report = redact_report(report)  # nunca persistir secretos que hayan quedado en la evidencia cruda
    out_json = out_html.replace(".html", ".json") if out_html.endswith(".html") else out_html + ".json"
    with open(out_json, "w", encoding="utf-8") as f:
        json.dump(safe_report.to_dict(), f, indent=2, ensure_ascii=False, default=str)
    save_html_report(safe_report, out_html)
    console.print(f"\n[green]Reporte guardado:[/green] {out_html} / {out_json}")
    if sarif_path:
        save_sarif_report(safe_report, sarif_path)
        console.print(f"[green]SARIF guardado:[/green] {sarif_path}")


_SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"]
_SEVERITY_COLOR = {"critical": "bold red", "high": "red", "medium": "yellow", "low": "cyan", "info": "dim"}


def _print_findings_table(report, title: str | None = None):
    """Vuelca el detalle de cada hallazgo CONFIRMADO (no suprimido) directo en
    la terminal (severidad, confidence, test_id, target, título, remediación)
    -- para no depender de abrir el .html cuando solo se quiere ver el
    resultado ahí mismo. Los suprimidos (allowlist/--min-confidence) no
    aparecen acá -- ver reporte.html/.json para auditarlos."""
    confirmed = [f for f in report.findings if not f.passed and not f.suppressed]
    suppressed_count = sum(1 for f in report.findings if not f.passed and f.suppressed)
    confirmed.sort(key=lambda f: _SEVERITY_ORDER.index(f.severity.value) if f.severity.value in _SEVERITY_ORDER else 99)

    if not confirmed:
        extra = f" ({suppressed_count} suprimido(s), ver reporte para auditar)" if suppressed_count else ""
        console.print(f"[green]✓ Sin hallazgos confirmados — {report.target_name}.[/green]{extra}")
        return

    t = Table(title=title or f"Hallazgos confirmados — {report.target_name} ({len(confirmed)})"
                            + (f" · {suppressed_count} suprimido(s)" if suppressed_count else ""))
    t.add_column("Sev")
    t.add_column("Conf")
    t.add_column("Test ID")
    t.add_column("Target")
    t.add_column("Título")
    t.add_column("Remediación", overflow="fold")
    for f in confirmed:
        c = _SEVERITY_COLOR.get(f.severity.value, "white")
        t.add_row(f"[{c}]{f.severity.value.upper()}[/{c}]", f.confidence, f.test_id, f.target,
                   f.title, f.remediation or "-")
    console.print(t)


def _emit_report(report, args, out_html: str, sarif_path: str | None = None, label: str | None = None):
    """Punto único de salida de un ScanReport: escribe archivos (.html/.json/
    .sarif) salvo que se pida --no-file, e imprime el detalle en terminal si
    se pidió --print (o siempre, si --no-file dejó al archivo fuera de juego --
    de lo contrario la corrida no mostraría ningún resultado)."""
    if not getattr(args, "no_file", False):
        _write_reports(report, out_html, sarif_path)
    if getattr(args, "print_findings", False) or getattr(args, "no_file", False):
        _print_findings_table(report, title=label)


def _regression_summary(new_findings: list[dict]) -> list[dict]:
    """Solo lo mínimo para notificar (test_id/severity/title/target) -- nunca
    evidence.request/response: un webhook es un destino externo, y Ares no
    exfiltra ahí lo mismo que redacta antes de persistir a disco."""
    return [{"test_id": f["test_id"], "severity": f["severity"], "target": f["target"], "title": f["title"]} for f in new_findings]


async def _post_webhook(url: str, payload: dict):
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.post(url, json=payload)
        console.print(f"[green]Webhook enviado[/green] a {url} (HTTP {resp.status_code})")
    except Exception as e:
        console.print(f"[yellow]No se pudo enviar el webhook a {url}: {e}[/yellow]")


def _maybe_send_single_regression_webhook(args, report):
    """scan/vet: un solo target, un solo --baseline -- si hay hallazgos NUEVOS
    respecto al baseline, un único POST (nunca uno por finding ni uno por
    scan sin regresión)."""
    url = getattr(args, "webhook_on_regression", None)
    if not url or not report.baseline_diff:
        return
    new = report.baseline_diff.get("new") or []
    if not new:
        return
    asyncio.run(_post_webhook(url, {
        "event": "ares_regression", "target": report.target_name,
        "new_count": len(new), "new_findings": _regression_summary(new),
        "summary": report.baseline_diff["summary"],
    }))


def _run_one(args, target_name: str, transport: str, connection: dict):
    config = _build_config(args, target_name, transport, connection)

    if args.compare_auth:
        if not config.auth:
            console.print("[yellow]--compare-auth pedido pero no se pasó --auth-token; la corrida 'con auth' "
                           "y 'sin auth' serán idénticas.[/yellow]")
        report_with, report_without = asyncio.run(run_auth_comparison(config, progress_cb=_make_progress(verbose=config.verbose)))
        report = report_with
        console.print(f"\n[bold]Impacto de auth:[/bold] {report.auth_impact['summary']}")
        suffix_without = args.out.replace(".html", ".sin_auth.html") if args.out.endswith(".html") else args.out + ".sin_auth"
        _emit_report(report_without, args, suffix_without, None, label=f"Hallazgos SIN auth — {report_without.target_name}")
    else:
        report = asyncio.run(run_scan(config, progress_cb=_make_progress(verbose=config.verbose)))

    if args.baseline:
        try:
            report.baseline_diff = diff_against_baseline(report, args.baseline)
            console.print(f"\n[bold]Baseline:[/bold] {report.baseline_diff['summary']}")
            _maybe_send_single_regression_webhook(args, report)
        except FileNotFoundError:
            console.print(f"[yellow]--baseline '{args.baseline}' no existe, se omite el diff.[/yellow]")

    _emit_report(report, args, args.out, args.sarif_out)


def cmd_scan(args):
    if args.config:
        servers = discover_mcp_servers_from_file(args.config)
        if not servers:
            console.print(f"[red]No se encontraron servidores en '{args.config}'.[/red]")
            return
        for s in servers:
            console.print(f"\n[bold]=== {s['server_name']} ===[/bold]")
            out = args.out.replace(".html", f".{s['server_name']}.html") if args.out.endswith(".html") else f"{args.out}.{s['server_name']}"
            args_copy = argparse.Namespace(**vars(args))
            args_copy.out = out
            if s.get("url"):
                conn = {"url": s["url"]}
                if s.get("headers"):
                    conn["headers"] = s["headers"]
                _run_one(args_copy, s["server_name"], "http", conn)
            elif s.get("command"):
                _run_one(args_copy, s["server_name"], "stdio", {"command": s["command"], "args": s.get("args") or []})
        return

    if args.transport == "stdio":
        if not args.command:
            console.print("[red]--command es requerido para --transport stdio.[/red]")
            sys.exit(1)
        connection = {"command": args.command, "args": args.args.split() if args.args else []}
    else:
        if not args.url:
            console.print(f"[red]--url es requerido para --transport {args.transport}.[/red]")
            sys.exit(1)
        connection = {"url": args.url}

    _run_one(args, args.name or args.command or args.url, args.transport, connection)


def cmd_vet(args):
    """
    Auditoría de máxima cobertura para decidir si un MCP es apto para tu
    operación: corre TODOS los tests registrados (incluidos los opt-in:
    dynamic.rate_limit, auth.weak_credentials, adv.ssrf_exfil,
    supplychain.dependency_vulnerabilities, adv.live_agent_injection si hay
    ANTHROPIC_API_KEY), con --allow-network y --environment production
    forzados, compare-auth automático si diste --auth-token, y SARIF siempre.

    Es intrusivo a propósito -- pensado para correr ANTES de poner el MCP en
    producción, no contra algo que ya sirve tráfico real sin que lo sepas.
    """
    if args.transport == "stdio":
        if not args.command:
            console.print("[red]--command es requerido para --transport stdio.[/red]")
            sys.exit(1)
        connection = {"command": args.command, "args": args.args.split() if args.args else []}
    else:
        if not args.url:
            console.print(f"[red]--url es requerido para --transport {args.transport}.[/red]")
            sys.exit(1)
        connection = {"url": args.url}

    full_args = argparse.Namespace(
        transport=args.transport, command=args.command, args=args.args, url=args.url,
        name=args.name, tests=",".join(sorted(all_tests().keys())),
        out=args.out, sarif_out=args.sarif_out or (args.out.rsplit(".", 1)[0] + ".sarif"),
        baseline=args.baseline, max_fuzz_cases=args.max_fuzz_cases,
        allow_network=True, request_delay_ms=args.request_delay_ms,
        oob_callback_host=args.oob_callback_host, environment="production",
        source_path=args.source_path, ca_bundle=getattr(args, "ca_bundle", None),
        trust_presented_cert=getattr(args, "trust_presented_cert", False), header=args.header,
        auth_token=args.auth_token, auth_type=args.auth_type, auth_header_name=args.auth_header_name,
        compare_auth=bool(args.auth_token),
        print_findings=args.print_findings, no_file=args.no_file,
        allowlist=args.allowlist, min_confidence=args.min_confidence,
        live_agent_provider=args.live_agent_provider,
        webhook_on_regression=args.webhook_on_regression,
        package_name=args.package_name, test_timeout_s=args.test_timeout_s,
        verbose=args.verbose,
    )

    console.print(f"[bold]Auditoría de máxima cobertura[/bold] — {len(all_tests())} tests, "
                  f"incluidos los opt-in. Esto es intrusivo (fuzzing agresivo, rate limit burst, "
                  f"intentos de credenciales) -- confirmá que tenés autorización para este target.")
    if not args.source_path:
        console.print("[dim]Sin --source-path: supplychain.dependency_vulnerabilities y "
                       "supplychain.source_sast no van a tener nada para analizar y se saltean.[/dim]")
    if not any(os.environ.get(k) for k in ("ANTHROPIC_API_KEY", "OPENAI_API_KEY", "OLLAMA_HOST")):
        console.print("[dim]Sin ANTHROPIC_API_KEY/OPENAI_API_KEY/OLLAMA_HOST: adv.live_agent_injection se "
                       "saltea con un finding informativo (no gasta cuota).[/dim]")
    if not args.package_name:
        console.print("[dim]Sin --package-name: static.typosquatting_check se saltea con un finding "
                       "informativo.[/dim]")

    _run_one(full_args, args.name or args.command or args.url, args.transport, connection)


def _server_to_connection(s: dict) -> tuple[str, dict] | None:
    """Normaliza una entrada de discover/--config a (transport, connection)."""
    if s.get("url"):
        conn = {"url": s["url"]}
        if s.get("headers"):
            conn["headers"] = s["headers"]
        return "http", conn
    if s.get("command"):
        return "stdio", {"command": s["command"], "args": s.get("args") or []}
    return None


async def _full_one(sem: asyncio.Semaphore, args, server: dict, mode: str, out_dir: str, results: list):
    name = server.get("server_name") or server.get("command") or server.get("url") or "target"
    async with sem:
        parsed = _server_to_connection(server)
        if parsed is None:
            console.print(f"[yellow]⚠ '{name}' no tiene ni command ni url, se omite.[/yellow]")
            results.append({"name": name, "error": "sin command ni url"})
            return
        transport, connection = parsed
        headers = _parse_headers(args.header)
        if headers:
            connection.setdefault("headers", {}).update(headers)
        auth = _build_auth(args)
        if auth:
            connection["auth"] = auth

        selected = [] if mode == "scan" else sorted(all_tests().keys())
        config = ScanConfig(
            target_name=name,
            transport=transport,
            connection=connection,
            selected_tests=selected,
            max_fuzz_cases_per_tool=args.max_fuzz_cases,
            allow_network_side_effects=(mode == "vet") or args.allow_network,
            auth=auth,
            environment=args.environment,
            source_path=args.source_path,
            # ya validado una sola vez en cmd_full() antes del gather -- acá solo se resuelve
            # (misma ruta/env var) sin reimprimir ni re-chequear por cada target concurrente.
            ca_bundle=resolve_ca_bundle(getattr(args, "ca_bundle", None)),
            trust_presented_cert=getattr(args, "trust_presented_cert", False),
            request_delay_ms=args.request_delay_ms,
            oob_callback_host=args.oob_callback_host,
            allowlist_path=_resolve_allowlist(args),
            min_confidence=getattr(args, "min_confidence", "heuristic"),
            live_agent_provider=getattr(args, "live_agent_provider", "auto"),
            package_name=getattr(args, "package_name", None),
            test_timeout_s=getattr(args, "test_timeout_s", 60.0),
            verbose=getattr(args, "verbose", False),
        )

        console.print(f"[cyan]▶ {name}[/cyan] ({transport}, modo {mode})...")
        try:
            report = await run_scan(config, progress_cb=_make_progress(label=name, verbose=config.verbose))
            safe_name = re.sub(r"[^\w.-]+", "_", str(name)) or "target"

            baseline_dir = getattr(args, "baseline_dir", None)
            if baseline_dir:
                baseline_file = os.path.join(baseline_dir, f"{safe_name}.json")
                if os.path.isfile(baseline_file):
                    report.baseline_diff = diff_against_baseline(report, baseline_file)

            out_html = os.path.join(out_dir, f"{safe_name}.html")
            _emit_report(report, args, out_html, None, label=f"Hallazgos confirmados — {name}")
            s = report.summary()
            results.append({
                "name": name, "out": None if getattr(args, "no_file", False) else out_html, "summary": s,
                "score": report.score, "policy": report.policy_verdict,
                "tools_enumerated": report.tools_enumerated,
                "baseline_diff": report.baseline_diff,
            })
            grade = report.score["grade"] if report.score else "?"
            verdict = report.policy_verdict["overall"] if report.policy_verdict else "?"
            where = f"-> {out_html}" if not getattr(args, "no_file", False) else "(--no-file, solo terminal)"
            console.print(f"[green]✔ listo:[/green] {name} — {s['confirmed_findings']} hallazgos, "
                          f"grade {grade}, policy {verdict} {where}")
        except Exception as e:
            results.append({"name": name, "error": str(e)})
            console.print(f"[red]✖ falló:[/red] {name}: {e}")


async def _run_full(args, servers: list[dict], mode: str, out_dir: str) -> list[dict]:
    sem = asyncio.Semaphore(max(1, args.concurrency))
    results: list[dict] = []
    await asyncio.gather(*(_full_one(sem, args, s, mode, out_dir, results) for s in servers))
    return results


def cmd_full(args):
    """
    Modo 'full': encadena discover -> scan/vet de TODOS los targets encontrados,
    corriéndolos simultáneamente (hasta --concurrency a la vez) en vez de uno por
    uno. Es el equivalente batch de correr cada modo a mano en orden.
    """
    console.print("[bold]Modo full[/bold] — 1) discover  2) "
                  f"{args.mode} de cada server encontrado, en paralelo (máx {args.concurrency} a la vez)\n")

    _resolve_ca_bundle_arg(args)  # valida/avisa una sola vez; _full_one lo re-resuelve silencioso por target

    if args.config:
        servers = discover_mcp_servers_from_file(args.config)
    elif args.command or args.url:
        if args.transport == "stdio" and not args.command:
            console.print("[red]--command es requerido para --transport stdio.[/red]")
            sys.exit(1)
        if args.transport != "stdio" and not args.url:
            console.print(f"[red]--url es requerido para --transport {args.transport}.[/red]")
            sys.exit(1)
        servers = [{
            "server_name": args.name or args.command or args.url,
            "command": args.command,
            "args": args.args.split() if args.args else [],
            "url": args.url if args.transport != "stdio" else None,
        }]
    else:
        servers = discover_mcp_servers()

    if not servers:
        console.print("[yellow]No se encontraron servidores MCP (ni localmente, ni por --config/--command/--url).[/yellow]")
        return

    table = Table(title=f"Targets a correr en modo full ({len(servers)})")
    table.add_column("Servidor")
    table.add_column("Target")
    for s in servers:
        target = s.get("url") or f"{s.get('command')} {' '.join(s.get('args') or [])}"
        table.add_row(s.get("server_name") or "?", target)
    console.print(table)

    if not args.no_file:
        os.makedirs(args.out_dir, exist_ok=True)
    results = asyncio.run(_run_full(args, servers, args.mode, args.out_dir))

    summary = Table(title="Resumen modo full")
    summary.add_column("Servidor")
    summary.add_column("Hallazgos")
    summary.add_column("Grade")
    summary.add_column("Policy")
    summary.add_column("Reporte")
    ok = 0
    for r in results:
        if "error" in r:
            summary.add_row(r["name"], "[red]error[/red]", "-", "-", r["error"])
            continue
        ok += 1
        s = r["summary"]
        grade = r["score"]["grade"] if r["score"] else "?"
        verdict = r["policy"]["overall"] if r["policy"] else "?"
        summary.add_row(r["name"], str(s["confirmed_findings"]), grade, verdict, r["out"] or "(--no-file)")
    console.print(summary)
    if args.no_file:
        console.print(f"\n[bold]{ok}/{len(results)}[/bold] targets completados. (--no-file: nada se escribió a disco, ver detalle arriba en terminal)")
    else:
        console.print(f"\n[bold]{ok}/{len(results)}[/bold] targets completados. Reportes en [green]{args.out_dir}/[/green]")

    if not args.no_cross_server:
        _run_cross_server_correlation(args, results)

    _maybe_send_full_regression_webhook(args, results)


def _maybe_send_full_regression_webhook(args, results: list[dict]):
    """full: N targets, N posibles baselines -- UN SOLO POST agregando todos
    los que tuvieron hallazgos nuevos (nunca uno por target, nunca si nadie
    tuvo regresión). Es la versión 'campaña' matizada: sin cron/scheduling
    propio -- eso lo corre el cron/systemd timer del SO llamando a
    'ares.sh full --baseline-dir ... --webhook-on-regression ...'."""
    url = getattr(args, "webhook_on_regression", None)
    if not url:
        return
    regressions = []
    for r in results:
        diff = r.get("baseline_diff")
        if diff and diff.get("new"):
            regressions.append({
                "target": r["name"], "new_count": len(diff["new"]),
                "new_findings": _regression_summary(diff["new"]),
            })
    if not regressions:
        console.print("[dim]--webhook-on-regression: sin hallazgos nuevos en ningún target, no se envía nada.[/dim]")
        return
    asyncio.run(_post_webhook(url, {
        "event": "ares_full_regression",
        "targets_with_new_findings": regressions,
        "summary": f"{len(regressions)} de {len(results)} target(s) tienen hallazgos nuevos desde su baseline.",
    }))


def _run_cross_server_correlation(args, results: list[dict]):
    ok_results = [r for r in results if "error" not in r]
    if len(ok_results) < 2:
        return  # analyze_cross_server ya maneja esto, pero evitamos el ruido de "0 hallazgos" con 0-1 targets

    reports_by_server = {r["name"]: r.get("tools_enumerated") or [] for r in ok_results}
    correlation = analyze_cross_server(reports_by_server)

    console.print(f"\n[bold]Correlación cross-server[/bold] (MCP09:2025 Tool Shadowing + cadenas de exfiltración "
                  f"entre targets distintos) — {correlation['summary']}")

    if correlation["tool_shadowing"]:
        t = Table(title=f"Tool shadowing entre servers ({len(correlation['tool_shadowing'])})")
        t.add_column("Sev")
        t.add_column("Tipo")
        t.add_column("Servers")
        t.add_column("Tools")
        t.add_column("Detalle", overflow="fold")
        for item in correlation["tool_shadowing"]:
            c = _SEVERITY_COLOR.get(item["severity"], "white")
            t.add_row(f"[{c}]{item['severity'].upper()}[/{c}]", item["kind"],
                       " / ".join(item["servers"]), " / ".join(item["tools"]), item["detail"])
        console.print(t)

    if correlation["cross_server_exfil_chains"]:
        t = Table(title=f"Cadenas de exfiltración cross-server ({len(correlation['cross_server_exfil_chains'])})")
        t.add_column("Sev")
        t.add_column("Servers")
        t.add_column("Tools")
        t.add_column("Detalle", overflow="fold")
        for item in correlation["cross_server_exfil_chains"]:
            c = _SEVERITY_COLOR.get(item["severity"], "white")
            t.add_row(f"[{c}]{item['severity'].upper()}[/{c}]",
                       " / ".join(item["servers"]), " / ".join(item["tools"]), item["detail"])
        console.print(t)

    if not correlation["tool_shadowing"] and not correlation["cross_server_exfil_chains"]:
        console.print("[green]✓ Sin indicios de tool shadowing ni cadenas de exfiltración cross-server.[/green]")

    if not args.no_file:
        # '_raw': el reporte real (HTML/json/SARIF con score/policy) se guarda más abajo
        # como cross_server_correlation.json -- mismo nombre sin el sufijo hubiera pisado
        # a este (lo pisaba, de hecho, hasta que se encontró corriendo esto de verdad).
        out_path = os.path.join(args.out_dir, "cross_server_correlation_raw.json")
        with open(out_path, "w", encoding="utf-8") as f:
            json.dump(correlation, f, indent=2, ensure_ascii=False)
        console.print(f"[green]Correlación (dict crudo) guardada:[/green] {out_path}")

    # Antes de esto, lo de arriba era TODO lo que existía: un dict suelto impreso en
    # terminal y volcado a un .json plano -- nunca pasaba por calculate_score/
    # PolicyEngine/SARIF, aunque el propio código ya marca severity='critical' para
    # directive_cross_reference. Un CI con --sarif-out jamás veía esto en el code
    # scanning de GitHub, y ninguna policy BLOCK podía gatillar por acá. Se arma un
    # ScanReport real con el mismo pipeline que cualquier otro target.
    findings = cross_server_findings(reports_by_server)
    report = ScanReport(
        scan_id=str(uuid.uuid4())[:8],
        target_name="(correlación cross-server)",
        started_at=datetime.now(timezone.utc).isoformat(),
        ares_version=ARES_VERSION,
        findings=findings,
    )
    report.finished_at = datetime.now(timezone.utc).isoformat()
    report.score = calculate_score(report)
    report.policy_verdict = PolicyEngine().evaluate(report, args.environment)
    console.print(f"[bold]Correlación cross-server:[/bold] score {report.score['score']}/100 "
                  f"(grade {report.score['grade']}) — policy {report.policy_verdict['overall']}")

    if not args.no_file:
        out_html = os.path.join(args.out_dir, "cross_server_correlation.html")
        out_sarif = os.path.join(args.out_dir, "cross_server_correlation.sarif")
        _write_reports(report, out_html, out_sarif)


def discover_mcp_servers_from_file(path: str) -> list[dict]:
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)
    servers = data.get("mcpServers") or data.get("mcp_servers") or {}
    out = []
    for name, cfg in servers.items():
        if not isinstance(cfg, dict):
            continue
        out.append({
            "server_name": name, "command": cfg.get("command"),
            "args": cfg.get("args", []), "url": cfg.get("url") or cfg.get("serverUrl"),
            "headers": cfg.get("headers"),
        })
    return out


def main():
    parser = argparse.ArgumentParser(description="Ares — MCP Red Team Tool")
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_list = sub.add_parser("list-tests")
    p_list.set_defaults(func=cmd_list_tests)

    p_discover = sub.add_parser("discover", help="Descubre servers MCP configurados localmente (Claude Desktop, Cursor, etc.)")
    p_discover.set_defaults(func=cmd_discover)

    p_rules = sub.add_parser("update-rules", help="Refresca el cache local de patrones de secretos desde gitleaks.toml (público, sin API key)")
    p_rules.set_defaults(func=cmd_update_rules)

    p_frameworks = sub.add_parser("check-frameworks", help="Avisa si OWASP MCP/LLM/API Top 10 o MITRE ATLAS cambiaron de versión -- nunca actualiza nada solo")
    p_frameworks.add_argument("--ack", action="store_true", help="acepta el estado actual como nuevo baseline (deja de avisar sobre este cambio puntual)")
    p_frameworks.add_argument("--fail-if-stale", dest="fail_if_stale", type=float, default=None, help="para CI: exit code 1 si el baseline más viejo tiene más de N días, o si no hay baseline, o si hay un cambio sin revisar. Sin esta flag, el comando siempre sale 0 (uso interactivo normal)")
    p_frameworks.set_defaults(func=cmd_check_frameworks)

    p_serve = sub.add_parser("serve", help="Levanta el dashboard web (FastAPI + WebSocket) en localhost")
    p_serve.add_argument("--host", default="127.0.0.1")
    p_serve.add_argument("--port", type=int, default=8000)
    p_serve.add_argument("--token", default=None, help="exige este token (header X-Ares-Token o ?token=) en toda request al dashboard. También se puede setear via ARES_DASHBOARD_TOKEN")
    p_serve.set_defaults(func=cmd_serve)

    p_scan = sub.add_parser("scan")
    p_scan.add_argument("--transport", choices=["stdio", "sse", "http"], default="stdio")
    p_scan.add_argument("--command", default=None, help="comando para lanzar el server MCP (stdio), ej: python")
    p_scan.add_argument("--args", default="", help="argumentos del comando, ej: 'target_server.py'")
    p_scan.add_argument("--url", default=None, help="URL del server MCP (transporte sse/http)")
    p_scan.add_argument("--config", default=None, help="ruta a un config estilo Claude Desktop; escanea todos sus mcpServers en batch")
    p_scan.add_argument("--name", default=None)
    p_scan.add_argument("--tests", default="", help="lista de test ids separados por coma; vacío = todos los default")
    p_scan.add_argument("--out", default="reporte.html")
    p_scan.add_argument("--sarif-out", dest="sarif_out", default=None, help="también exporta hallazgos confirmados en SARIF")
    p_scan.add_argument("--baseline", default=None, help="ruta a un reporte.json anterior; agrega al reporte qué hallazgos son nuevos/resueltos/persisten desde esa corrida")
    p_scan.add_argument("--max-fuzz-cases", type=int, default=25)
    p_scan.add_argument("--allow-network", action="store_true", help="habilita tests que hacen conexiones externas reales (SSRF, etc.)")
    p_scan.add_argument("--request-delay-ms", dest="request_delay_ms", type=int, default=0, help="pausa entre llamadas a tools, para no saturar targets sensibles")
    p_scan.add_argument("--oob-callback-host", dest="oob_callback_host", default=None, help='host:puerto alcanzable por el target, para confirmar adv.ssrf_exfil por callback real (ej. "192.168.1.50:8899")')
    p_scan.add_argument("--environment", choices=["production", "development"], default="production", help="ambiente usado por el policy engine para el veredicto BLOCK/CONDITIONAL/ALLOW")
    p_scan.add_argument("--source-path", dest="source_path", default=None, help="ruta local al código fuente del server, para supplychain.dependency_vulnerabilities")
    p_scan.add_argument("--ca-bundle", dest="ca_bundle", default=None, help="ruta a un bundle de CA (PEM) para validar el certificado TLS del server (http/sse) contra una CA interna/corporativa, sin desactivar la verificación. Fallback: variable de entorno SSL_CERT_FILE")
    p_scan.add_argument("--trust-presented-cert", dest="trust_presented_cert", action="store_true", help="http/sse: si la conexión falla por TLS no confiable (self-signed/CA desconocida) y no diste --ca-bundle, trae el certificado que presenta el server y lo FIJA (pinning TOFU) para conectarse y correr las pruebas igual. NO valida identidad (el cert se sigue reportando self-signed/riesgo) -- es para auditar un target interno sin frenar")
    p_scan.add_argument("--header", action="append", default=[], help='header HTTP extra "Clave: Valor" (repetible, transporte sse/http)')
    p_scan.add_argument("--auth-token", dest="auth_token", default=None, help="credencial a inyectar (transporte sse/http)")
    p_scan.add_argument("--auth-type", dest="auth_type", choices=["bearer", "apikey", "custom"], default="bearer")
    p_scan.add_argument("--auth-header-name", dest="auth_header_name", default=None, help="nombre del header para auth-type apikey/custom, ej: X-API-Key")
    p_scan.add_argument("--auth-token-b", dest="auth_token_b", default=None, help="SEGUNDA credencial/tenant válido contra el mismo server, para auth.cross_session_context_bleed (fuga de contexto entre sesiones -- MCP10:2025). Independiente de --auth-token")
    p_scan.add_argument("--auth-type-b", dest="auth_type_b", choices=["bearer", "apikey", "custom"], default="bearer")
    p_scan.add_argument("--auth-header-name-b", dest="auth_header_name_b", default=None, help="nombre del header para --auth-type-b apikey/custom")
    p_scan.add_argument("--compare-auth", dest="compare_auth", action="store_true", help="corre el scan con y sin las credenciales dadas, y reporta qué hallazgos mitiga realmente la auth")
    p_scan.add_argument("--print", dest="print_findings", action="store_true", help="además de los archivos, imprime en la terminal el detalle de cada hallazgo confirmado (severidad, confidence, test, target, remediación)")
    p_scan.add_argument("--no-file", dest="no_file", action="store_true", help="no escribe reporte.html/.json/.sarif -- solo termina en la terminal (implica --print)")
    p_scan.add_argument("--allowlist", default=None, help="ruta a un .ares_allowlist.yml; sin esto, se auto-detecta '.ares_allowlist.yml' en el directorio actual si existe. Suprime findings conocidos/aceptados (no los borra: siguen en el reporte, pero no gatean score/policy)")
    p_scan.add_argument("--min-confidence", dest="min_confidence", choices=["heuristic", "verified"], default="heuristic", help="'verified' (default 'heuristic') sube el piso de qué gatea score/policy: solo hechos observados directamente bloquean, lo heurístico queda visible pero no cuenta -- gran reductor de ruido en CI")
    p_scan.add_argument("--live-agent-provider", dest="live_agent_provider", choices=["auto", "anthropic", "openai", "ollama", "all"], default="auto", help="proveedor(es) para adv.live_agent_injection. 'auto' = el primero con credencial disponible; 'all' = corre contra todos los que tengan credencial (comparación cross-model)")
    p_scan.add_argument("--package-name", dest="package_name", default=None, help="nombre de paquete declarado (npm/pypi) para static.typosquatting_check, ej. 'mcp-server-fetch'")
    p_scan.add_argument("--test-timeout-s", dest="test_timeout_s", type=float, default=60.0, help="segundos máximos por test antes de cortarlo y seguir con el resto (default 60)")
    p_scan.add_argument("--max-consecutive-timeouts", dest="max_consecutive_timeouts", type=int, default=3, help="circuit breaker: tras N timeouts seguidos, se saltea el resto de la batería de una (0 = sin límite)")
    p_scan.add_argument("--no-sandbox", dest="no_sandbox", action="store_true", help="desactiva el aislamiento de proceso (prlimit) del subprocess stdio del target -- por default va con RLIMIT real de memoria/CPU/procesos/FDs")
    p_scan.add_argument("--sandbox-mem-mb", dest="sandbox_mem_mb", type=int, default=512, help="tope de memoria virtual (MB) del proceso del target vía prlimit (default 512)")
    p_scan.add_argument("--sandbox-cpu-s", dest="sandbox_cpu_s", type=int, default=120, help="tope de tiempo de CPU (segundos) del proceso del target vía prlimit (default 120)")
    p_scan.add_argument("--sandbox-nproc", dest="sandbox_nproc", type=int, default=None, help="tope de procesos/threads del target vía prlimit -- bloquea fork bombs. Default: calculado dinámicamente (lo que ya tiene el usuario corriendo + margen), nunca un número absoluto fijo")
    p_scan.add_argument("--sandbox-nofile", dest="sandbox_nofile", type=int, default=256, help="tope de file descriptors abiertos del target vía prlimit (default 256)")
    p_scan.add_argument("--max-text-for-analysis", dest="max_text_for_analysis", type=int, default=None, help="override del cap de chars analizados con regex (descripciones/schemas) -- default engine.core.limits.MAX_TEXT_FOR_ANALYSIS (200000)")
    p_scan.add_argument("--max-response-content", dest="max_response_content", type=int, default=None, help="override del cap de chars de una respuesta de call_tool/read_resource -- default engine.core.limits.MAX_RESPONSE_CONTENT (2000000)")
    p_scan.add_argument("--no-session-reset", dest="no_session_reset", action="store_true", help="no cerrar/reabrir la sesión tras un timeout -- por default sí se reconecta, para no arrastrar estado envenenado ni dejar el subprocess viejo vivo")
    p_scan.add_argument("--verbose", action="store_true", help="imprime cada llamada real (list_tools/call_tool/read_resource) en vivo, con request/response truncados -- no solo el resumen por test")
    p_scan.add_argument("--webhook-on-regression", dest="webhook_on_regression", default=None, help="requiere --baseline: si aparecen hallazgos NUEVOS respecto al baseline, hace UN POST JSON a esta URL (nunca si no hay regresión). Para correr esto en un cron/systemd timer del SO -- Ares no reinventa scheduling")
    p_scan.set_defaults(func=cmd_scan)

    p_vet = sub.add_parser("vet", help="Auditoría de máxima cobertura antes de implementar un MCP: corre TODOS los tests (incluidos opt-in), pensada para el gate de 'apto para mi operación'")
    p_vet.add_argument("--transport", choices=["stdio", "sse", "http"], default="stdio")
    p_vet.add_argument("--command", default=None)
    p_vet.add_argument("--args", default="")
    p_vet.add_argument("--url", default=None)
    p_vet.add_argument("--name", default=None)
    p_vet.add_argument("--out", default="reporte_vet.html")
    p_vet.add_argument("--sarif-out", dest="sarif_out", default=None, help="default: mismo nombre que --out con extensión .sarif")
    p_vet.add_argument("--baseline", default=None)
    p_vet.add_argument("--max-fuzz-cases", type=int, default=50, help="más alto que 'scan' default -- esto es auditoría exhaustiva")
    p_vet.add_argument("--request-delay-ms", dest="request_delay_ms", type=int, default=0)
    p_vet.add_argument("--oob-callback-host", dest="oob_callback_host", default=None)
    p_vet.add_argument("--source-path", dest="source_path", default=None, help="ruta al código fuente, para incluir el chequeo de dependencias vulnerables (OSV.dev)")
    p_vet.add_argument("--ca-bundle", dest="ca_bundle", default=None, help="ruta a un bundle de CA (PEM) para validar el TLS del server contra una CA interna (ver 'scan --help'); fallback SSL_CERT_FILE")
    p_vet.add_argument("--trust-presented-cert", dest="trust_presented_cert", action="store_true", help="fija el cert presentado (pinning TOFU) para conectarse a un target con cert interno y auditarlo igual (ver 'scan --help')")
    p_vet.add_argument("--header", action="append", default=[])
    p_vet.add_argument("--auth-token", dest="auth_token", default=None, help="si lo das, corre compare-auth automáticamente")
    p_vet.add_argument("--auth-type", dest="auth_type", choices=["bearer", "apikey", "custom"], default="bearer")
    p_vet.add_argument("--auth-header-name", dest="auth_header_name", default=None)
    p_vet.add_argument("--print", dest="print_findings", action="store_true", help="además de los archivos, imprime en la terminal el detalle de cada hallazgo confirmado")
    p_vet.add_argument("--no-file", dest="no_file", action="store_true", help="no escribe reporte_vet.html/.json/.sarif -- solo termina en la terminal (implica --print)")
    p_vet.add_argument("--allowlist", default=None, help="ruta a un .ares_allowlist.yml; sin esto, se auto-detecta en el directorio actual")
    p_vet.add_argument("--min-confidence", dest="min_confidence", choices=["heuristic", "verified"], default="heuristic", help="'verified' sube el piso de qué gatea score/policy (ver 'scan --help')")
    p_vet.add_argument("--live-agent-provider", dest="live_agent_provider", choices=["auto", "anthropic", "openai", "ollama", "all"], default="auto", help="proveedor(es) para adv.live_agent_injection")
    p_vet.add_argument("--package-name", dest="package_name", default=None, help="nombre de paquete declarado (npm/pypi) para static.typosquatting_check")
    p_vet.add_argument("--test-timeout-s", dest="test_timeout_s", type=float, default=60.0, help="segundos máximos por test (default 60)")
    p_vet.add_argument("--verbose", action="store_true", help="imprime cada llamada real en vivo (ver 'scan --help')")
    p_vet.add_argument("--webhook-on-regression", dest="webhook_on_regression", default=None, help="requiere --baseline: UN POST JSON a esta URL solo si aparecen hallazgos NUEVOS (ver 'scan --help')")
    p_vet.set_defaults(func=cmd_vet)

    p_full = sub.add_parser(
        "full",
        help="Modo batch: discover + scan/vet de TODOS los targets encontrados, en paralelo (equivalente a correr cada modo a mano en orden)",
    )
    p_full.add_argument("--mode", choices=["scan", "vet"], default="vet",
                         help="'scan' = tests default de cada target; 'vet' = cobertura máxima, todos los tests (default)")
    p_full.add_argument("--concurrency", type=int, default=3, help="cuántos targets correr en simultáneo (default 3)")
    p_full.add_argument("--out-dir", dest="out_dir", default="reportes_full", help="carpeta donde se guarda un reporte por target")
    p_full.add_argument("--config", default=None, help="ruta a un config estilo Claude Desktop; usa esos servers en vez de auto-discover")
    p_full.add_argument("--transport", choices=["stdio", "sse", "http"], default="stdio", help="solo si das --command/--url explícito (single target)")
    p_full.add_argument("--command", default=None, help="target único explícito (stdio), en vez de auto-discover")
    p_full.add_argument("--args", default="")
    p_full.add_argument("--url", default=None, help="target único explícito (http/sse), en vez de auto-discover")
    p_full.add_argument("--name", default=None)
    p_full.add_argument("--max-fuzz-cases", type=int, default=25)
    p_full.add_argument("--allow-network", action="store_true", help="ignorado en modo vet (ya lo fuerza); aplica solo a --mode scan")
    p_full.add_argument("--request-delay-ms", dest="request_delay_ms", type=int, default=0)
    p_full.add_argument("--oob-callback-host", dest="oob_callback_host", default=None)
    p_full.add_argument("--environment", choices=["production", "development"], default="production")
    p_full.add_argument("--source-path", dest="source_path", default=None)
    p_full.add_argument("--ca-bundle", dest="ca_bundle", default=None, help="ruta a un bundle de CA (PEM) para validar el TLS de TODOS los targets http/sse contra una CA interna; fallback SSL_CERT_FILE")
    p_full.add_argument("--trust-presented-cert", dest="trust_presented_cert", action="store_true", help="fija el cert presentado (pinning TOFU) de cada target http/sse para conectarse y auditar igual (ver 'scan --help')")
    p_full.add_argument("--header", action="append", default=[])
    p_full.add_argument("--auth-token", dest="auth_token", default=None)
    p_full.add_argument("--auth-type", dest="auth_type", choices=["bearer", "apikey", "custom"], default="bearer")
    p_full.add_argument("--auth-header-name", dest="auth_header_name", default=None)
    p_full.add_argument("--print", dest="print_findings", action="store_true", help="además de los archivos, imprime en la terminal el detalle de cada hallazgo confirmado por target")
    p_full.add_argument("--no-file", dest="no_file", action="store_true", help="no escribe ningún reporte a disco -- solo termina en la terminal (implica --print)")
    p_full.add_argument("--allowlist", default=None, help="ruta a un .ares_allowlist.yml, aplicado a TODOS los targets; sin esto, se auto-detecta en el directorio actual")
    p_full.add_argument("--min-confidence", dest="min_confidence", choices=["heuristic", "verified"], default="heuristic", help="'verified' sube el piso de qué gatea score/policy, aplicado a TODOS los targets")
    p_full.add_argument("--live-agent-provider", dest="live_agent_provider", choices=["auto", "anthropic", "openai", "ollama", "all"], default="auto")
    p_full.add_argument("--package-name", dest="package_name", default=None, help="nombre de paquete declarado (npm/pypi) para static.typosquatting_check, aplicado a TODOS los targets")
    p_full.add_argument("--test-timeout-s", dest="test_timeout_s", type=float, default=60.0, help="segundos máximos por test (default 60), aplicado a TODOS los targets")
    p_full.add_argument("--verbose", action="store_true", help="imprime cada llamada real en vivo por target, con prefijo [nombre-del-target]")
    p_full.add_argument("--no-cross-server", dest="no_cross_server", action="store_true", help="no corre la correlación cross-server (tool shadowing + cadenas de exfiltración entre targets distintos) al terminar")
    p_full.add_argument("--baseline-dir", dest="baseline_dir", default=None, help="carpeta con un reporte.json anterior POR TARGET (mismo nombre de archivo que --out-dir generaría, ej. 'stdio_practica.json'); si existe, se diffea igual que --baseline en scan/vet")
    p_full.add_argument("--webhook-on-regression", dest="webhook_on_regression", default=None, help="requiere --baseline-dir: UN SOLO POST JSON agregando TODOS los targets con hallazgos nuevos (nunca uno por target, nunca si nadie tuvo regresión)")
    p_full.set_defaults(func=cmd_full)

    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
