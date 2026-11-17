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

from engine.core.models import ScanConfig, AuthConfig, ScanReport, LEVEL_NAMES
from engine.reporting.scoring import calculate_score
from engine.policy.engine import PolicyEngine
from engine.core.registry import list_meta, all_tests, ids_at_or_below_level
from engine.orchestrator import run_scan
from engine.compare import run_auth_comparison
from engine.reporting.html_report import save_html_report
from engine.reporting.sarif import save_sarif_report
from engine.reporting.redact import redact_report
from engine.reporting.suppress import default_allowlist_path
from engine.baseline import diff_against_baseline
from engine.core.tls import resolve_ca_bundle, ca_bundle_source, fetch_presented_cert_pem
from engine.core.sandbox import DEFAULT_MEM_MB as DEFAULT_SANDBOX_MEM_MB
from engine.discovery.local_configs import discover_mcp_servers
from engine.crossserver import analyze_cross_server, cross_server_findings
from engine import __version__ as ARES_VERSION
from engine.supplychain.rule_sources import fetch_gitleaks_patterns, save_cache, cache_info
from engine.core.framework_watch import check_for_updates, save_baseline, oldest_baseline_age_days

console = Console()


def cmd_api_list_tests(args):
    from engine.api.registry import all_api_tests
    table = Table(title="Tests de API disponibles (REST + GraphQL)")
    table.add_column("ID"); table.add_column("Nivel"); table.add_column("Tipo")
    table.add_column("Nombre"); table.add_column("Default")
    reg = all_api_tests()
    for tid, (meta, _) in sorted(reg.items(), key=lambda kv: (getattr(kv[1][0], "kind", "rest"), kv[0])):
        table.add_row(tid, f"{meta.level} {LEVEL_NAMES[meta.level]}", getattr(meta, "kind", "rest"),
                      meta.name, "si" if meta.default_enabled else "no (opt-in)")
    console.print(table)


def cmd_list_tests(args):
    max_level = getattr(args, "max_level", None)
    table = Table(title="Tests disponibles" + (f" (nivel <= {max_level})" if max_level else ""))
    table.add_column("ID")
    table.add_column("Nivel")
    table.add_column("Categoría")
    table.add_column("Nombre")
    table.add_column("Default")
    table.add_column("Red externa")
    rows = sorted(list_meta(), key=lambda m: (m.level, m.category.value, m.id))
    if max_level:
        rows = [m for m in rows if m.level <= max_level]
    for meta in rows:
        table.add_row(
            meta.id, f"{meta.level} {LEVEL_NAMES[meta.level]}", meta.category.value, meta.name,
            "si" if meta.default_enabled else "no (opt-in)",
            "si" if meta.requires_network else "no",
        )
    console.print(table)
    console.print(
        "\n[dim]Niveles -- 1 Básico (metadata/análisis estático), 2 Intermedio (sondeo con "
        "payloads), 3 Avanzado (impacto confirmado/red real), 4 Crítico (agente real en el "
        "loop). Usá --max-level en 'scan'/'vet' para correr solo hasta un nivel dado.[/dim]"
    )


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

    verify_bad = 0
    if getattr(args, "verify", False):
        from engine.core.framework_watch import verify_citations
        console.print("\n[cyan]Verificando que cada código/ID citado en frameworks.py exista en su fuente primaria...[/cyan]")
        try:
            vrows = asyncio.run(verify_citations())
        except Exception as e:
            console.print(f"[red]Falló la verificación: {e}[/red]")
            vrows = []
        vt = Table(title="Citas verificadas contra la fuente primaria")
        for c in ("Framework", "Código", "Estado", "Detalle"):
            vt.add_column(c)
        for r in vrows:
            if r["status"] == "ok":
                continue  # solo mostrar lo que requiere atención; el resumen cuenta los ok
            verify_bad += 1
            vt.add_row(r["framework"], r["code"], f"[bold red]{r['status']}[/bold red]", r["detail"][:90])
        ok = sum(1 for r in vrows if r["status"] == "ok")
        if verify_bad:
            console.print(vt)
        console.print(f"[{'green' if not verify_bad else 'red'}]{ok}/{len(vrows)} citas verificadas OK"
                      f"{'' if not verify_bad else f', {verify_bad} requieren revisión'}.[/]")

    if args.ack and verify_bad:
        console.print("[bold red]No se aceptó el baseline:[/bold red] hay citas que no verifican contra la fuente primaria "
                      "(ver arriba). Corregir frameworks.py y volver a correr con --ack.")
    elif args.ack:
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
        exit_code = 1 if (any_alert or verify_bad) else 0
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


def cmd_check_lists(args):
    """Contrasta las listas curadas a mano contra su fuente pública real (ver engine/core/list_watch.py).
    Nunca modifica nada: solo informa qué hay que revisar."""
    from engine.core.list_watch import check_all_lists, STATUS_BAD
    console.print("[cyan]Verificando listas curadas contra OSV.dev, modelcontextprotocol/servers y gitleaks...[/cyan]")
    try:
        rows = asyncio.run(check_all_lists())
    except Exception as e:
        console.print(f"[red]Falló la verificación: {e}[/red]")
        sys.exit(1)
    table = Table(title="Listas curadas -- estado contra la fuente pública")
    for c in ("Lista", "Chequeo", "Estado", "Detalle"):
        table.add_column(c)
    style = {"ok": "green", "stale": "bold red", "drift": "bold red", "missing": "bold red", "error": "yellow"}
    for r in rows:
        table.add_row(r["list"], r["check"], f"[{style[r['status']]}]{r['status']}[/{style[r['status']]}]", r["detail"][:110])
    console.print(table)
    bad = [r for r in rows if r["status"] in STATUS_BAD]
    errs = [r for r in rows if r["status"] == "error"]
    if bad:
        console.print(f"\n[bold red]{len(bad)} chequeo(s) requieren revisión humana[/bold red] "
                      f"(vencida / desfasada / con entradas faltantes). Este comando nunca edita las listas.")
    if errs:
        console.print(f"[yellow]{len(errs)} chequeo(s) no se pudieron completar (red/API) -- no cuentan como OK.[/yellow]")
    if not bad and not errs:
        console.print("[green]Todas las listas curadas coinciden con su fuente.[/green]")
    if args.fail_on_drift and (bad or errs):
        sys.exit(1)



def _build_api_auth(token, atype, header_name):
    if not token:
        return {}
    if atype == "bearer":
        return {"Authorization": f"Bearer {token}"}
    if atype == "basic":
        import base64
        user_pass = token if ":" in token else f"{token}:"
        return {"Authorization": f"Basic {base64.b64encode(user_pass.encode()).decode()}"}
    return {(header_name or "X-API-Key"): token}


def _resolve_oauth2_token(args) -> str | None:
    """Si se dieron --oauth2-token-url/--oauth2-client-id/--oauth2-client-secret, resuelve un
    access_token real vía el grant client_credentials y lo devuelve (para usarlo como Bearer).
    None si no se configuró OAuth2 -- ahí el camino normal (--auth-token/--auth-type) sigue
    exactamente como antes."""
    token_url = getattr(args, "oauth2_token_url", None)
    if not token_url:
        return None
    client_id = getattr(args, "oauth2_client_id", None)
    client_secret = getattr(args, "oauth2_client_secret", None)
    if not client_id or not client_secret:
        console.print("[red]--oauth2-token-url requiere --oauth2-client-id y --oauth2-client-secret[/red]")
        sys.exit(1)
    from engine.core.oauth import fetch_client_credentials_token
    try:
        token = fetch_client_credentials_token(
            token_url, client_id, client_secret, scope=getattr(args, "oauth2_scope", None),
        )
    except RuntimeError as e:
        console.print(f"[red]{e}[/red]")
        sys.exit(1)
    console.print("[green]Token OAuth2 (client_credentials) obtenido correctamente.[/green]")
    return token


def cmd_api_scan(args):
    from engine.api.runner import run_api_scan
    headers = _parse_headers(args.header)
    oauth2_token = _resolve_oauth2_token(args)
    auth_a = {"Authorization": f"Bearer {oauth2_token}"} if oauth2_token else \
        _build_api_auth(args.auth_token, args.auth_type, args.auth_header_name)
    auth_b = _build_api_auth(args.auth_token_b, args.auth_type_b, args.auth_header_name_b)
    selected = [t for t in args.tests.split(",") if t] if args.tests else []
    if getattr(args, "all_tests", False) and not selected:
        # equivalente de 'vet' del lado MCP: corre TODOS los tests registrados (incluidos
        # opt-in como api.bola/api.mass_assignment/api.injection_probe/api.rate_limit,
        # gql.alias_batching/gql.depth_limit), sin el filtro default_enabled de api-scan normal.
        from engine.api.registry import all_api_tests
        selected = list(all_api_tests())
    elif args.max_level and not selected:
        from engine.api.registry import all_api_tests
        reg = all_api_tests()
        selected = [tid for tid, (meta, _) in reg.items() if meta.default_enabled and meta.level <= args.max_level]
    verify = resolve_ca_bundle(args.ca_bundle) if getattr(args, "ca_bundle", None) else True
    # --trust-presented-cert: mismo pinning TOFU que 'scan'/'vet'/'full' (ver
    # engine/orchestrator.py) -- sin esto, api-scan no tenía forma de auditar una API con
    # cert self-signed/CA interna sin pasar --ca-bundle.
    pinned_cert_file = None
    cert_pin_note = None
    if getattr(args, "trust_presented_cert", False) and verify is True and args.url.startswith("https://"):
        pinned_cert_file = fetch_presented_cert_pem(args.url)
        if pinned_cert_file:
            verify = pinned_cert_file
            cert_pin_note = (
                "--trust-presented-cert: se fijó (pinning TOFU) el certificado que presentó el server "
                "para poder conectarse y auditar. Esto NO valida su identidad contra una CA de confianza "
                "-- si ya había un MITM, se fijó el cert del atacante."
            )
        else:
            cert_pin_note = "--trust-presented-cert: no se pudo obtener el certificado presentado por el server."
    console.print(f"[cyan]Auditando API en {args.url} ...[/cyan]")
    try:
        report = asyncio.run(run_api_scan(
            base_url=args.url, spec_source=args.spec, selected_tests=selected or None, headers=headers,
            auth_a=auth_a or None, auth_b=auth_b or None, jwt=args.jwt or args.auth_token, verify=verify,
            delay_ms=args.request_delay_ms, max_fuzz=args.max_fuzz_cases, test_timeout_s=args.test_timeout_s,
            graphql_path=args.graphql_path, allowlist_path=_resolve_allowlist(args),
            min_confidence=args.min_confidence, environment=args.environment,
            proxy=getattr(args, "proxy", None), client_cert=getattr(args, "client_cert", None),
            client_key=getattr(args, "client_key", None),
        ))
    finally:
        if pinned_cert_file:
            try:
                os.unlink(pinned_cert_file)
            except OSError:
                pass
    if cert_pin_note:
        report.errors.append(cert_pin_note)
    _emit_report(report, args, args.out, args.sarif_out)


def _parse_headers(raw: list[str]) -> dict:
    headers = {}
    for h in raw or []:
        if ":" not in h:
            continue
        k, v = h.split(":", 1)
        headers[k.strip()] = v.strip()
    return headers


def _build_auth(args) -> AuthConfig | None:
    oauth2_token = _resolve_oauth2_token(args)
    if oauth2_token:
        return AuthConfig(type="bearer", token=oauth2_token)
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
    max_level = getattr(args, "max_level", None)
    if max_level and not selected:
        # sin --tests explícito: en vez de dejar selected_tests vacío (que el orquestador
        # expande a TODOS los default_enabled sin mirar nivel), armamos la lista a mano
        # como "default_enabled AND nivel <= N" -- --max-level nunca agrega opt-in, solo
        # recorta. Si el usuario puso --tests a mano, esa elección explícita gana entera
        # (ver help de --max-level): no filtramos esa lista por nivel.
        allowed = set(ids_at_or_below_level(max_level))
        selected = [tid for tid, (meta, _) in all_tests().items() if meta.default_enabled and tid in allowed]
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
        proxy=getattr(args, "proxy", None),
        client_cert=getattr(args, "client_cert", None),
        client_key=getattr(args, "client_key", None),
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
        sandbox_mem_mb=getattr(args, "sandbox_mem_mb", None) or DEFAULT_SANDBOX_MEM_MB,
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

    vet_test_ids = sorted(all_tests().keys())
    if getattr(args, "max_level", None):
        vet_test_ids = [t for t in vet_test_ids if t in set(ids_at_or_below_level(args.max_level))]

    full_args = argparse.Namespace(
        transport=args.transport, command=args.command, args=args.args, url=args.url,
        name=args.name, tests=",".join(vet_test_ids),
        out=args.out, sarif_out=args.sarif_out or (args.out.rsplit(".", 1)[0] + ".sarif"),
        baseline=args.baseline, max_fuzz_cases=args.max_fuzz_cases,
        allow_network=True, request_delay_ms=args.request_delay_ms,
        oob_callback_host=args.oob_callback_host, environment="production",
        source_path=args.source_path, ca_bundle=getattr(args, "ca_bundle", None),
        trust_presented_cert=getattr(args, "trust_presented_cert", False), header=args.header,
        proxy=getattr(args, "proxy", None), client_cert=getattr(args, "client_cert", None),
        client_key=getattr(args, "client_key", None),
        # resuelto UNA sola vez acá (no se reenvían oauth2_token_url/client_id/secret) -- evita
        # pedir un token nuevo por segunda vez más abajo en _build_config/_build_auth.
        auth_token=_resolve_oauth2_token(args) or args.auth_token,
        auth_type="bearer" if getattr(args, "oauth2_token_url", None) else args.auth_type,
        auth_header_name=args.auth_header_name,
        compare_auth=bool(args.auth_token) or bool(getattr(args, "oauth2_token_url", None)),
        print_findings=args.print_findings, no_file=args.no_file,
        allowlist=args.allowlist, min_confidence=args.min_confidence,
        live_agent_provider=args.live_agent_provider,
        webhook_on_regression=args.webhook_on_regression,
        package_name=args.package_name, test_timeout_s=args.test_timeout_s,
        verbose=args.verbose,
        no_sandbox=getattr(args, "no_sandbox", False),
        sandbox_mem_mb=getattr(args, "sandbox_mem_mb", DEFAULT_SANDBOX_MEM_MB),
        sandbox_cpu_s=getattr(args, "sandbox_cpu_s", 120),
        sandbox_nproc=getattr(args, "sandbox_nproc", None),
        sandbox_nofile=getattr(args, "sandbox_nofile", 256),
        max_consecutive_timeouts=getattr(args, "max_consecutive_timeouts", 3),
        max_text_for_analysis=getattr(args, "max_text_for_analysis", None),
        max_response_content=getattr(args, "max_response_content", None),
        no_session_reset=getattr(args, "no_session_reset", False),
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

        max_level = getattr(args, "max_level", None)
        if mode == "scan":
            if max_level:
                allowed = set(ids_at_or_below_level(max_level))
                selected = [tid for tid, (meta, _) in all_tests().items() if meta.default_enabled and tid in allowed]
            else:
                selected = []
        else:
            selected = sorted(all_tests().keys())
            if max_level:
                allowed = set(ids_at_or_below_level(max_level))
                selected = [t for t in selected if t in allowed]
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
            proxy=getattr(args, "proxy", None),
            client_cert=getattr(args, "client_cert", None),
            client_key=getattr(args, "client_key", None),
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


def cmd_netrecon(args):
    """Reconocimiento de red activo (httpx + subfinder + nuclei + katana)."""
    from engine.netrecon.runner import run_netrecon_scan

    selected = [t for t in args.tests.split(",") if t] if args.tests else None
    severities = [s.strip() for s in args.nuclei_severity.split(",") if s.strip()] \
        if args.nuclei_severity else None
    scope = [s.strip() for s in args.scope.split(",") if s.strip()] \
        if args.scope else None

    console.print(f"[cyan]Reconocimiento de red — {args.target}[/cyan]")
    if scope:
        console.print(f"[dim]Scope: {', '.join(scope)}[/dim]")
    console.print("[bold yellow]Aviso:[/bold yellow] este comando envía tráfico real al target. "
                  "Confirmá que tenés autorización para escanearlo.")

    def _netrecon_progress(event: dict) -> None:
        etype = event.get("type", "")
        if etype == "test_started":
            console.print(f"  [dim]▶ {event['test_id']} — {event.get('name','')}[/dim]")
        elif etype == "test_finished":
            n = event.get("findings_count", 0)
            c = event.get("confirmed", 0)
            console.print(f"  [dim]✓ {event['test_id']}: {n} findings ({c} confirmados)[/dim]")
        elif etype == "test_error":
            console.print(f"  [red]✗ {event['test_id']}: {event.get('error','')}[/red]")
        elif etype == "noise_reduction":
            console.print(f"  [dim]· ruido suprimido: {event.get('allowlisted',0)} allowlist, "
                          f"{event.get('below_confidence_floor',0)} confidence[/dim]")
        elif etype == "log":
            console.print(f"  [dim]{event.get('message','')}[/dim]")

    report = asyncio.run(run_netrecon_scan(
        target_url=args.target,
        scope=scope,
        selected_tests=selected,
        nuclei_severity=severities,
        timeout_s=args.timeout_s,
        rate_limit=args.rate_limit,
        min_confidence=args.min_confidence,
        environment=args.environment,
        allowlist_path=getattr(args, "allowlist", None),
        progress_cb=_netrecon_progress,
    ))

    _emit_report(report, args, args.out, args.sarif_out)


def cmd_install_tools(args):
    """Descarga y verifica las herramientas de red (nuclei/httpx/subfinder/katana/ffuf/dalfox)."""
    from engine.tools.installer import install_all, TOOL_VERSIONS, ALL_TOOLS
    from engine.tools.paths import tools_dir

    tools = [t.strip() for t in args.tools.split(",") if t.strip()] if args.tools else None
    targets = tools or ALL_TOOLS

    console.print(f"[cyan]Instalando herramientas de red en {tools_dir()}[/cyan]")
    for name in targets:
        ver = TOOL_VERSIONS.get(name, "?")
        console.print(f"  [dim]{name} v{ver}[/dim]")

    errors = install_all(
        tools=tools,
        force=args.force,
        progress=lambda msg: console.print(msg),
    )

    if errors:
        console.print("\n[bold red]Errores:[/bold red]")
        for name, err in errors.items():
            console.print(f"  [red]✗ {name}:[/red] {err}")
        raise SystemExit(1)

    console.print(f"\n[green]✓ Herramientas instaladas en {tools_dir()}[/green]")
    console.print("[dim]Verificá con: ares netrecon-list-tests[/dim]")


def cmd_netrecon_list_tests(args):
    """Lista los tests de reconocimiento de red disponibles."""
    from engine.netrecon.registry import list_net_meta
    import engine.netrecon.tests  # noqa: F401 — fuerza el registro
    table = Table(title="Tests de reconocimiento de red")
    table.add_column("ID"); table.add_column("Nivel"); table.add_column("Nombre"); table.add_column("Descripción", overflow="fold")
    for meta in list_net_meta():
        table.add_row(meta.id, str(meta.level), meta.name, meta.description)
    console.print(table)


def cmd_mcp_server(args):
    """Arranca Ares como servidor MCP."""
    from engine.mcp_server import mcp
    transport = getattr(args, "transport", "stdio")
    if transport == "stdio":
        console.print("[dim]Iniciando Ares MCP server (stdio)…[/dim]")
        mcp.run(transport="stdio")
    else:
        host = getattr(args, "host", "127.0.0.1")
        port = getattr(args, "port", 8766)
        console.print(f"[dim]Iniciando Ares MCP server ({transport}) en {host}:{port}…[/dim]")
        mcp.run(transport=transport, host=host, port=port)


def cmd_schedule_list(args):
    """Lista schedules configurados."""
    from engine.scheduler.scheduler import ScanScheduler
    from dataclasses import asdict
    sched = ScanScheduler("reports")
    entries = sched.list_all()
    if not entries:
        console.print("[dim]Sin schedules configurados.[/dim]")
        return
    for e in entries:
        status = "[green]habilitado[/green]" if e.enabled else "[dim]deshabilitado[/dim]"
        console.print(f"  [cyan]{e.id}[/cyan] {e.cron} {e.scan_type} → {e.params.get('target_url','?')} {status}")
        console.print(f"    runs={e.run_count} errors={e.error_count} next={e.next_run}")


def cmd_schedule_add(args):
    """Agrega un schedule nuevo."""
    from engine.scheduler.scheduler import ScanScheduler, ScheduleEntry
    import uuid as _uuid
    sched = ScanScheduler("reports")
    scope_list = [s.strip() for s in args.scope.split(",") if s.strip()] if getattr(args, "scope", None) else None
    params = {"target_url": args.target}
    if scope_list:
        params["scope"] = scope_list
    if getattr(args, "goal", None):
        params["goal"] = args.goal
    if getattr(args, "provider", None) and args.provider != "auto":
        params["provider"] = args.provider
    if getattr(args, "model", None):
        params["model"] = args.model
    entry = ScheduleEntry(
        id=getattr(args, "schedule_id", None) or _uuid.uuid4().hex[:8],
        cron=args.cron,
        scan_type=args.scan_type,
        params=params,
        notify_webhook=getattr(args, "notify_webhook", None),
    )
    result = sched.add(entry)
    console.print(f"[green]Schedule creado:[/green] {result.id} — próximo run: {result.next_run}")


def cmd_schedule_delete(args):
    """Elimina un schedule."""
    from engine.scheduler.scheduler import ScanScheduler
    sched = ScanScheduler("reports")
    ok = sched.delete(args.schedule_id)
    if ok:
        console.print(f"[green]Schedule eliminado:[/green] {args.schedule_id}")
    else:
        console.print(f"[red]Schedule no encontrado:[/red] {args.schedule_id}")


def cmd_schedule_daemon(args):
    """Corre el daemon de schedules en foreground."""
    from engine.scheduler.scheduler import ScanScheduler
    sched = ScanScheduler("reports")
    console.print("[cyan]Scheduler daemon iniciado[/cyan] — Ctrl+C para detener")
    entries = sched.list_all()
    enabled = [e for e in entries if e.enabled]
    console.print(f"[dim]{len(enabled)} schedules habilitados[/dim]")
    for e in enabled:
        console.print(f"  [dim]{e.id}  {e.cron}  {e.scan_type}  {e.params.get('target_url','?')}[/dim]")
    asyncio.run(sched.run_forever())


def cmd_custom_tool_default(args):
    console.print("[yellow]Uso:[/yellow] ares custom-tool <subcomando>")
    console.print("  list            — lista custom tools definidos")
    console.print("  add             — agrega un custom tool (interactivo)")
    console.print("  delete <id>     — elimina un custom tool")
    console.print("  test <id>       — ejecuta un custom tool con params opcionales")
    console.print("\nEjemplo:")
    console.print('  ares custom-tool add --name my-curl --type bash --cmd "curl -s {{url}}"')


def cmd_custom_tool_list(args):
    from engine.tools.custom import CustomToolStore
    store = CustomToolStore()
    tools = store.list_all()
    if not tools:
        console.print("[dim]Sin custom tools definidos.[/dim]")
        return
    from rich.table import Table
    t = Table(show_header=True, header_style="bold cyan")
    t.add_column("ID", style="dim", width=10)
    t.add_column("Nombre")
    t.add_column("Tipo")
    t.add_column("Descripción")
    t.add_column("Activo", justify="center")
    for tool in tools:
        t.add_row(
            tool.id,
            tool.name,
            tool.tool_type.value,
            tool.description[:60],
            "✓" if tool.enabled else "✗",
        )
    console.print(t)


def cmd_custom_tool_add(args):
    from engine.tools.custom import CustomTool, CustomToolStore, CustomToolType
    try:
        tool_type = CustomToolType(args.tool_type)
    except ValueError:
        console.print(f"[red]Tipo inválido: {args.tool_type}. Usa: http, command, bash[/red]")
        return
    tool = CustomTool(
        name=args.name,
        description=args.description or "",
        tool_type=tool_type,
        command_template=args.cmd or "",
        url_template=args.url or "",
        method=args.method or "GET",
        timeout_s=args.timeout_s,
    )
    store = CustomToolStore()
    try:
        created = store.add(tool)
        console.print(f"[green]Custom tool creado:[/green] {created.id} — {created.name}")
    except ValueError as e:
        console.print(f"[red]{e}[/red]")


def cmd_custom_tool_delete(args):
    from engine.tools.custom import CustomToolStore
    store = CustomToolStore()
    ok = store.delete(args.tool_id)
    if ok:
        console.print(f"[green]Eliminado:[/green] {args.tool_id}")
    else:
        console.print(f"[red]Tool no encontrado:[/red] {args.tool_id}")


def cmd_custom_tool_test(args):
    import asyncio
    from engine.tools.custom import CustomToolStore
    store = CustomToolStore()
    tool = store.get(args.tool_id)
    if tool is None:
        console.print(f"[red]Tool no encontrado:[/red] {args.tool_id}")
        return
    # Parse --param key=value pairs
    params: dict = {}
    for p in (args.params or []):
        if "=" in p:
            k, v = p.split("=", 1)
            params[k.strip()] = v.strip()
    console.print(f"[cyan]Ejecutando:[/cyan] {tool.name} ({tool.tool_type.value})")
    output = asyncio.run(store.execute(args.tool_id, params))
    console.print(output)


def cmd_schedule_default(args):
    """Handler por defecto cuando se escribe 'ares schedule' sin subcomando."""
    console.print("[yellow]Uso:[/yellow] ares schedule <subcomando>")
    console.print("  list        — lista schedules configurados")
    console.print("  add         — agrega un schedule nuevo")
    console.print("  delete <id> — elimina un schedule")
    console.print("  run-daemon  — corre el daemon en foreground")
    console.print("\nEjemplo:")
    console.print('  ares schedule add --cron "0 2 * * *" --type netrecon --target https://example.com')


def cmd_agent_scan(args):
    """Scan de red autónomo dirigido por LLM. El agente Claude decide iterativamente
    qué tests correr basándose en hallazgos acumulados."""
    try:
        from engine.agent.orchestrator import run_agent_scan
    except ImportError as e:
        console.print(f"[red]{e}[/red]")
        sys.exit(1)

    scope = [s.strip() for s in args.scope.split(",") if s.strip()] if args.scope else None
    denylist = [s.strip() for s in args.denylist.split(",") if s.strip()] if getattr(args, "denylist", None) else None

    provider_info = args.provider if args.provider != "auto" else "auto (detecta keys del entorno)"
    model_info = args.model or f"(default del provider {args.provider})"
    console.print(f"[cyan]Agent scan autónomo — {args.target}[/cyan]")
    console.print(f"[dim]Provider: {provider_info} · Modelo: {model_info} · Max rondas: {args.max_rounds}[/dim]")
    if scope:
        console.print(f"[dim]Scope: {', '.join(scope)}[/dim]")
    if args.goal:
        console.print(f"[dim]Objetivo: {args.goal}[/dim]")
    if args.allow_level3:
        console.print("[bold yellow]Aviso:[/bold yellow] tests nivel 3 habilitados (sqlmap SQLi — intrusivo)")
    console.print("[bold yellow]Aviso:[/bold yellow] este comando envía tráfico real al target y llama a la API de Claude. "
                  "Confirmá que tenés autorización y ANTHROPIC_API_KEY configurado.")

    def _agent_progress(event: dict) -> None:
        etype = event.get("type", "")
        if etype == "agent_round":
            console.print(f"\n[bold cyan]— Ronda {event['round']}/{event['max_rounds']} —[/bold cyan]")
        elif etype == "agent_thinking":
            console.print(f"  [cyan]🤔 {event['title']}[/cyan]")
            if event.get("content"):
                excerpt = event["content"][:200]
                console.print(f"  [dim]{excerpt}{'…' if len(event['content']) > 200 else ''}[/dim]")
        elif etype == "agent_tool_call":
            console.print(f"  [dim]→ ejecutando {event['test_id']}…[/dim]")
        elif etype == "agent_finished":
            posture = event.get("security_posture", "")
            console.print(f"\n[green]✓ Análisis final:[/green] {posture[:300]}{'…' if len(posture) > 300 else ''}")
        elif etype == "gate_denied":
            console.print(f"  [yellow]⛔ gate denegó {event['test_id']}: {event['reason']}[/yellow]")
        elif etype == "agent_error":
            console.print(f"  [red]ERROR del agente: {event['error']}[/red]")
        elif etype == "test_started":
            console.print(f"  [dim]▶ {event['test_id']} — {event.get('name','')}[/dim]")
        elif etype == "test_finished":
            n, c = event.get("findings_count", 0), event.get("confirmed", 0)
            console.print(f"  [dim]✓ {event['test_id']}: {n} findings ({c} confirmados)[/dim]")
        elif etype == "test_error":
            console.print(f"  [red]✗ {event['test_id']}: {event.get('error','')}[/red]")
        elif etype == "noise_reduction":
            console.print(f"  [dim]· ruido suprimido: {event.get('allowlisted',0)} allowlist, "
                          f"{event.get('below_confidence_floor',0)} confidence[/dim]")

    if getattr(args, "v2", False):
        from engine.agent.orchestrator_v2 import run_agent_scan_v2
        report = asyncio.run(run_agent_scan_v2(
            target_url=args.target,
            scope=scope,
            goal=getattr(args, "goal", None),
            provider=args.provider,
            model=args.model or None,
            timeout_s=args.timeout_s,
            rate_limit=args.rate_limit,
            min_confidence=args.min_confidence,
            environment=args.environment,
            allow_level3=args.allow_level3,
            denylist=denylist,
            allowlist_path=getattr(args, "allowlist", None),
            progress_cb=_agent_progress,
        ))
    else:
        report = asyncio.run(run_agent_scan(
            target_url=args.target,
            scope=scope,
            goal=getattr(args, "goal", None),
            provider=args.provider,
            model=args.model or None,
            max_rounds=args.max_rounds,
            timeout_s=args.timeout_s,
            rate_limit=args.rate_limit,
            min_confidence=args.min_confidence,
            environment=args.environment,
            allow_level3=args.allow_level3,
            denylist=denylist,
            allowlist_path=getattr(args, "allowlist", None),
            progress_cb=_agent_progress,
        ))

    _emit_report(report, args, args.out, args.sarif_out)


def cmd_tools_status(args):
    """Estado de cada herramienta de red: instalada, versión pinneada, path."""
    from engine.tools.paths import tools_status
    from engine.tools.installer import TOOL_VERSIONS
    table = Table(title="Estado de herramientas de red")
    table.add_column("Herramienta"); table.add_column("Disponible"); table.add_column("Versión pinneada"); table.add_column("Fuente"); table.add_column("Path")
    for name, info in tools_status().items():
        ok = "[green]✓[/green]" if info["available"] else "[red]✗[/red]"
        table.add_row(name, ok, info["pinned_version"], info["source"], info["path"] or "-")
    console.print(table)


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
    p_list.add_argument("--max-level", dest="max_level", type=int, choices=[1, 2, 3, 4], default=None,
                         help="solo lista tests con nivel <= N (1 Básico .. 4 Crítico)")
    p_list.set_defaults(func=cmd_list_tests)

    p_api_list = sub.add_parser("api-list-tests", help="lista los tests de API (REST + GraphQL) disponibles")
    p_api_list.set_defaults(func=cmd_api_list_tests)

    p_discover = sub.add_parser("discover", help="Descubre servers MCP configurados localmente (Claude Desktop, Cursor, etc.)")
    p_discover.set_defaults(func=cmd_discover)

    p_rules = sub.add_parser("update-rules", help="Refresca el cache local de patrones de secretos desde gitleaks.toml (público, sin API key)")
    p_rules.set_defaults(func=cmd_update_rules)

    p_frameworks = sub.add_parser("check-frameworks", help="Avisa si OWASP MCP/LLM/API Top 10 o MITRE ATLAS cambiaron de versión -- nunca actualiza nada solo")
    p_frameworks.add_argument("--ack", action="store_true", help="acepta el estado actual como nuevo baseline (deja de avisar sobre este cambio puntual)")
    p_frameworks.add_argument("--fail-if-stale", dest="fail_if_stale", type=float, default=None, help="para CI: exit code 1 si el baseline más viejo tiene más de N días, o si no hay baseline, o si hay un cambio sin revisar. Sin esta flag, el comando siempre sale 0 (uso interactivo normal)")
    p_frameworks.add_argument("--verify", action="store_true", help="además de detectar cambios, verifica que CADA código citado en frameworks.py (MCP/LLM/ATLAS) exista en su fuente primaria -- detecta renumeraciones/retiros (ej. LLM Top 10 2025->2026)")
    p_frameworks.set_defaults(func=cmd_check_frameworks)

    p_lists = sub.add_parser("check-lists", help="verifica las listas curadas (feed de CVEs, paquetes legítimos, patrones de secretos) contra sus fuentes públicas (OSV.dev, repo oficial de servers MCP, gitleaks)")
    p_lists.add_argument("--fail-on-drift", dest="fail_on_drift", action="store_true", help="para CI: exit code 1 si alguna lista está vencida, desfasada o le faltan entradas")
    p_lists.set_defaults(func=cmd_check_lists)

    p_serve = sub.add_parser("serve", help="Levanta el dashboard web (FastAPI + WebSocket) en localhost")
    p_serve.add_argument("--host", default="127.0.0.1")
    p_serve.add_argument("--port", type=int, default=8000)
    p_serve.add_argument("--token", default=None, help="exige este token (header X-Ares-Token o ?token=) en toda request al dashboard. También se puede setear via ARES_DASHBOARD_TOKEN")
    p_serve.set_defaults(func=cmd_serve)

    p_scan = sub.add_parser("scan")
    p_scan.add_argument("--transport", choices=["stdio", "sse", "http"], default="stdio", help="nota: con sse, los tests de fuzzing de protocolo crudo (protocol.jsonrpc_malformed_fuzz y similares) no corren -- el canal RPC crudo (engine/protocol/rawrpc.py) solo soporta stdio/http")
    p_scan.add_argument("--command", default=None, help="comando para lanzar el server MCP (stdio), ej: python")
    p_scan.add_argument("--args", default="", help="argumentos del comando, ej: 'target_server.py'")
    p_scan.add_argument("--url", default=None, help="URL del server MCP (transporte sse/http)")
    p_scan.add_argument("--config", default=None, help="ruta a un config estilo Claude Desktop; escanea todos sus mcpServers en batch")
    p_scan.add_argument("--name", default=None)
    p_scan.add_argument("--tests", default="", help="lista de test ids separados por coma; vacío = todos los default")
    p_scan.add_argument("--max-level", dest="max_level", type=int, choices=[1, 2, 3, 4], default=None,
                         help="solo corre tests con nivel <= N (1 Básico, 2 Intermedio, 3 Avanzado, 4 Crítico -- "
                              "ver 'list-tests'). Se combina con --tests; si --tests viene explícito, ese ID "
                              "corre igual aunque supere --max-level (elección explícita gana).")
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
    p_scan.add_argument("--proxy", default=None, help="proxy HTTP/HTTPS/SOCKS para TODO el tráfico hacia el target http/sse, ej: http://127.0.0.1:8080 (para interceptar con Burp/mitmproxy) o socks5://host:1080 (SOCKS requiere 'pip install httpx[socks]' -- falla con un error claro de httpx si falta)")
    p_scan.add_argument("--client-cert", dest="client_cert", default=None, help="ruta a un certificado de cliente (PEM) para mTLS -- el server exige que ARES mismo se autentique con un cert, no solo que valide el del server (eso es --ca-bundle)")
    p_scan.add_argument("--client-key", dest="client_key", default=None, help="clave privada (PEM) de --client-cert, si no está en el mismo archivo")
    p_scan.add_argument("--trust-presented-cert", dest="trust_presented_cert", action="store_true", help="http/sse: si la conexión falla por TLS no confiable (self-signed/CA desconocida) y no diste --ca-bundle, trae el certificado que presenta el server y lo FIJA (pinning TOFU) para conectarse y correr las pruebas igual. NO valida identidad (el cert se sigue reportando self-signed/riesgo) -- es para auditar un target interno sin frenar")
    p_scan.add_argument("--header", action="append", default=[], help='header HTTP extra "Clave: Valor" (repetible, transporte sse/http)')
    p_scan.add_argument("--auth-token", dest="auth_token", default=None, help="credencial a inyectar (transporte sse/http). Para --auth-type basic: 'usuario:contraseña'. Ver también --oauth2-token-url para resolver un access_token OAuth2 client-credentials en vez de pasarlo a mano")
    p_scan.add_argument("--auth-type", dest="auth_type", choices=["bearer", "apikey", "custom", "basic"], default="bearer")
    p_scan.add_argument("--auth-header-name", dest="auth_header_name", default=None, help="nombre del header para auth-type apikey/custom, ej: X-API-Key")
    p_scan.add_argument("--oauth2-token-url", dest="oauth2_token_url", default=None, help="si se da, resuelve un access_token real vía OAuth2 client_credentials contra este token endpoint y lo usa como Bearer -- ignora --auth-token/--auth-type si están dados. Requiere --oauth2-client-id y --oauth2-client-secret")
    p_scan.add_argument("--oauth2-client-id", dest="oauth2_client_id", default=None)
    p_scan.add_argument("--oauth2-client-secret", dest="oauth2_client_secret", default=None)
    p_scan.add_argument("--oauth2-scope", dest="oauth2_scope", default=None, help="scope opcional a pedir en el token OAuth2")
    p_scan.add_argument("--auth-token-b", dest="auth_token_b", default=None, help="SEGUNDA credencial/tenant válido contra el mismo server, para auth.cross_session_context_bleed (fuga de contexto entre sesiones -- MCP10:2025). Independiente de --auth-token")
    p_scan.add_argument("--auth-type-b", dest="auth_type_b", choices=["bearer", "apikey", "custom", "basic"], default="bearer")
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
    p_scan.add_argument("--sandbox-mem-mb", dest="sandbox_mem_mb", type=int, default=DEFAULT_SANDBOX_MEM_MB,
                         help=f"tope de memoria VIRTUAL (MB) del proceso del target vía prlimit --as (default "
                              f"{DEFAULT_SANDBOX_MEM_MB}; un runtime JIT/managed -- Node/V8, JVM, .NET -- reserva "
                              f"mucha más memoria virtual que la que usa de verdad al arrancar, así que un valor "
                              f"chico corta la conexión con TODO server en esos runtimes, no solo a un ataque real)")
    p_scan.add_argument("--sandbox-cpu-s", dest="sandbox_cpu_s", type=int, default=120, help="tope de tiempo de CPU (segundos) del proceso del target vía prlimit (default 120)")
    p_scan.add_argument("--sandbox-nproc", dest="sandbox_nproc", type=int, default=None, help="tope de procesos/threads del target vía prlimit -- bloquea fork bombs. Default: calculado dinámicamente (lo que ya tiene el usuario corriendo + margen), nunca un número absoluto fijo")
    p_scan.add_argument("--sandbox-nofile", dest="sandbox_nofile", type=int, default=256, help="tope de file descriptors abiertos del target vía prlimit (default 256)")
    p_scan.add_argument("--max-text-for-analysis", dest="max_text_for_analysis", type=int, default=None, help="override del cap de chars analizados con regex (descripciones/schemas) -- default engine.core.limits.MAX_TEXT_FOR_ANALYSIS (200000)")
    p_scan.add_argument("--max-response-content", dest="max_response_content", type=int, default=None, help="override del cap de chars de una respuesta de call_tool/read_resource -- default engine.core.limits.MAX_RESPONSE_CONTENT (2000000)")
    p_scan.add_argument("--no-session-reset", dest="no_session_reset", action="store_true", help="no cerrar/reabrir la sesión tras un timeout -- por default sí se reconecta, para no arrastrar estado envenenado ni dejar el subprocess viejo vivo")
    p_scan.add_argument("--verbose", action="store_true", help="imprime cada llamada real (list_tools/call_tool/read_resource) en vivo, con request/response truncados -- no solo el resumen por test")
    p_scan.add_argument("--webhook-on-regression", dest="webhook_on_regression", default=None, help="requiere --baseline: si aparecen hallazgos NUEVOS respecto al baseline, hace UN POST JSON a esta URL (nunca si no hay regresión). Para correr esto en un cron/systemd timer del SO -- Ares no reinventa scheduling")
    p_scan.set_defaults(func=cmd_scan)

    p_api = sub.add_parser("api-scan", help="Audita una API REST/GraphQL (OWASP API Security Top 10) -- mismo motor de reporte/score/policy/SARIF que 'scan'")
    p_api.add_argument("--url", required=True, help="base URL de la API, ej: http://localhost:8888")
    p_api.add_argument("--spec", default=None, help="OpenAPI/Swagger/Postman: ruta local o URL. Sin esto, se intenta autodescubrir en rutas comunes (/openapi.json, /swagger.json...)")
    p_api.add_argument("--graphql-path", dest="graphql_path", default=None, help="path del endpoint GraphQL si no es uno de los comunes (/graphql, /api/graphql, /v1/graphql, /gql)")
    p_api.add_argument("--tests", default="", help="lista de test ids separados por coma; vacío = todos los default_enabled")
    p_api.add_argument("--max-level", dest="max_level", type=int, choices=[1, 2, 3, 4], default=None)
    p_api.add_argument("--all-tests", dest="all_tests", action="store_true",
                       help="corre TAMBIEN los tests opt-in (api.bola, api.mass_assignment, "
                            "api.injection_probe, api.rate_limit, gql.alias_batching, "
                            "gql.depth_limit) -- equivalente de 'vet' para el módulo de API, "
                            "pensado para el gate 'apto para mi operación', no para CI ruidoso")
    p_api.add_argument("--out", default="reporte_api.html")
    p_api.add_argument("--sarif-out", dest="sarif_out", default=None)
    p_api.add_argument("--header", action="append", default=[], help='header HTTP extra "Clave: Valor" (repetible)')
    p_api.add_argument("--auth-token", dest="auth_token", default=None, help="credencial principal (identidad A)")
    p_api.add_argument("--auth-type", dest="auth_type", choices=["bearer", "apikey", "custom", "basic"], default="bearer")
    p_api.add_argument("--auth-header-name", dest="auth_header_name", default=None)
    p_api.add_argument("--oauth2-token-url", dest="oauth2_token_url", default=None, help="resuelve un access_token real vía OAuth2 client_credentials en vez de pasar --auth-token a mano (ver 'scan --help')")
    p_api.add_argument("--oauth2-client-id", dest="oauth2_client_id", default=None)
    p_api.add_argument("--oauth2-client-secret", dest="oauth2_client_secret", default=None)
    p_api.add_argument("--oauth2-scope", dest="oauth2_scope", default=None)
    p_api.add_argument("--auth-token-b", dest="auth_token_b", default=None, help="SEGUNDA credencial/identidad, para api.bola (acceso cruzado con dos usuarios reales)")
    p_api.add_argument("--auth-type-b", dest="auth_type_b", choices=["bearer", "apikey", "custom", "basic"], default="bearer")
    p_api.add_argument("--auth-header-name-b", dest="auth_header_name_b", default=None)
    p_api.add_argument("--jwt", default=None, help="override: JWT a analizar en api.jwt, si es distinto de --auth-token")
    p_api.add_argument("--ca-bundle", dest="ca_bundle", default=None)
    p_api.add_argument("--proxy", default=None, help="proxy HTTP/HTTPS/SOCKS para toda la auditoría (ver 'scan --help')")
    p_api.add_argument("--client-cert", dest="client_cert", default=None, help="certificado de cliente (PEM) para mTLS (ver 'scan --help')")
    p_api.add_argument("--client-key", dest="client_key", default=None)
    p_api.add_argument("--trust-presented-cert", dest="trust_presented_cert", action="store_true", help="si el TLS de la API no valida (self-signed/CA desconocida) y no diste --ca-bundle, trae el certificado que presenta el server y lo FIJA (pinning TOFU) para conectarse y auditar igual. NO valida identidad (ver 'scan --help')")
    p_api.add_argument("--request-delay-ms", dest="request_delay_ms", type=int, default=0)
    p_api.add_argument("--max-fuzz-cases", dest="max_fuzz_cases", type=int, default=40)
    p_api.add_argument("--test-timeout-s", dest="test_timeout_s", type=float, default=60.0)
    p_api.add_argument("--environment", choices=["production", "development"], default="production")
    p_api.add_argument("--allowlist", default=None)
    p_api.add_argument("--min-confidence", dest="min_confidence", choices=["heuristic", "verified"], default="heuristic")
    p_api.add_argument("--print", dest="print_findings", action="store_true")
    p_api.add_argument("--no-file", dest="no_file", action="store_true")
    p_api.set_defaults(func=cmd_api_scan)

    p_vet = sub.add_parser("vet", help="Auditoría de máxima cobertura antes de implementar un MCP: corre TODOS los tests (incluidos opt-in), pensada para el gate de 'apto para mi operación'")
    p_vet.add_argument("--transport", choices=["stdio", "sse", "http"], default="stdio", help="nota: con sse, los tests de fuzzing de protocolo crudo (protocol.jsonrpc_malformed_fuzz y similares) no corren -- el canal RPC crudo (engine/protocol/rawrpc.py) solo soporta stdio/http")
    p_vet.add_argument("--command", default=None)
    p_vet.add_argument("--args", default="")
    p_vet.add_argument("--url", default=None)
    p_vet.add_argument("--name", default=None)
    p_vet.add_argument("--out", default="reporte_vet.html")
    p_vet.add_argument("--sarif-out", dest="sarif_out", default=None, help="default: mismo nombre que --out con extensión .sarif")
    p_vet.add_argument("--baseline", default=None)
    p_vet.add_argument("--max-fuzz-cases", type=int, default=50, help="más alto que 'scan' default -- esto es auditoría exhaustiva")
    p_vet.add_argument("--max-level", dest="max_level", type=int, choices=[1, 2, 3, 4], default=None,
                        help="por default vet corre TODOS los tests incluidos opt-in; con esto se limita a "
                             "nivel <= N (ej. --max-level 3 para excluir adv.live_agent_injection)")
    p_vet.add_argument("--request-delay-ms", dest="request_delay_ms", type=int, default=0)
    p_vet.add_argument("--oob-callback-host", dest="oob_callback_host", default=None)
    p_vet.add_argument("--source-path", dest="source_path", default=None, help="ruta al código fuente, para incluir el chequeo de dependencias vulnerables (OSV.dev)")
    p_vet.add_argument("--ca-bundle", dest="ca_bundle", default=None, help="ruta a un bundle de CA (PEM) para validar el TLS del server contra una CA interna (ver 'scan --help'); fallback SSL_CERT_FILE")
    p_vet.add_argument("--proxy", default=None, help="proxy HTTP/HTTPS/SOCKS para toda la auditoría (ver 'scan --help')")
    p_vet.add_argument("--client-cert", dest="client_cert", default=None, help="certificado de cliente (PEM) para mTLS (ver 'scan --help')")
    p_vet.add_argument("--client-key", dest="client_key", default=None)
    p_vet.add_argument("--trust-presented-cert", dest="trust_presented_cert", action="store_true", help="fija el cert presentado (pinning TOFU) para conectarse a un target con cert interno y auditarlo igual (ver 'scan --help')")
    p_vet.add_argument("--header", action="append", default=[])
    p_vet.add_argument("--auth-token", dest="auth_token", default=None, help="si lo das, corre compare-auth automáticamente")
    p_vet.add_argument("--auth-type", dest="auth_type", choices=["bearer", "apikey", "custom", "basic"], default="bearer")
    p_vet.add_argument("--auth-header-name", dest="auth_header_name", default=None)
    p_vet.add_argument("--oauth2-token-url", dest="oauth2_token_url", default=None, help="resuelve un access_token real vía OAuth2 client_credentials en vez de pasar --auth-token a mano (ver 'scan --help')")
    p_vet.add_argument("--oauth2-client-id", dest="oauth2_client_id", default=None)
    p_vet.add_argument("--oauth2-client-secret", dest="oauth2_client_secret", default=None)
    p_vet.add_argument("--oauth2-scope", dest="oauth2_scope", default=None)
    p_vet.add_argument("--print", dest="print_findings", action="store_true", help="además de los archivos, imprime en la terminal el detalle de cada hallazgo confirmado")
    p_vet.add_argument("--no-file", dest="no_file", action="store_true", help="no escribe reporte_vet.html/.json/.sarif -- solo termina en la terminal (implica --print)")
    p_vet.add_argument("--allowlist", default=None, help="ruta a un .ares_allowlist.yml; sin esto, se auto-detecta en el directorio actual")
    p_vet.add_argument("--min-confidence", dest="min_confidence", choices=["heuristic", "verified"], default="heuristic", help="'verified' sube el piso de qué gatea score/policy (ver 'scan --help')")
    p_vet.add_argument("--live-agent-provider", dest="live_agent_provider", choices=["auto", "anthropic", "openai", "ollama", "all"], default="auto", help="proveedor(es) para adv.live_agent_injection")
    p_vet.add_argument("--package-name", dest="package_name", default=None, help="nombre de paquete declarado (npm/pypi) para static.typosquatting_check")
    p_vet.add_argument("--test-timeout-s", dest="test_timeout_s", type=float, default=60.0, help="segundos máximos por test (default 60)")
    p_vet.add_argument("--verbose", action="store_true", help="imprime cada llamada real en vivo (ver 'scan --help')")
    p_vet.add_argument("--webhook-on-regression", dest="webhook_on_regression", default=None, help="requiere --baseline: UN POST JSON a esta URL solo si aparecen hallazgos NUEVOS (ver 'scan --help')")
    # Los flags de sandbox/recursos NO son sobre cobertura (eso vet ya lo fuerza al máximo) sino
    # sobre si el PROCESO del target arranca siquiera en este host -- confirmado contra un target
    # real con 200+ módulos: 256 FDs default no alcanza para cargarlos todos (EMFILE) y el default
    # de memoria no alcanza para la reserva de WASM de Node/undici (WebAssembly OOM). Antes 'vet'
    # no exponía ninguno de estos, así que un target legítimo pero pesado no tenía forma de pasar
    # por acá -- mismos flags que 'scan', mismo default.
    p_vet.add_argument("--no-sandbox", dest="no_sandbox", action="store_true", help="desactiva el aislamiento de proceso (prlimit) del subprocess stdio del target (ver 'scan --help')")
    p_vet.add_argument("--sandbox-mem-mb", dest="sandbox_mem_mb", type=int, default=DEFAULT_SANDBOX_MEM_MB, help="tope de memoria VIRTUAL (MB) del proceso del target vía prlimit --as (ver 'scan --help')")
    p_vet.add_argument("--sandbox-cpu-s", dest="sandbox_cpu_s", type=int, default=120, help="tope de tiempo de CPU (segundos) del proceso del target vía prlimit (default 120)")
    p_vet.add_argument("--sandbox-nproc", dest="sandbox_nproc", type=int, default=None, help="tope de procesos/threads del target vía prlimit (ver 'scan --help')")
    p_vet.add_argument("--sandbox-nofile", dest="sandbox_nofile", type=int, default=256, help="tope de file descriptors abiertos del target vía prlimit (default 256)")
    p_vet.add_argument("--max-consecutive-timeouts", dest="max_consecutive_timeouts", type=int, default=3, help="circuit breaker: tras N timeouts/excepciones seguidas, se saltea el resto de la batería de una (0 = sin límite)")
    p_vet.add_argument("--max-text-for-analysis", dest="max_text_for_analysis", type=int, default=None, help="override del cap de chars analizados con regex (ver 'scan --help')")
    p_vet.add_argument("--max-response-content", dest="max_response_content", type=int, default=None, help="override del cap de chars de una respuesta de call_tool/read_resource (ver 'scan --help')")
    p_vet.add_argument("--no-session-reset", dest="no_session_reset", action="store_true", help="no cerrar/reabrir la sesión tras un timeout (ver 'scan --help')")
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
    p_full.add_argument("--transport", choices=["stdio", "sse", "http"], default="stdio", help="solo si das --command/--url explícito (single target). nota: con sse, los tests de fuzzing de protocolo crudo (protocol.jsonrpc_malformed_fuzz y similares) no corren -- el canal RPC crudo (engine/protocol/rawrpc.py) solo soporta stdio/http")
    p_full.add_argument("--command", default=None, help="target único explícito (stdio), en vez de auto-discover")
    p_full.add_argument("--args", default="")
    p_full.add_argument("--url", default=None, help="target único explícito (http/sse), en vez de auto-discover")
    p_full.add_argument("--name", default=None)
    p_full.add_argument("--max-fuzz-cases", type=int, default=25)
    p_full.add_argument("--max-level", dest="max_level", type=int, choices=[1, 2, 3, 4], default=None,
                         help="limita los tests corridos (en ambos modos) a nivel <= N -- ver 'list-tests'")
    p_full.add_argument("--allow-network", action="store_true", help="ignorado en modo vet (ya lo fuerza); aplica solo a --mode scan")
    p_full.add_argument("--request-delay-ms", dest="request_delay_ms", type=int, default=0)
    p_full.add_argument("--oob-callback-host", dest="oob_callback_host", default=None)
    p_full.add_argument("--environment", choices=["production", "development"], default="production")
    p_full.add_argument("--source-path", dest="source_path", default=None)
    p_full.add_argument("--ca-bundle", dest="ca_bundle", default=None, help="ruta a un bundle de CA (PEM) para validar el TLS de TODOS los targets http/sse contra una CA interna; fallback SSL_CERT_FILE")
    p_full.add_argument("--proxy", default=None, help="proxy HTTP/HTTPS/SOCKS para toda la auditoría (ver 'scan --help')")
    p_full.add_argument("--client-cert", dest="client_cert", default=None, help="certificado de cliente (PEM) para mTLS (ver 'scan --help')")
    p_full.add_argument("--client-key", dest="client_key", default=None)
    p_full.add_argument("--trust-presented-cert", dest="trust_presented_cert", action="store_true", help="fija el cert presentado (pinning TOFU) de cada target http/sse para conectarse y auditar igual (ver 'scan --help')")
    p_full.add_argument("--header", action="append", default=[])
    p_full.add_argument("--auth-token", dest="auth_token", default=None)
    p_full.add_argument("--auth-type", dest="auth_type", choices=["bearer", "apikey", "custom", "basic"], default="bearer")
    p_full.add_argument("--auth-header-name", dest="auth_header_name", default=None)
    p_full.add_argument("--oauth2-token-url", dest="oauth2_token_url", default=None, help="resuelve un access_token real vía OAuth2 client_credentials en vez de pasar --auth-token a mano (ver 'scan --help')")
    p_full.add_argument("--oauth2-client-id", dest="oauth2_client_id", default=None)
    p_full.add_argument("--oauth2-client-secret", dest="oauth2_client_secret", default=None)
    p_full.add_argument("--oauth2-scope", dest="oauth2_scope", default=None)
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

    # ── netrecon ─────────────────────────────────────────────────────────────
    p_netrecon = sub.add_parser(
        "netrecon",
        help="Reconocimiento de red activo: HTTP probe, subdomain enum, nuclei scan, web crawl"
    )
    p_netrecon.add_argument("--target", required=True,
                             help="URL o dominio del objetivo, ej: https://example.com")
    p_netrecon.add_argument("--scope", default=None,
                             help="dominios en scope, separados por coma (ej: example.com,sub.example.com); "
                                  "sin esto, no se verifica scope (modo libre)")
    p_netrecon.add_argument("--tests", default="",
                             help="IDs de tests a correr separados por coma; vacío = todos "
                                  "(net.httpx_probe, net.subfinder, net.bbot_osint, net.katana_crawl, "
                                  "net.nuclei_scan, net.ffuf_fuzz, net.dalfox_xss, net.sqlmap_sqli)")
    p_netrecon.add_argument("--nuclei-severity", dest="nuclei_severity", default="critical,high,medium",
                             help="severidades nuclei a incluir, separadas por coma (default: critical,high,medium)")
    p_netrecon.add_argument("--timeout-s", dest="timeout_s", type=int, default=180,
                             help="timeout por test en segundos (default 180)")
    p_netrecon.add_argument("--rate-limit", dest="rate_limit", type=int, default=150,
                             help="peticiones/seg máximas hacia el target (default 150)")
    p_netrecon.add_argument("--out", default="reporte_netrecon.html")
    p_netrecon.add_argument("--sarif-out", dest="sarif_out", default=None)
    p_netrecon.add_argument("--environment", choices=["production", "development", "staging"], default="production")
    p_netrecon.add_argument("--min-confidence", dest="min_confidence",
                             choices=["heuristic", "verified"], default="heuristic")
    p_netrecon.add_argument("--allowlist", dest="allowlist", default=None,
                             help="ruta a .ares_allowlist.yml para suprimir findings conocidos")
    p_netrecon.add_argument("--print", dest="print_findings", action="store_true")
    p_netrecon.add_argument("--no-file", dest="no_file", action="store_true")
    p_netrecon.set_defaults(func=cmd_netrecon)

    # ── install-tools ─────────────────────────────────────────────────────────
    p_install = sub.add_parser(
        "install-tools",
        help="Descarga y verifica binarios de seguridad: nuclei, httpx, subfinder, katana, ffuf, dalfox"
    )
    p_install.add_argument("--tools", default=None,
                            help="herramientas a instalar, separadas por coma; "
                                 "vacío = todas (nuclei,httpx,subfinder,katana,ffuf,dalfox,sqlmap,bbot)")
    p_install.add_argument("--force", action="store_true",
                            help="reinstala aunque el binario ya exista")
    p_install.add_argument("--help-tools", dest="help_tools", action="store_true",
                            help="muestra las herramientas disponibles y sus versiones pinneadas")
    p_install.set_defaults(func=cmd_install_tools)

    # ── netrecon-list-tests ───────────────────────────────────────────────────
    p_nrl = sub.add_parser("netrecon-list-tests", help="Lista los tests de reconocimiento de red disponibles")
    p_nrl.set_defaults(func=cmd_netrecon_list_tests)

    # ── tools-status ─────────────────────────────────────────────────────────
    p_ts = sub.add_parser("tools-status", help="Estado de las herramientas de red (instalada/path/versión)")
    p_ts.set_defaults(func=cmd_tools_status)

    # ── mcp-server ────────────────────────────────────────────────────────────
    p_mcp_srv = sub.add_parser(
        "mcp-server",
        help="Arranca Ares como servidor MCP (expone ares_netrecon, ares_agent_scan, ares_list_reports, etc.)"
    )
    p_mcp_srv.add_argument("--transport", choices=["stdio", "http", "sse"], default="stdio",
                            help="transporte MCP (default: stdio)")
    p_mcp_srv.add_argument("--host", default="127.0.0.1")
    p_mcp_srv.add_argument("--port", type=int, default=8766)
    p_mcp_srv.set_defaults(func=cmd_mcp_server)

    # ── custom-tool ───────────────────────────────────────────────────────────
    p_ct = sub.add_parser("custom-tool", help="Gestión de custom tools definidos por el usuario")
    p_ct.set_defaults(func=cmd_custom_tool_default)
    ct_sub = p_ct.add_subparsers(dest="ct_action")

    ct_list = ct_sub.add_parser("list", help="Lista custom tools")
    ct_list.set_defaults(func=cmd_custom_tool_list)

    ct_add = ct_sub.add_parser("add", help="Agrega un custom tool")
    ct_add.add_argument("--name", required=True, help="Nombre único del tool")
    ct_add.add_argument("--description", default="", help="Descripción para el agente LLM")
    ct_add.add_argument("--type", dest="tool_type", choices=["http", "command", "bash"], default="command")
    ct_add.add_argument("--cmd", default=None, help="Plantilla de comando (usa {{param}} para sustitución)")
    ct_add.add_argument("--url", default=None, help="URL template (tipo http)")
    ct_add.add_argument("--method", default="GET", help="HTTP method (tipo http)")
    ct_add.add_argument("--timeout-s", dest="timeout_s", type=int, default=60)
    ct_add.set_defaults(func=cmd_custom_tool_add)

    ct_del = ct_sub.add_parser("delete", help="Elimina un custom tool")
    ct_del.add_argument("tool_id", help="ID del tool a eliminar")
    ct_del.set_defaults(func=cmd_custom_tool_delete)

    ct_test = ct_sub.add_parser("test", help="Prueba un custom tool")
    ct_test.add_argument("tool_id", help="ID del tool a ejecutar")
    ct_test.add_argument("params", nargs="*", metavar="key=value", help="Parámetros para el template")
    ct_test.set_defaults(func=cmd_custom_tool_test)

    # ── schedule ──────────────────────────────────────────────────────────────
    p_sched = sub.add_parser("schedule", help="Gestión de scans programados (cron-style)")
    p_sched.set_defaults(func=cmd_schedule_default)
    sched_sub = p_sched.add_subparsers(dest="schedule_action")

    p_sched_list = sched_sub.add_parser("list", help="Lista schedules configurados")
    p_sched_list.set_defaults(func=cmd_schedule_list)

    p_sched_add = sched_sub.add_parser("add", help="Agrega un schedule nuevo")
    p_sched_add.add_argument("--cron", required=True, help="Expresión cron de 5 campos (ej: '0 2 * * *')")
    p_sched_add.add_argument("--type", dest="scan_type",
                              choices=["scan", "api-scan", "netrecon", "agent-scan"], default="netrecon")
    p_sched_add.add_argument("--target", required=True)
    p_sched_add.add_argument("--scope", default=None)
    p_sched_add.add_argument("--id", dest="schedule_id", default=None)
    p_sched_add.add_argument("--goal", default=None)
    p_sched_add.add_argument("--provider", default="auto",
                              help="provider LLM: auto|anthropic|openai|deepseek|nvidia|mistral|groq|together|openrouter|gemini|xai|ollama|custom")
    p_sched_add.add_argument("--model", default=None,
                              help="modelo del provider (vacío = default del provider)")
    p_sched_add.add_argument("--webhook", dest="notify_webhook", default=None)
    p_sched_add.set_defaults(func=cmd_schedule_add)

    p_sched_del = sched_sub.add_parser("delete", help="Elimina un schedule")
    p_sched_del.add_argument("schedule_id")
    p_sched_del.set_defaults(func=cmd_schedule_delete)

    p_sched_run = sched_sub.add_parser("run-daemon", help="Corre el daemon de schedules en foreground")
    p_sched_run.set_defaults(func=cmd_schedule_daemon)

    # ── agent-scan ────────────────────────────────────────────────────────────
    p_agent = sub.add_parser(
        "agent-scan",
        help="Scan autónomo dirigido por LLM: Claude decide qué tests correr según hallazgos acumulados. Requiere ANTHROPIC_API_KEY"
    )
    p_agent.add_argument("--target", required=True,
                          help="URL o dominio del objetivo, ej: https://example.com")
    p_agent.add_argument("--scope", default=None,
                          help="dominios en scope, separados por coma. Recomendado siempre.")
    p_agent.add_argument("--goal", default=None,
                          help="instrucción al agente, ej: 'Encontrar paneles admin expuestos y SQLi'")
    p_agent.add_argument("--provider", default="auto",
                          help="provider LLM: auto|anthropic|openai|deepseek|nvidia|mistral|groq|together|openrouter|gemini|xai|ollama|custom. 'auto' detecta API keys del entorno. (default: auto)")
    p_agent.add_argument("--model", default=None,
                          help="modelo del provider (vacío = default del provider, ej: claude-sonnet-5-5, gpt-4o-mini, deepseek-chat)")
    p_agent.add_argument("--max-rounds", dest="max_rounds", type=int, default=8,
                          help="rondas máximas de llamadas al LLM (default 8)")
    p_agent.add_argument("--timeout-s", dest="timeout_s", type=int, default=180,
                          help="timeout por test en segundos (default 180)")
    p_agent.add_argument("--rate-limit", dest="rate_limit", type=int, default=150,
                          help="peticiones/seg máximas hacia el target (default 150)")
    p_agent.add_argument("--allow-level3", dest="allow_level3", action="store_true",
                          help="permite tests nivel 3 (net.sqlmap_sqli — intrusivo, solo con autorización explícita)")
    p_agent.add_argument("--denylist", default=None,
                          help="hosts siempre bloqueados, separados por coma. Las IPs privadas/loopback van automáticamente.")
    p_agent.add_argument("--out", default="reporte_agent.html")
    p_agent.add_argument("--sarif-out", dest="sarif_out", default=None)
    p_agent.add_argument("--environment", choices=["production", "development", "staging"], default="production")
    p_agent.add_argument("--min-confidence", dest="min_confidence",
                          choices=["heuristic", "verified"], default="heuristic")
    p_agent.add_argument("--allowlist", dest="allowlist", default=None)
    p_agent.add_argument("--print", dest="print_findings", action="store_true")
    p_agent.add_argument("--no-file", dest="no_file", action="store_true")
    p_agent.add_argument("--v2", action="store_true", default=False,
                         help="Usar orquestador Planner+Worker separados (experimental)")
    p_agent.set_defaults(func=cmd_agent_scan)

    # ── rsi ────────────────────────────────────────────────────────────────
    p_rsi = sub.add_parser("rsi", help="Gestión de lecciones RSI (Recursive Self-Improvement)")
    rsi_sub = p_rsi.add_subparsers(dest="rsi_cmd", required=True)

    p_rsi_list = rsi_sub.add_parser("list", help="Lista lecciones extraídas de scans anteriores")
    p_rsi_list.add_argument("--kind", default=None,
                             choices=["exploitation", "enumeration", "false_positive",
                                      "efficiency", "chaining"],
                             help="Filtrar por tipo de lección")
    p_rsi_list.add_argument("--limit", type=int, default=50)
    p_rsi_list.set_defaults(func=cmd_rsi_list)

    p_rsi_clear = rsi_sub.add_parser("clear", help="Elimina todas las lecciones RSI")
    p_rsi_clear.set_defaults(func=cmd_rsi_clear)

    p_rsi_rm = rsi_sub.add_parser("remove", help="Elimina una lección por ID")
    p_rsi_rm.add_argument("lesson_id")
    p_rsi_rm.set_defaults(func=cmd_rsi_remove)

    args = parser.parse_args()
    args.func(args)


def cmd_rsi_list(args):
    from engine.rsi.lessons import LessonLibrary, LessonKind
    lib = LessonLibrary()
    if args.kind:
        lessons = lib.by_kind(LessonKind(args.kind))
    else:
        lessons = lib.all()
    lessons_sorted = sorted(lessons, key=lambda l: l.created_at, reverse=True)[:args.limit]
    if not lessons_sorted:
        print("No hay lecciones RSI guardadas.")
        return
    for l in lessons_sorted:
        print(f"[{l.id}] {l.kind.value:15s} conf={l.confidence:.2f} hits={l.hits}")
        print(f"  CUE:    {l.cue[:80]}")
        print(f"  ACTION: {l.action[:80]}")
        print(f"  SOURCE: scan {l.source_scan_id}  created: {l.created_at[:10]}")
        print()


def cmd_rsi_clear(args):
    from engine.rsi.lessons import LessonLibrary
    lib = LessonLibrary()
    count = lib.clear()
    print(f"Eliminadas {count} lecciones RSI.")


def cmd_rsi_remove(args):
    from engine.rsi.lessons import LessonLibrary
    lib = LessonLibrary()
    ok = lib.remove(args.lesson_id)
    if ok:
        print(f"Lección {args.lesson_id} eliminada.")
    else:
        print(f"No se encontró la lección {args.lesson_id}.")


if __name__ == "__main__":
    main()
