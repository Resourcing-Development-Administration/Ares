# Arquitectura de Ares

Documento técnico interno: cómo está armado el proyecto por dentro, para no
tener que releer todo el código cada vez que se vuelve a tocar. Para
instalación y uso ver [README.md](README.md); para la referencia completa de
cada test/flag ver [MANUAL.md](MANUAL.md). Esto es la vista de "estructura y
funcionamiento", no de features.

- [1. Idea central](#1-idea-central)
- [2. Árbol del proyecto](#2-árbol-del-proyecto)
- [3. Flujo de datos de un scan](#3-flujo-de-datos-de-un-scan)
- [4. Modelo de datos central](#4-modelo-de-datos-central)
- [5. Patrón de plugin de un test](#5-patrón-de-plugin-de-un-test)
- [6. `engine/core/`: lo que ningún test debería reinventar](#6-enginecore-lo-que-ningún-test-debería-reinventar)
- [7. CLI (`cli/main.py`)](#7-cli-climainpy)
- [8. Dashboard web (`webui/`)](#8-dashboard-web-webui)
- [9. Pipeline de reporte](#9-pipeline-de-reporte)
- [10. Policy engine](#10-policy-engine)
- [11. Baseline diff / comparación de auth / modo `full`](#11-baseline-diff--comparación-de-auth--modo-full)
- [12. Tests del propio Ares](#12-tests-del-propio-ares)
- [13. Puntos de extensión](#13-puntos-de-extensión)
- [14. Decisiones de diseño no obvias](#14-decisiones-de-diseño-no-obvias)

---

## 1. Idea central

Ares es un cliente MCP que se conecta a un servidor MCP objetivo (propio o
ajeno, vía stdio o http/sse), enumera su superficie (tools/resources/
prompts) y corre un conjunto de **tests async independientes** contra esa
superficie. Cada test produce `Finding`s; el orquestador los junta en un
`ScanReport`, calcula un score y un veredicto de policy, y el reporte se
serializa a HTML/JSON/SARIF.

No hay estado compartido entre tests salvo el `ctx: dict` que arma el
orquestador (tools enumeradas, config, etc.) — sumar un test nuevo nunca
requiere tocar el orquestador ni los demás tests.

## 2. Árbol del proyecto

```
Ares/
├── ares.sh                  # entrypoint único (Linux/macOS, bash): crea/actualiza .venv y delega a cli/main.py
├── ares.ps1                 # mismo entrypoint para Windows (PowerShell) -- sandbox.py (prlimit/bwrap) sigue
│                              #   siendo Linux-only igual, esto solo resuelve el lanzador
├── ares.bat                  # forwarder delgado a ares.ps1 para cmd.exe/doble-click (bypassa ExecutionPolicy)
├── cli/main.py               # parseo de argparse + comandos: list-tests, discover, update-rules,
│                              #   scan, vet, full, serve
├── engine/
│   ├── core/
│   │   ├── models.py         # Finding, Evidence, ScanConfig, ScanReport, TestMeta, AuthConfig, Severity, Category
│   │   ├── registry.py       # @register_test + all_tests()/list_meta() — auto-registro de plugins
│   │   ├── client.py         # MCPTarget: wrapper sobre el SDK oficial mcp (stdio/sse/http)
│   │   ├── risk.py           # CVSS v3.1 + OWASP Risk Rating Methodology → severidad/riesgo por finding
│   │   ├── cvss.py           # implementación de la fórmula CVSS v3.1 (vector → score)
│   │   ├── confidence.py     # verified/heuristic por test_id (+ override por instancia)
│   │   ├── frameworks.py     # tags OWASP MCP/LLM/API Top 10 + MITRE ATLAS por test_id -- los 10 ítems de
│   │   │                      #   cada Top 10 cubiertos, verificados contra fuente primaria (no memoria)
│   │   ├── framework_watch.py # check_for_updates()/save_baseline(): avisa (nunca actualiza solo) si
│   │   │                      #   OWASP MCP/LLM/API Top 10 o MITRE ATLAS cambiaron de versión pública
│   │   │                      #   (comando `check-frameworks`, con --ack y --fail-if-stale para CI)
│   │   ├── limits.py          # cap_text(): tope de tamaño para texto analizado con regex y para
│   │   │                      #   respuestas de call_tool/read_resource -- defensa contra un target
│   │   │                      #   que infla el costo de análisis de Ares a propósito
│   │   └── sandbox.py         # wrap_command(): aislamiento REAL del subprocess stdio -- prlimit
│   │                           #   (RLIMIT memoria/CPU/procesos/FDs, nproc calculado dinámicamente
│   │                           #   relativo a lo que YA corre, nunca absoluto) + bwrap (namespaces de
│   │                           #   PID/IPC/UTS + corte de red condicional a allow_network)
│   ├── recon/tests.py        # enumerate, suspicious_descriptions, excessive_permissions, audit_logging
│   ├── static/
│   │   ├── tests.py           # schema_permissive, no_schema, known_cve_check, typosquatting_check
│   │   ├── known_cves.py      # feed curado y VERIFICADO (nunca inventado) de CVEs reales de servers MCP oficiales
│   │   └── typosquatting.py   # lista curada de paquetes MCP legítimos + similitud Jaro-Winkler
│   ├── dynamic/               # fuzz_tools, fuzz_resources, command_injection, path_traversal,
│   │   │                      #   credential_harvest_paths, rate_limit
│   │   ├── tests.py
│   │   └── payload_gen.py    # generación de casos de fuzzing por tipo de schema
│   ├── adversarial/
│   │   ├── tests.py          # injection_passthrough, confused_deputy, destructive_no_confirmation,
│   │   │                     #   rug_pull, ssrf_exfil
│   │   ├── chain_tests.py    # adv.stateful_chain_exfil: encadenamiento multi-step CONFIRMADO por ejecución real
│   │   ├── live_agent_tests.py  # adv.live_agent_injection: agente real en el loop (Anthropic/OpenAI/Ollama), opt-in
│   │   └── oob.py             # listener local para confirmar SSRF por callback real (--oob-callback-host)
│   ├── auth/tests.py          # unauthenticated_access, weak_credentials, authz_object_level (BOLA en
│   │                          #   tools), resource_object_level (BOLA en resources), oauth_metadata_security
│   │                          #   (RFC 9728), cross_session_context_bleed (canario de doble marcador --
│   │                          #   id vs secreto, nunca el mismo valor -- plantado con una credencial y
│   │                          #   confirmado con una SEGUNDA credencial/tenant independiente; requiere
│   │                          #   --auth-token-b, http/sse únicamente)
│   ├── exposure/tests.py      # transport_security, cors_misconfig, network_reachability, session_id_entropy
│   ├── supplychain/
│   │   ├── tests.py           # secret_exposure, tool_squatting, exfiltration_chain, malicious_patterns,
│   │   │                     #   dependency_vulnerabilities, source_sast
│   │   ├── sast.py            # runner de semgrep (offline, ruleset propio) para supplychain.source_sast
│   │   ├── rule_sources.py    # fetch/cache de patrones de gitleaks.toml (comando update-rules)
│   │   ├── manifest_parsers.py # parseo de requirements.txt/package.json/package-lock.json
│   │   ├── similarity.py      # Jaro-Winkler para tool squatting (y para tool shadowing en crossserver.py)
│   │   └── osv.py             # consulta a OSV.dev (CVEs reales) para dependency_vulnerabilities
│   ├── discovery/
│   │   ├── well_known.py      # rutas de config conocidas (Claude Desktop, Cursor, VSCode, Windsurf, Codex)
│   │   └── local_configs.py   # discover_mcp_servers(): parsea esas configs → lista de targets
│   ├── crossserver.py         # analyze_cross_server() (dict para consola/JSON crudo) +
│   │                          #   cross_server_findings() (Finding reales -- score/policy/SARIF, no solo
│   │                          #   texto de consola): tool shadowing (MCP09:2025) + cadenas de exfiltración
│   │                          #   ENTRE servers distintos -- solo aplicable con 2+ targets (modo full)
│   ├── policy/engine.py       # policy.yaml + findings → veredicto BLOCK/CONDITIONAL/ALLOW
│   ├── reporting/
│   │   ├── scoring.py         # score 0-100 + grade A-F desde los findings confirmados
│   │   ├── html_report.py     # reporte HTML navegable (self-contained)
│   │   ├── sarif.py           # export SARIF 2.1.0 para CI/GitHub code scanning
│   │   ├── redact.py          # redacta secretos de la evidencia antes de persistir a disco
│   │   └── suppress.py        # apply_noise_reduction(): allowlist (.ares_allowlist.yml) + --min-confidence
│   ├── orchestrator.py        # run_scan(): conecta, corre los tests seleccionados, arma el ScanReport
│   ├── compare.py             # run_auth_comparison(): corre el scan con y sin auth, diffea
│   └── baseline.py            # diff_against_baseline(): compara contra un reporte.json anterior
├── payloads/
│   ├── prompt_injection.py    # payloads de prompt injection reutilizados por varios tests adversarial
│   └── canary.py               # generación/verificación de canarios (confirma ejecución real, no solo reflejo)
├── policy.yaml                 # reglas de policy por test_id × ambiente (production/development)
├── .ares_allowlist.example.yml # plantilla de allowlist de findings aceptados -- copiar a .ares_allowlist.yml
├── rules/
│   ├── secrets_patterns.json  # cache de patrones de secretos (banco propio + gitleaks vía update-rules)
│   └── semgrep_mcp.yml        # ruleset propio para supplychain.source_sast (taint-aware, offline)
├── webui/
│   ├── app.py                  # FastAPI: /api/tests, /api/discover, /api/reports, /ws/scan (progreso en vivo)
│   └── static/index.html       # dashboard SPA (vanilla JS), consume los endpoints de arriba
├── target_server.py             # MCP vulnerable de práctica, vía stdio
├── target_server_http.py        # MCP vulnerable de práctica, vía streamable-http sin auth
├── tests/                       # test suite del propio Ares (pytest), ver sección 12
├── reports/                      # salida por defecto del dashboard (persistido, gitignored)
└── README.md / MANUAL.md / ARCHITECTURE.md
```

## 3. Flujo de datos de un scan

```
CLI (cmd_scan/cmd_vet/cmd_full)  o  webui (ws_scan)
        │  arma un ScanConfig (target, tests seleccionados, flags)
        ▼
engine.orchestrator.run_scan(config, progress_cb)
        │
        ├─ abre MCPTarget(transport, connection)  ─┐ si falla, NO aborta el scan entero:
        │    (stdio_client / sse_client /            queda registrado como error y los tests
        │     streamablehttp_client del SDK mcp)      que no necesitan sesión igual corren
        │
        ├─ arma ctx = {max_fuzz_cases_per_tool, source_path, transport, connection,
        │              oob_callback_host, baseline_tools, connection_error,
        │              secondary_auth (para auth.cross_session_context_bleed), ...}
        │   (connection["sandbox"] lleva mem_mb/cpu_s/nproc/nofile/allow_network --
        │    client.py los lee ahí para armar el wrap_command() de engine/core/sandbox.py)
        │
        ├─ para cada test_id seleccionado (registry.all_tests()):
        │      si requires_network y no allow_network_side_effects → se salta (error informativo)
        │      emit("test_started") → await func(target, ctx) → list[Finding]
        │      emit("test_finished" | "test_error")
        │      (ctx se va enriqueciendo: recon.enumerate deja ctx["tools"/"resources"/"prompts"]
        │       para que los tests siguientes no vuelvan a enumerar)
        │
        ▼
ScanReport (findings + errores + tools/resources/prompts enumerados)
        │
        ├─ apply_noise_reduction(report, allowlist_path, min_confidence)  (engine/reporting/suppress.py)
        │    marca Finding.suppressed=True (allowlist o --min-confidence) ANTES de calcular score/policy --
        │    nunca borra el finding, solo lo saca del conteo que sigue
        ├─ calculate_score(report)         → report.score        (engine/reporting/scoring.py)
        ├─ PolicyEngine().evaluate(report)  → report.policy_verdict (engine/policy/engine.py, ignora suppressed)
        └─ (opcional) diff_against_baseline / run_auth_comparison
        ▼
redact_report(report)  →  save_html_report / json.dump / save_sarif_report
```

`progress_cb` es el mismo callback para CLI (imprime con `rich`) y para el
dashboard (emite por WebSocket) — el orquestador no sabe ni le importa quién
está escuchando.

## 4. Modelo de datos central

Todo vive en `engine/core/models.py`:

- **`Finding`** — el output atómico de un test. Campos fijos: `test_id`,
  `title`, `category`, `target`, `description`, `evidence`, `passed`,
  `remediation`, `references`. **`severity`, `risk`, `confidence` y
  `frameworks` NO se setean a mano** — son properties calculadas a partir de
  `test_id` (y opcionalmente de un `*_override` cuando esa instancia puntual
  tiene evidencia distinta al caso típico, ej. `cvss_vector_override` cuando
  un SSRF se confirmó por callback OOB real). Ver `engine/core/risk.py`.
  También trae `suppressed`/`suppressed_reason` (default `False`/`None`) --
  seteados únicamente por `apply_noise_reduction` (sección 3), nunca por un
  test; un finding suprimido sigue en `report.findings` y en el HTML/JSON,
  solo se excluye de `ScanReport.summary()`/`PolicyEngine.evaluate()`.
- **`Evidence`** — request/response/notes/raw de la prueba concreta; se
  serializa a dict de forma segura (si algo no es JSON-serializable, se
  vuelca como `str()`).
- **`ScanConfig`** — todo lo que necesita `run_scan`: target, transporte,
  tests seleccionados, flags de red/auth/ambiente/fuzzing.
- **`ScanReport`** — el output completo de una corrida: findings +
  enumeración + errores + score + policy_verdict + (opcional) auth_impact/
  baseline_diff. `to_dict()` es lo que se vuelca a `reporte.json`.
- **`TestMeta`** — metadata declarativa de un test (id, categoría,
  default_enabled, requires_network) — es lo que arma `list-tests` y los
  checkboxes del dashboard.
- **`AuthConfig`** — credenciales explícitas (`bearer`/`apikey`/`custom`) →
  se convierten en headers HTTP vía `to_headers()`.

## 5. Patrón de plugin de un test

Cada módulo de categoría (`engine/<categoria>/tests.py`) define funciones
`async def` decoradas con `@register_test`, que se auto-registran en un dict
global (`engine/core/registry.py::_REGISTRY`) al importar el módulo. El
orquestador importa todos los módulos de test al arrancar
(`engine/orchestrator.py`, bloque de imports `# noqa: F401`) — **ese bloque
de imports es la única lista central de qué categorías existen**; un módulo
de test nuevo que no se importe ahí nunca se registra.

```python
@register_test(
    id="recon.enumerate",
    name="Enumeración de tools/resources/prompts",
    category=Category.RECON,
    description="Lista todo lo que expone el servidor MCP.",
    default_enabled=True,     # False = opt-in, solo corre con --tests o con `vet`
    requires_network=False,   # True = requiere --allow-network (conexiones salientes reales)
)
async def enumerate_surface(target: MCPTarget, ctx: dict) -> list[Finding]:
    tools = await target.list_tools()
    ...
    return [Finding(test_id="recon.enumerate", ...)]
```

Firma fija: `(target: MCPTarget, ctx: dict) -> list[Finding]`. `target` es
`None` si la conexión inicial falló (tests que no necesitan sesión viva —
`auth.unauthenticated_access`, `exposure.*`, `auth.oauth_metadata_security` —
manejan ese caso con su propio cliente HTTP en vez de `target`).

## 6. `engine/core/`: lo que ningún test debería reinventar

- **`client.py` (`MCPTarget`)** — única puerta al SDK `mcp` real. Expone
  `list_tools/list_resources/list_resource_templates/list_prompts/call_tool/
  read_resource`, todas con logging crudo en `call_log` (evidencia) y
  `call_tool`/`read_resource` **nunca levantan excepción** — devuelven un
  dict normalizado `{ok, content, is_error, raw_error, elapsed_ms}`, así los
  tests de fuzzing pueden iterar sin try/except por cada caso. `_log()`
  (el punto único por el que pasan todas las llamadas) reenvía cada entrada
  en vivo vía `self.progress_cb` si `ScanConfig.verbose=True` -- eso es
  `--verbose`/el checkbox del dashboard: el orquestador setea
  `target.progress_cb = emit` y `target.current_test_id` antes de cada
  test, así cada llamada real sale tageada con qué test la disparó.
- **`risk.py` + `cvss.py`** — CVSS v3.1 real (vector → score, verificado
  contra vectores de referencia públicos) + OWASP Risk Rating Methodology
  (Likelihood × Impact → Note/Low/Medium/High/Critical). Es la única fuente
  de verdad de severidad; un test no "elige" severidad, como mucho ajusta el
  vector con un override cuando tiene evidencia real de que esa instancia es
  distinta al caso típico. `risk_for(..., category=...)` calcula además un
  `aivss` complementario (`aivss_for()`, sección 7.1 del MANUAL) — solo si
  se pasa `category`; nunca reemplaza el CVSS/OWASP Risk Rating de arriba,
  que sigue gateando policy/score.
- **`confidence.py`** — `verified` vs `heuristic` por `test_id`.
- **`frameworks.py`** — mapeo estático `test_id → [tags OWASP/MITRE]`; un
  test de CI (`test_every_registered_test_has_framework_coverage`) exige que
  todo test registrado resuelva al menos un tag.
- **`framework_watch.py`** — a diferencia de `frameworks.py` (qué framework
  aplica a cada test), esto detecta cuándo esos frameworks EXTERNOS
  cambiaron de versión públicamente (comando `check-frameworks`, API de
  GitHub, sin token). Nunca actualiza nada solo -- un Top 10 nuevo puede
  implicar escribir un test, no solo refrescar un JSON.
- **`limits.py`** — `cap_text()`, el único lugar que decide cuánto texto no
  confiable de un target se analiza con regex o se guarda de una respuesta.
  Aplicado en `client.py` (fuente) y en los blob-builders de
  `recon/supplychain` (defensa en profundidad).
- **`sandbox.py`** — `wrap_command()`, aislamiento real del subprocess
  stdio (`prlimit` + `bwrap`, ver sección 2 más arriba). Distinto de
  `limits.py`: eso acota lo que Ares LEE de un target hostil, esto acota lo
  que el PROCESO del target puede CONSUMIR/ALCANZAR del host.

Ver sección 7 del MANUAL para el detalle completo de la metodología.

## 7. CLI (`cli/main.py`)

Un solo archivo, `argparse` con subparsers. Cada `cmd_*` arma un
`ScanConfig` (o varios) y llama a `engine.orchestrator.run_scan` (a veces vía
`engine.compare.run_auth_comparison`), y termina en `_emit_report(report,
args, out_html, sarif_path)` — el punto único de salida de un `ScanReport`:
escribe `.html`/`.json`/(opcional)`.sarif` vía `_write_reports()` (redacta
primero con `redact_report`) salvo que `args.no_file` esté seteado, e
imprime una tabla de hallazgos confirmados en terminal
(`_print_findings_table()`) si `args.print_findings` o `args.no_file` están
seteados — `--print`/`--no-file` son flags de `scan`/`vet`/`full` que
controlan esto (ver sección 3.4 del MANUAL). `no_file` sin `print_findings`
igual fuerza la tabla en terminal, para que la corrida nunca termine sin
mostrar nada.

| Comando | Qué hace | Función |
|---|---|---|
| `list-tests` | imprime `list_meta()` en tabla | `cmd_list_tests` |
| `discover` | `discover_mcp_servers()` (sin escanear nada) | `cmd_discover` |
| `update-rules` | fetch de gitleaks.toml → `rules/secrets_patterns.json` | `cmd_update_rules` |
| `scan` | un target (o batch vía `--config`), tests seleccionados o default | `cmd_scan` → `_run_one` |
| `vet` | fuerza TODOS los tests + `--allow-network` + `production`, un solo target | `cmd_vet` (arma un `Namespace` completo y llama a `_run_one`) |
| `full` | discover (o `--config`/target explícito) + `scan`/`vet` de **todos** los targets, **en paralelo** (`asyncio.gather` + `asyncio.Semaphore(--concurrency)`) | `cmd_full` → `_run_full` → `_full_one` por target |
| `serve` | levanta `webui.app:app` con uvicorn | `cmd_serve` |

`full` es el modo agregado más reciente: no reimplementa nada, arma un
`ScanConfig` por target (igual que `_build_config`) y corre `run_scan`
directamente dentro de tareas `asyncio` concurrentes — no dispara procesos
`ares.sh` hijos, así que comparte venv/proceso y es rápido. Cada target
recibe su propio reporte en `--out-dir`; un error en un target no aborta a
los demás (se captura por tarea y queda marcado como `error` en el resumen).

## 8. Dashboard web (`webui/`)

`webui/app.py` (FastAPI) + `webui/static/index.html` (SPA vanilla JS, sin
build step). Mismo motor que la CLI — no hay lógica de scanning duplicada.
Expone los tres modos (`scan`/`vet`/`full`), no solo `scan` como en la
versión inicial — ver la guía de uso campo por campo en
[DASHBOARD.md](DASHBOARD.md).

- `GET /api/tests` → `list_meta()` (mismos datos que `list-tests`).
- `GET /api/discover` → `discover_mcp_servers()`.
- `GET /api/reports` → índice de corridas persistidas (`reports/index.json`).
- `GET /reports/{scan_id}/{archivo}` → sirve el html/json/sarif ya generado.
- `WS /ws/scan` → un target, modo `scan` o `vet` (`mode` en el payload).
  `_build_config(params, target_name, transport, connection, mode)` arma el
  `ScanConfig` completo (auth, opciones, allowlist/min-confidence,
  live-agent-provider, baseline, etc. — mismos campos que la CLI); `mode=vet`
  fuerza todos los tests + `allow_network` + `production` + max-fuzz-cases 50,
  igual que `cmd_vet` en `cli/main.py`. Llama a `run_scan`/`run_auth_comparison`
  con `progress_cb` que reenvía cada evento por el socket (mismo formato que
  consume `_make_progress` en la CLI). Si `baseline_path` está seteado,
  `_apply_baseline_and_webhook()` corre el diff y, si hay findings nuevos y
  se dio `webhook_on_regression`, un solo POST (mismo mecanismo que
  `cli/main.py::_post_webhook`, sin evidencia cruda en el payload).
- `WS /ws/full` → N targets en paralelo (`asyncio.gather` + `Semaphore`,
  mismo patrón que `cli/main.py::_run_full`). Los targets salen de
  `full_config_json` (pegado en el form, mismo parser que
  `discover_mcp_servers_from_file`) o de `full_selected_targets` (checkboxes
  sobre el resultado de `/api/discover`). Cada evento de progreso va tageado
  con `target`. Al terminar, si 2+ targets no fallaron, corre
  `engine.crossserver.analyze_cross_server` sobre sus `tools_enumerated` y
  lo persiste en `<scan_id>/cross_server_correlation.json` — mismo motor que
  usa `cmd_full` en la CLI.

Bindea a `127.0.0.1` por default; con `--host` distinto imprime advertencia
(puede lanzar procesos stdio locales y abrir conexiones salientes reales,
más aún en `vet`/`full` que las fuerzan).

## 9. Pipeline de reporte

```
ScanReport
  → redact_report()        engine/reporting/redact.py — limpia secretos de
                            evidence.request/response/raw antes de tocar disco
  → reporte.json            json.dump(report.to_dict())
  → reporte.html             engine/reporting/html_report.py — self-contained,
                              cards por finding, filtros, panel de riesgo expandible
  → reporte.sarif (opcional) engine/reporting/sarif.py — SARIF 2.1.0, con
                              security-severity para GitHub code scanning.
                              Un finding suprimido va igual en `results[]`
                              pero con `suppressions[]` (mecanismo nativo
                              SARIF) -- GitHub code scanning lo muestra
                              "dismissed", nunca desaparece del todo.
```

`ares_version` (de `engine/__init__.py`) queda estampado en cada reporte para
trazabilidad.

## 10. Policy engine

`engine/policy/engine.py::PolicyEngine` lee `policy.yaml` (reglas por
patrón de `test_id`, con wildcard `algo.*`, + `severity_fallback` por
severidad cuando no hay regla explícita) y calcula, por ambiente
(`production`/`development`), un veredicto por finding y el veredicto
agregado = el más restrictivo de todos (`ALLOW < CONDITIONAL < BLOCK`).
Pensado para gatear CI: `BLOCK` = no apto tal como está para ese ambiente.

## 11. Baseline diff / comparación de auth / modo `full`

- **`engine/baseline.py`** — compara findings confirmados contra un
  `reporte.json` anterior por clave `(test_id, target)` → nuevo/resuelto/
  persiste. También alimenta a `adv.rug_pull` (compara hash de definición de
  tools, no solo findings).
- **`engine/compare.py::run_auth_comparison`** — corre `run_scan` dos veces
  (con y sin `config.auth`/headers) y diffea qué findings desaparecen al
  autenticarse (`mitigated_by_auth`) vs cuáles persisten igual
  (`not_mitigated_by_auth`).
- **modo `full`** (sección 7) — no es un módulo nuevo del engine, es
  orquestación pura a nivel CLI sobre `run_scan` + `discovery`.
- **`engine/crossserver.py::analyze_cross_server`** — llamado desde
  `cmd_full` (no desde el orquestador: opera sobre VARIOS `ScanReport` ya
  terminados, `{server_name: tools_enumerated}`, no sobre uno). Devuelve un
  dict plano (no `Finding`/`Category`: es estructuralmente N-a-N entre
  targets, no encaja en el modelo de un solo target) con `tool_shadowing`
  (colisión/similitud de nombres entre servers + descripciones que
  referencian directivamente tools de OTRO server con lenguaje directivo) y
  `cross_server_exfil_chains` (reader en server A + sender en server B,
  reusando los mismos `READER_RE`/`SENDER_RE` que
  `supplychain.exfiltration_chain` pero cruzando servers). Se imprime y se
  guarda en `<out-dir>/cross_server_correlation.json`.
- **Regresión vía webhook** (`--webhook-on-regression`, en `_run_one` para
  scan/vet y en `cmd_full._maybe_send_full_regression_webhook` para full) —
  la versión "campaña" deliberadamente chica: reusa `--baseline`/
  `--baseline-dir` que ya existían, y hace **un solo** POST (nunca por
  finding, nunca sin regresión) con un payload que excluye `evidence` a
  propósito (un webhook es un destino externo; Ares no le manda ahí lo
  mismo que redacta antes de persistir a disco). No agrega scheduling
  propio -- el cron/systemd timer que dispara `ares.sh full` es del SO.

## 12. Tests del propio Ares

`tests/` (pytest, `asyncio_mode = "auto"` en `pyproject.toml`). Valida que
cada detector encuentra lo que dice encontrar contra los targets vulnerables
(`target_server.py`/`target_server_http.py`, positivo) y que **no** dispara
falsos positivos contra `tests/fixtures/safe_server.py` (negativo). Fixtures
en `tests/conftest.py` levantan/apagan los servers reales como subprocesos
(`session`-scoped para el fixture HTTP). También hay unitarios puros
(Jaro-Winkler, canario, CVSS contra vectores de referencia, scoring, policy
engine) en `tests/test_unit.py`. Corre en CI (`.github/workflows/test.yml`)
en cada push.

## 13. Puntos de extensión

- **Test nuevo** → función `@register_test` en el módulo de categoría que
  corresponda (o uno nuevo, agregándolo al bloque de imports de
  `engine/orchestrator.py` y a `packages` en `pyproject.toml`). Aparece solo
  en `list-tests`, CLI y dashboard. Correr `pytest` después.
- **Categoría de reporte nueva** (ej. un cuarto formato de export) → agregar
  módulo en `engine/reporting/` + llamarlo desde `_write_reports` en
  `cli/main.py` (y desde `webui/app.py` si el dashboard también debe
  ofrecerlo).
- **Modo de CLI nuevo** → un `cmd_*` en `cli/main.py` + su subparser en
  `main()`. Si orquesta múltiples targets, mirar `cmd_full`/`_run_full` como
  referencia de patrón (semáforo de concurrencia + `_write_reports` por
  target + tabla resumen con `rich`).
- **Fuente de datos externa nueva** (como OSV.dev o gitleaks) → debe ser
  siempre opt-in explícito (flag o subcomando dedicado), nunca disparada
  automáticamente por un `scan` normal — es una decisión de diseño explícita
  del proyecto (ver README, "Bases públicas consultadas").

## 14. Decisiones de diseño no obvias

- **Nada se elige "a mano" por test**: severidad (CVSS+OWASP Risk Rating),
  confidence y framework tags se derivan de `test_id` centralizadamente
  (`engine/core/`), no se hardcodean en cada test. Esto es intencional para
  que sean consistentes entre módulos — si hace falta ajustar una instancia
  puntual, se usa un `*_override` en el `Finding`, no un valor fijo.
- **La conexión inicial puede fallar legítimamente** (server bien asegurado
  devuelve 401) y el orquestador no aborta el scan: eso es justamente la
  señal que buscan `auth.unauthenticated_access` y varios de `exposure.*`.
  Ese `try/except` en `orchestrator.py` usa `except*` (PEP 654, Python
  3.11+) en vez de un `except Exception` normal: una falla real de
  conexión (DNS que no resuelve, TLS roto) dentro de `session.initialize()`
  se propaga desde un `anyio.TaskGroup` interno del SDK `mcp` como
  `BaseExceptionGroup` (mezclada con un `CancelledError`, que NO es
  `Exception`) -- un `except Exception` normal no la atrapa, y antes
  tumbaba el proceso entero. `MCPTarget.__aenter__` además envuelve todo su
  cuerpo en `try/except BaseException: await self._stack.aclose(); raise`
  -- si falla a mitad de camino (streams ya entrados, `initialize()`
  todavía no), sin este cleanup explícito los recursos quedan sin cerrar y
  el cleanup se dispara después, desde otra tarea, produciendo el mismo
  tipo de crash. Ver `tests/test_detectors.py::test_dns_failure_on_connect_never_crashes_the_process`.
- **Ningún scan toca red por su cuenta para "actualizarse"**: `update-rules`
  (gitleaks) y `supplychain.dependency_vulnerabilities` (OSV.dev) son
  siempre acciones explícitas/opt-in; ver sección 10 del MANUAL para el
  detalle de qué toca red y qué no.
- **`call_tool`/`read_resource` de `MCPTarget` nunca propagan excepción** —
  devuelven un dict normalizado, para que fuzzing masivo (`dynamic.fuzz_*`)
  no necesite try/except por cada caso generado.
- **`full` corre tareas `asyncio` concurrentes dentro de un solo proceso**,
  no subprocesos `ares.sh` — comparte el venv ya activado, evita el overhead
  de reinstalar/relanzar por target, y permite limitar concurrencia con un
  `Semaphore` en vez de con locks de sistema operativo.
- **`adv.stateful_chain_exfil` nunca reenvía el dato REAL leído** — usa un
  canario sintético (`payloads/canary.py::new_canary`) como "carga simulada"
  entre el tool lector y el tool emisor. Confirma la explotabilidad de la
  cadena (el emisor acepta el dato sin validar procedencia) sin arriesgar
  exfiltrar contenido real del target durante la auditoría misma.
- **`supplychain.source_sast` corre semgrep con `--config <ruta local>`,
  NUNCA `--config auto/p/ci`** — esas últimas sí pegan al registro público
  de reglas de semgrep.dev, rompiendo la invariante "nada toca red sola". El
  ruleset (`rules/semgrep_mcp.yml`) es chico y curado a mano a propósito, no
  un intento de reemplazar un SAST completo.
- **`engine/crossserver.py` tiene DOS salidas, no una** — `analyze_cross_server()`
  (dict plano, para la tabla de consola y el JSON crudo) y
  `cross_server_findings()` (`Finding` reales). Esto NO era así originalmente
  a propósito ("correlacionar 2+ targets es N-a-N, no encaja en el modelo de
  un target") -- y ese diseño resultó ser un gap real, no una decisión
  acertada: el propio código ya marcaba `severity='critical'` para
  `directive_cross_reference` pero nunca pasaba por `calculate_score`/
  `PolicyEngine`/SARIF, invisible para cualquier CI. Se corrigió armando un
  `ScanReport` sintético (`target_name="(correlación cross-server)"`) con
  esos `Finding`, mismo pipeline que cualquier otro target -- ver
  `cli/main.py::_run_cross_server_correlation` / `webui/app.py::ws_full`.
  El dict plano se mantiene aparte (`cross_server_correlation_raw.json`,
  nombre con sufijo a propósito: el primer intento lo escribía en el MISMO
  archivo que el reporte real y uno pisaba al otro).
- **Reducción de ruido nunca borra ni oculta un finding** — `suppressed` es
  visible en HTML (badge + razón)/JSON/SARIF (`suppressions[]` nativo)
  siempre; solo se excluye del conteo que alimenta score/policy. La
  alternativa (no generar el finding) rompería la trazabilidad de auditoría
  y el diff contra baseline.
- **`static.known_cve_check` nunca fabrica un CVE** — cada entrada de
  `engine/static/known_cves.py` se verificó contra una fuente pública real
  (avisos de seguridad/advisory databases) antes de agregarse. Es
  `confidence: heuristic` (no `verified`) a propósito: el `name`/`version`
  que compara viene autoreportado por el TARGET bajo auditoría (vía
  `initialize`/`serverInfo`), que podría mentir -- a diferencia de
  `supplychain.dependency_vulnerabilities`, donde el manifiesto
  (`--source-path`) es un archivo del USUARIO, no del target.
- **Todo test tiene un timeout individual (`ScanConfig.test_timeout_s`,
  default 60s), envuelto con `asyncio.wait_for` en el orquestador** —
  fail-closed: un tool del target que nunca responde corta SOLO ese test
  (queda como error, no como excepción no manejada) y el resto del scan
  sigue. Sin esto, un solo test colgado tumbaba la corrida completa.
- **AIVSS se computa desde defaults de factores agénticos POR CATEGORÍA de
  test** (`engine/core/risk.py::_AGENTIC_FACTORS`), no por test_id
  individual — es una aproximación deliberada (documentada con
  `is_approximation: true` en cada resultado): Ares no puede observar
  mitigaciones reales del target, así que ajustar por-test agregaría falsa
  precisión sin más información real detrás.
- **`RLIMIT_NPROC` nunca es un número absoluto en `engine/core/sandbox.py`**
  — confirmado el error real: `--nproc=64` fijo tumbó la suite de tests
  ENTERA, porque ese límite es sobre el TOTAL de procesos/threads que YA
  tiene el usuario (EUID) en todo el host, kernel aparte -- un shell vacío
  en este mismo dev box ya tenía 59. El default (`nproc=None`) cuenta los
  procesos actuales vía `/proc` y suma `NPROC_HEADROOM` (200) -- si no se
  puede medir (no-Linux), se omite `--nproc` del todo en vez de adivinar.
- **`bwrap` necesita `--tmpfs /tmp` para darle al target un `/tmp` propio y
  escribible, pero eso TAPA con un tmpfs vacío cualquier cosa que ya
  hubiera en `/tmp` del host** — confirmado rompiendo un script de prueba
  real servido desde ahí (el scratchpad de una sesión de Claude Code vive
  bajo `/tmp/claude-.../`): el subprocess ni encontraba su propio archivo.
  `_paths_under_tmp_to_restore()` re-expone (`--ro-bind` puntual, no la
  carpeta entera) cualquier ruta bajo `/tmp` que aparezca en `command`/
  `args`, aplicado DESPUÉS del `--tmpfs /tmp` en la lista de argumentos de
  bwrap (bwrap resuelve binds en orden, el de más atrás gana en la misma
  ruta).
- **`auth.cross_session_context_bleed` usa DOS canarios, nunca uno** — con
  un solo canario usado como identificador Y como contenido a la vez, un
  simple ECO del argumento es indistinguible de una fuga real (confirmado:
  `read_file(path=canario)` fallando con `"no existe el archivo '<canario>'"`
  marcaba como fuga confirmada algo que solo era el mensaje de error
  citando su propio input). `canary_id` se manda en llamadas de lectura;
  `canary_secret` NUNCA se manda como argumento en ninguna llamada de
  lectura -- cualquier aparición de `canary_secret` es inequívoca, sin
  necesitar `strip_reflections`.
