# Ares — Estado del Proyecto

Plataforma híbrida ofensiva/defensiva. Ares era análisis profundo de MCPs/APIs simulando un atacante. ARTEX era herramienta ofensiva activa usada por hackers. El híbrido es la herramienta definitiva para que empresas y gobiernos analicen sus propias fallas desde la perspectiva del adversario.

**~205 archivos Python en engine/ · ~37 000 líneas · 10 skills · 17 scripts · port ARTEX 100% completo**

---

## Progreso por wave

| Wave | Contenido | Estado |
|---|---|---|
| Wave 1 | Infraestructura core (auth, intercept, agent layer, subsistemas) | ✅ 100% |
| Wave 2 | Skills (10) + Scripts (5) | ✅ 100% |
| Wave 3 | DB schema, server API, dashboard, extension, conexiones | ✅ 100% |
| Wave 4 | Traffic module, agent lifecycle, DB persistence, skill scripts, PoC scripts | ✅ 100% |
| Wave 5 | cancelcause, runinfo, promptcatalog, session, constraints, scan/bbot ingest, webfetch, server infra, asset DSL | ✅ 100% |

---

## Engine — módulos existentes (pre-hibridación)

| Módulo | Descripción | AI |
|---|---|---|
| `engine/adversarial/` | Cadenas de ataque: injection, auth bypass, deserialization, prototype pollution | requiere AI |
| `engine/api/` | REST tester, OpenAPI parser, GraphQL introspection, auth flow | recomendado |
| `engine/dynamic/` | Browser automation, XSS, CSP analysis, CORS check, clickjacking | recomendado |
| `engine/netrecon/` | 8 tools de red: port scan, banner grab, DNS, whois, SSL, traceroute | no AI |
| `engine/persistence/` | Store de hallazgos, knowledge graph, task state, Postgres async | no AI |
| `engine/policy/` | Scope management, rate limits, finding deduplication, severity scoring | no AI |
| `engine/reporting/` | HTML report con severidad, timeline, executive summary | recomendado |
| `engine/egress/governor.py` | Egress governor con rate limit por perfil ⚠️ bug: cache_ttl no aplicado | no AI |
| `engine/agent/budget.py` | Budget de tokens/coste con margen de wrapup (port de ARTEX budget.go) | no AI |
| `engine/agent/planner.py` | Planner LLM: descompone objetivos en subtareas | requiere AI |
| `engine/agent/worker.py` | Worker: ejecuta subtareas, llama tools | requiere AI |
| `engine/intercept/gate.py` | Target gate: denylist, IPs privadas, nivel de intrusividad, aprobación humana | no AI |
| `engine/mcp_server.py` | Expone Ares como servidor MCP (atacable desde Claude Desktop etc.) | no AI |
| `webui/app.py` | FastAPI + WebSocket + dashboard | no AI |
| `webui/static/index.html` | Dashboard de 5 paneles (limitado vs ARTEX) | no AI |

---

## Engine — nuevo en la hibridación con ARTEX

### Seguridad y arranque

| Archivo | Qué hace |
|---|---|
| `engine/auth/auth.py` | JWT HS256 + bcrypt. `get_jwt_secret()` persiste en `~/.ares/jwt.key`. `get_admin_hash()` persiste en `~/.ares/admin.hash` |
| `engine/auth/login_limit.py` | `LoginLimiter` con escalada: 0–4 fallos libre · 5–9 → 60s · 10–19 → 300s · 20+ → 1800s |
| `engine/core/env_scrub.py` | `scrub_env()` elimina 16 patrones de secretos del `os.environ` al arrancar. Preserva `ARES_*`, `PATH`, `HOME`, `USER`. Loguea solo nombres, nunca valores |

### Intercept — ciclo de vida de tool calls

| Archivo | Qué hace |
|---|---|
| `engine/intercept/guard.py` | Orquestador `pre_tool/post_tool`: gate check → risk scoring (0–100) → judge si risk>50. Audit log circular maxlen=1000 |
| `engine/intercept/judge.py` | ⚠️ **Bug corregido**: de 8 a 11 preguntas. Las 3 nuevas usan negación para evitar el sesgo de polarización |
| `engine/intercept/risk.py` | Score de riesgo determinístico 0–100 por tool call sin LLM. `TOOL_BASE_SCORES` configurable |
| `engine/intercept/trace.py` | `CallTrace` con duración, límites de tamaño (`MAX_OUTPUT_LEN=50 000`), `cap_text()` con sufijo visible |
| `engine/intercept/review_context.py` | Separación `human_instruction` / `agent_summary` anti-prompt-injection en el contexto del juez |
| `engine/intercept/argv.py` | Parser de argumentos CLI por aridad (`ARGV_ARITY`) para extracción de targets con `shlex` |
| `engine/intercept/alwaysallow_denylist.py` | `ALWAYS_DENYLIST`: frozensets de binarios peligrosos (shell, priv escalation, remote access, system sensitive). `validate_allow_rule()` |
| `engine/intercept/target_extract.py` | Extracción automática de URLs/hosts/IPs de argumentos de cualquier tool. `NO_TARGET_TOOLS` frozenset |
| `engine/intercept/target_redirect.py` | Re-check del gate en cada hop HTTP: lanza `RedirectDenied` si el destino sale del scope |
| `engine/intercept/target_rendered.py` | Extracción de URLs del comando ya renderizado antes de ejecutarlo |

### Agent layer

| Archivo | Qué hace |
|---|---|
| `engine/agent/orchestrator.py` | **Stagnation detection añadida**: `STAGNATION_WINDOW=3` rondas sin findings nuevos → inyecta hint al planner. Emite evento `stagnation_detected` |
| `engine/agent/goals.py` | Descomposición de metas con LLM + extracción de constraints deny/allow del operador. `goal_is_ambiguous()` |
| `engine/agent/mainagent.py` | Chat agent paralelo al loop autónomo. El operador inyecta hints al planner via `asyncio.Queue` |
| `engine/agent/toolcatalog.py` | Catálogo con prioridad `db_override > builtin`. Exporta formatos Anthropic y OpenAI. `apply_db_override()` |
| `engine/agent/assembly.py` | Ensamblado del system prompt en 7 secciones ordenadas. Depende de `noise_profile` y `untrusted_boundary` |
| `engine/agent/deferred.py` | Registry de tools MCP con schema oculto hasta `unlock()` explícito. Reduce attack surface del agente |
| `engine/agent/noise_profile.py` | 5 niveles: `SILENT / QUIET / BALANCED / ACTIVE / LOUD`. Inyecta texto en el prompt. Controla `max_concurrent_tools` y `requests_per_second` |
| `engine/agent/retester.py` | Sesión dedicada de re-test: `RetestVerdict.REPRODUCED / FIXED / INCONCLUSIVE` |
| `engine/agent/coldgraph.py` | Grafo de exploración con nodos hot/cold. BFS para grupos conectados. `apply_digest()` para comprimir nodos fríos |
| `engine/agent/compaction.py` | Loop asyncio cada 30s que compacta nodos fríos del grafo con LLM. Semáforo de concurrencia |
| `engine/agent/llmpool.py` | **Upgrade**: circuit breaker escalado (trip 1→60s, trip 2→300s, trip 3+→1800s). Nuevo `health_status()` |

### Nuevos subsistemas

| Archivo | Qué hace |
|---|---|
| `engine/evidence/store.py` | Almacén content-addressed por sha256. GC por reference counting. Verificación de integridad en lectura. Export de manifest JSON |
| `engine/llmrec/llmrec.py` | Graba cada LLM call en JSONL: messages, response, tokens, latencia. Ring buffer en memoria. Truncación a 10k chars por campo |
| `engine/sidequestion/service.py` | El operador pregunta al agente en curso usando un snapshot del contexto. `Semaphore(1)` para serializar. No interrumpe el loop |

### Upgrades de módulos existentes

| Archivo | Cambios |
|---|---|
| `engine/notify/notifier.py` | +DingTalk (firma HMAC-SHA256), WeCom, Telegram Bot API, Email SMTP. SSRF guard en todos los canales. Severity filter. Markdown escaping. Cap de mensajes |
| `engine/proxy/recorder.py` | +HTTPS CONNECT tunneling: forward bidireccional con `asyncio.gather`. Log de metadata en JSONL |
| `webui/app.py` | Endpoint `POST /api/login` con rate limiting por IP. `_require_auth` como FastAPI `Depends`. `scrub_env()` al arrancar |
| `pyproject.toml` | Nuevas deps: `passlib[bcrypt]`, `python-jose[cryptography]` |

---

## Skills (10/10)

| Skill | Descripción | AI |
|---|---|---|
| `api-recon` | Enumeración de APIs: endpoints, métodos, params, routes frontend. Estático + dinámico con hooks/stubs | recomendado |
| `api-security` | Testing ofensivo REST/GraphQL/WebSocket/SOAP. BOLA, IDOR, BFLA, JWT/OAuth, mass assignment, SSRF. 10 fases | recomendado |
| `bbot-recon` | Recon breadth-first (bbot v3.0.2). Modos P/A/Loud. Recetas: subdomains, takeover, params, email perimeter | no AI |
| `codeaudit` | White-box: inventario de inputs, traza forward a sinks por clase de vuln. Requiere PoC ejecutado | recomendado |
| `edr-bypass-re` | RE de telemetría EDR en lab autorizado: hooks ntdll, kernel callbacks, ETW, AMSI. MITRE T1562 | requiere AI |
| `patch-diff` | N-day desde el fix del vendor: diff binario (ghidriff), inferencia de bug class, verificación con PoC | recomendado |
| `php2shell` | LFI→RCE via session.upload_progress (CVE-2026-109618/109619) en PHP 5.4–8.5.11. Lab-first siempre | recomendado |
| `playwright-cli` | Automatización de browser: clicks, fill, snapshot, network mocking, CDP attach, tracing, video | no AI |
| `rea` | RE de binarios vía MCP server: ELF, PE, Mach-O, APK, IPA, WASM, JS bundles. Secretos, endpoints, imports | requiere AI |
| `scopesentry` | Gestión de ScopeSentry vía MCP: proyectos, tareas, templates, assets. DSL de consultas | no AI |

---

## Scripts

| Script | Descripción |
|---|---|
| `scripts/backup.sh` | `pg_dump` de Postgres + `tar.gz` de `data/`. Destino: `ARES_BACKUP_DIR` |
| `scripts/posture_check.py` | 9 prompts calibrados contra un endpoint LLM local para medir over-refusal. Score 0–100 |
| `scripts/submission_review/review.py` | LLM judge pre-submission: impacto, reproducibilidad, evidencia, scope. Veredicto SUBMIT/REVISE/WITHHOLD |
| `scripts/benchmark/` | Estructura para medir hallazgos vs corpus de targets vulnerables. LLM judge con ground truth JSON |
| `scripts/extract-changelog-section.sh` | Extrae una sección de versión de `CHANGELOG.md` |

---

## Wave 4 — completada

### Traffic module (`engine/traffic/`)

| Archivo | Qué hace |
|---|---|
| `engine/traffic/traffic.py` | `Traffic` class: SQLite WAL + blob deduplication SHA-256 + FTS5. `query_exchanges()`, `get_exchange()`, `stats()`. Singleton `init()`/`get()` |
| `engine/traffic/external.py` | `record_external()`: empareja eventos CDP request+response por `requestId`, llama `_insert_exchange()` |
| `engine/traffic/archive.py` | `export_hosts()`: exporta exchanges + blobs a `manifest.json` + `blobs/<hash>` |
| `engine/traffic/evidence.py` | `read_evidence()`: lee bodies completos (inline o blob) para findings |
| `engine/traffic/pace.py` | `pace_request()`: espera governor con timeout 30s |
| `engine/traffic/stream.py` | `record_stream_message()`, `get_stream_messages()`, `stream_traffic_ws()` |

### Agent lifecycle (`engine/agent/`)

| Archivo | Qué hace |
|---|---|
| `engine/agent/terminalreason.py` | `TerminalReason` enum, `REASON_HINTS`, `terminal_text()` renderer |
| `engine/agent/taskclock.py` | `TaskClock`, `clamp_max_duration()`, `remaining_seconds()`, `is_expired()` |
| `engine/agent/wrapup.py` | Prompts de wrapup por agente + hooks DB-override + `build_settlement_for_task()` |
| `engine/agent/data_envelope.py` | `DataEnvelope` con nonce crypto, `wrap()`, `render_overview_sections()` |
| `engine/agent/finding_recorder.py` | `FindingRecorder` protocol + `NoopFindingRecorder` + guidance constants |
| `engine/agent/finding_workflow.py` | `FindingState`, traffic-binding toggle, `apply_workflow_tools()` |
| `engine/agent/noa.py` | `NoaBudget`, `NoaOptions`, `enable_noa()` context compression |

### DB persistence (`engine/persistence/`)

| Archivo | Qué hace |
|---|---|
| `engine/persistence/conversation.py` | `ConversationStore`: CRUD conversations + activities + token summaries |
| `engine/persistence/exploration.py` | `ExplorationStore`: nodes, facts, state transitions, cold marking |
| `engine/persistence/settings.py` | `SettingsStore`: KV con XOR-encryption para secrets, bool/int helpers |

### Skills api-recon scripts

| Script | Qué hace |
|---|---|
| `skills/api-recon/scripts/extract_route_map.py` | Extrae rutas de bundles JS (webpack/Vite/Rollup) vía regex |
| `skills/api-recon/scripts/harvest_static.py` | Crawla HTML + descarga JS assets para extraer endpoints |
| `skills/api-recon/scripts/preload.js` | Hook XHR/fetch/WebSocket inyectado vía CDP antes de navegación |
| `skills/api-recon/scripts/runtime_harvest.js` | `__ARES_HARVEST()` y `__ARES_ROUTES()` para SPA runtime collection |
| `skills/api-recon/scripts/spider_mpa.py` | Spider MPA hasta depth N: links + forms + inline endpoints |
| `skills/api-recon/scripts/build_perm_tree.py` | Árbol de permisos por rol desde route map, observaciones de seguridad |

### PoC scripts php2shell

| Script | Qué hace |
|---|---|
| `skills/php2shell/poc/verify_handler_mismatch.py` | Prueba extensiones PHP alternativas (.php5, .phtml, etc.) |
| `skills/php2shell/poc/verify_session_injection.py` | Race condition session.upload_progress con N threads |
| `skills/php2shell/poc/verify_uaf_asan.php` | Detecta UAF via ASan instrumentation en php-asan build |
| `skills/php2shell/lab/setup.sh` | Docker/Podman lab: PHP Apache + endpoints vulnerables + configuración |

### Integración traffic en app.py

`/api/capture` ahora escribe al Traffic SQLite store + fallback ring buffer.
Nuevos endpoints: `GET /api/traffic/exchanges`, `/api/traffic/exchanges/{id}`, `/api/traffic/stats`.

---

## Pendiente — Wave 3

### 1. DB Schema — 8 tablas nuevas

Sin estas tablas los nuevos subsistemas (llmrec, evidence, intercept audit) guardan en JSONL solamente.

- `task_credentials` — credenciales por tarea
- `task_templates` — plantillas reutilizables
- `task_archives` — historial comprimido
- `llm_usage` — uso de tokens por provider/modelo
- `intercept_audit` — log persistente del guard
- `company_scope` — scope empresarial multi-tenant
- `skill_gaps` — tracking de skills no cubiertas
- `digest` — compactaciones de cold graph

### 2. Server API — ~20 endpoints faltantes en `webui/app.py`

```
GET/POST  /api/goals, /api/constraints
POST      /api/tasks/{id}/start, /stop, /pause
GET       /api/tasks/archives, /credentials, /templates
POST      /api/intercept/approve, /deny          ← HITL en vivo
GET       /api/skills, POST /api/skill/{name}/load
GET       /api/llm-records
GET       /api/tool-usage
POST      /api/sidequestion/ask
GET       /api/update-check
```

### 3. Dashboard — de 5 paneles a 20+ vistas

`webui/static/index.html` es funcional pero muy limitado frente al dashboard completo de ARTEX. Vistas faltantes: tasks con estado en tiempo real, findings con filtros, assets, intercept HITL, skills, LLM records, agents, notify, settings (noise profile, budget, scope).

### 4. Browser Extension — upgrade a CDP

La extensión actual captura headers pero no request/response body. Necesita upgrade a Chrome DevTools Protocol para captura completa equivalente a ARTEX.

### ✅ Wave 3 completa

| Item | Archivo(s) | Cambio |
|---|---|---|
| Fix `cache_ttl` | `engine/egress/governor.py` | `_cache` dict en `Governor`, GET cache con TTL por perfil |
| Enrich → KG | `engine/enrich/probe.py` | `kg` param en `EnrichEngine`, `_push_to_kg_domain/url()` llama al graph |
| Coverage → HTML | `engine/reporting/html_report.py` | `_coverage_block()`, `_facts_block()`, `render_html(coverage_summary, facts)` |
| Netrecon → KG | `engine/netrecon/runner.py` | `kg` param, llama `kg.populate_from_report()` al final |
| DB schema | `engine/persistence/sql/005_artex_hybrid_tables.sql` | 8 tablas: `task_credentials`, `task_templates`, `task_archives`, `llm_usage`, `intercept_audit`, `company_scope`, `skill_gaps`, `digest` |
| Server API | `webui/app.py` | +21 endpoints: goals, constraints, tasks lifecycle, archives, templates, intercept HITL, skills, llm-records, tool-usage, sidequestion, update-check |
| Dashboard | `webui/static/index.html` | 5 → 14 paneles: tasks, findings, assets, intercept HITL, skills, LLM records, agents, notify, settings + `authedFetch()` |
| Extension CDP | `extension/background.js`, `manifest.json`, `popup.js/html` | `chrome.debugger` CDP con `Fetch.enable` para body completo; fallback `webRequest`; token field en popup |
