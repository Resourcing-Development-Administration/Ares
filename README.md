# Ares — MCP Red Team Tool

Motor de pruebas de seguridad para servidores MCP: recon, análisis estático,
fuzzing black-box dinámico, pruebas adversariales (prompt injection, SSRF,
confused deputy, tool poisoning, **line jumping**, **rug pull**, acciones
destructivas sin confirmación), autenticación tanto **sin credenciales**
(acceso anónimo, credenciales débiles) como **con una o DOS sesiones
autenticadas reales** (`auth.authz_object_level` — BOLA en tools;
`auth.resource_object_level` — lo mismo en resources; `auth.cross_session_context_bleed`
— planta un canario con una credencial y confirma si se filtra a una
**segunda** credencial/tenant independiente, sin heurística, por ejecución
real; `auth.oauth_metadata_security` — RFC 9728/PKCE), exposición de red
(TLS, CORS, alcance interno/público, entropía de session ID), auditoría
(soporte de logging), supply-chain (secretos expuestos, tool squatting,
cadenas de exfiltración, patrones maliciosos, dependencias vulnerables,
SAST) y correlación **cross-server** (tool shadowing + cadenas de
exfiltración entre servers distintos conectados en la misma sesión, modo
`full`). **39 tests** en total (niveles 1-4 de complejidad, ver `--max-level`),
incluyendo ataques multi-step confirmados
por ejecución real (no solo heurística).

**También audita APIs REST y GraphQL** (`ares api-scan`, módulo separado en
`engine/api/`, mismo motor de score/policy/SARIF): OWASP API Security Top 10
2023 -- rutas sensibles expuestas, headers de seguridad, CORS reflejado,
autenticación no exigida (BFLA), **BOLA/IDOR confirmado** (acceso cruzado
real entre dos ids con la misma credencial), errores verbosos, inyección
SQL/NoSQL básica, método TRACE, rate limiting, debilidades de JWT (`alg=none`,
sin `exp`), mass assignment; y GraphQL -- introspección, sugerencias de
campo, límite de profundidad, batching por alias sin límite, queries/
mutations sin autenticación, mutations ejecutables por GET. Guiado por un
spec OpenAPI/Swagger/Postman (local o URL) o autodescubierto en rutas
comunes; GraphQL se detecta solo. Probado en campo contra DVGA (GraphQL:
introspección + queries sin auth + mutations por GET, las 3 confirmadas) y
contra un fixture REST propio (los 7 detectores con hallazgo confirmado,
cero falsos positivos contra su contraparte segura).

Cada scan produce un score 0-100, un
veredicto de policy (BLOCK/CONDITIONAL/ALLOW) y opcionalmente un diff de qué
hallazgos mitiga realmente la autenticación (`--compare-auth`).

El motor también se defiende de un target activamente hostil, no solo de uno
vulnerable-pero-pasivo: el subprocess stdio corre con límites de recursos
reales (`prlimit`: memoria/CPU/procesos/FDs) y namespaces aislados
(`bwrap`: el target no puede ver, señalizar ni atacar por red al proceso de
Ares ni al host — la red se corta por completo salvo `--allow-network`),
un circuit breaker corta la batería si el target deja de responder de forma
sostenida, y un timeout nunca termina en un ALLOW silencioso — queda como
hallazgo real. Ver "Resiliencia del motor" más abajo.

Cada categoría es un módulo de "plugins" (`engine/<categoria>/tests.py`) que se
autoregistra vía `@register_test`. Sumar una prueba nueva = escribir una función
async más, sin tocar el orquestador ni el reporte.

Cada hallazgo trae tags de a qué framework de seguridad reconocido aplica —
revisado y actualizado (2026-10) leyendo el texto oficial de cada categoría/
técnica, no un resumen de terceros: **OWASP MCP Top 10 (2025)**, los 10
ítems con al menos un test (`MCP01:2025`..`MCP10:2025`); **OWASP LLM Top 10
(2025)**, los 10 con al menos un test; **OWASP API Security Top 10 (2023)**;
y **MITRE ATLAS** (v5.6.0, verificado contra el dataset primario), incluida
`AML.T0110` — la única técnica de ATLAS que nombra "Model Context Protocol"
explícitamente en su propia descripción oficial. Un test de CI
(`test_every_registered_test_has_framework_coverage`) falla si algún test
nuevo queda sin tag — ver `engine/core/frameworks.py` y la sección 6 del
manual. `ares check-frameworks` avisa (nunca actualiza solo) si alguno de
estos 4 frameworks cambió de versión públicamente desde el último check.

La severidad ya no se elige a mano: se calcula con **CVSS v3.1** (fórmula
oficial, verificada contra vectores de referencia públicos) + **OWASP Risk
Rating Methodology** (Likelihood × Impact, impacto al negocio, esfuerzo de
remediación) — ver `engine/core/risk.py` y la sección 7 del manual.

**Manual completo (CLI + dashboard web) en [MANUAL.md](MANUAL.md); guía del dashboard campo por campo en [DASHBOARD.md](DASHBOARD.md).**
**Estructura interna del proyecto y cómo funciona por dentro en [ARCHITECTURE.md](ARCHITECTURE.md).**

## Instalación y uso

```bash
./ares.sh list-tests
```

`ares.sh` es el punto de entrada único: crea el venv, instala/actualiza
dependencias solo cuando hace falta (detecta cambios en
`pyproject.toml`/`requirements.txt`), y delega a la CLI real. No hace falta
activar nada a mano — `./ares.sh scan ...`, `./ares.sh vet ...`,
`./ares.sh serve` funcionan directo, desde cualquier directorio.

**Windows**: `ares.sh` es bash puro — usá `ares.ps1` (PowerShell) o
`ares.bat` (forwarder para `cmd.exe`), mismo comportamiento (crea el venv,
instala dependencias solo si cambiaron, delega a la CLI real):

```powershell
cd Ares
.\ares.ps1 list-tests
.\ares.ps1 scan --command python --args target_server.py --out reporte.html
```

Requisito: **Python 3.11+** (instalalo desde python.org tildando "Add to
PATH"). Si PowerShell bloquea el script por la política de ejecución,
corré una vez `Set-ExecutionPolicy -Scope CurrentUser RemoteSigned` o usá
`ares.bat` (que ya hace el bypass solo para esa llamada). Variables
`$env:ARES_PYTHON` (ruta a un python.exe 3.11+) y `$env:ARES_EXTRAS`
(extras a instalar) ajustan el entorno. **La guía completa y detallada
está en la sección 2.0b del [manual](MANUAL.md).**

El aislamiento de proceso (`prlimit`/`bwrap`, ver "Resiliencia del motor"
abajo) es Linux-only — en Windows el scan corre igual, pero sin esa capa
específica; Ares lo avisa en el reporte, nunca en silencio.

Instalación manual equivalente (o como paquete con `pip install -e ".[dev]"`
para tener el comando `ares` en el PATH) — ver sección 2 del [manual](MANUAL.md).

## Uso

Listar todas las pruebas disponibles y cuáles corren por default:

```bash
./ares.sh list-tests
```

Correr un scan completo (todas las pruebas "default") contra un servidor MCP
propio, vía stdio:

```bash
./ares.sh scan --command python3 --args "mi_servidor.py" --out reporte.html
```

Correr solo pruebas específicas:

```bash
./ares.sh scan --command python3 --args "mi_servidor.py" \
  --tests recon.enumerate,recon.suspicious_descriptions,dynamic.fuzz_tools \
  --out reporte.html
```

Habilitar pruebas que hacen conexiones de red reales (SSRF a endpoints de
metadata cloud, etc. — deshabilitadas por default por ser intrusivas):

```bash
./ares.sh scan --command python3 --args "mi_servidor.py" --allow-network
```

Escanear un servidor remoto vía HTTP/SSE, con credenciales, comparando qué
protege realmente la autenticación, y con veredicto de policy para CI:

```bash
./ares.sh scan --transport http --url https://mi-server.com/mcp \
  --auth-token "$TOKEN" --auth-type bearer \
  --compare-auth --environment production \
  --sarif-out reporte.sarif --out reporte.html
```

Esto corre el scan dos veces (con y sin `$TOKEN`) y agrega al reporte una
sección "Impacto de autenticación": qué hallazgos desaparecen al autenticarse
(la auth SÍ los mitiga) y cuáles persisten igual (la auth NO los mitiga).

Contra un server interno servido con una **CA corporativa/privada**, pasá esa
CA para validar el TLS sin desactivar la verificación (fallback a la env var
estándar `SSL_CERT_FILE`; `REQUESTS_CA_BUNDLE`/`NODE_EXTRA_CA_CERTS` no aplican
—Ares es Python/httpx):

```bash
./ares.sh scan --transport http --url https://mcp.interno.corp/mcp \
  --ca-bundle /etc/ssl/certs/ca-corporativa.pem --out reporte.html
```

El test `exposure.certificate_type` deja anotado en el reporte el **tipo de
certificado** que presenta el server (CA pública, CA interna/privada,
self-signed o cadena desconocida), con emisor, validez y fingerprint SHA-256.
Ver sección 3.6b del [manual](MANUAL.md).

Descubrir qué servidores MCP hay configurados localmente (Claude Desktop,
Cursor, VSCode, Windsurf, Codex) y escanearlos todos de una:

```bash
./ares.sh discover
./ares.sh scan --config ~/.config/Claude/claude_desktop_config.json --out reporte.html
```

Correr **todos los modos en batch**: descubre los servers locales (o usa
`--config`/`--command`/`--url` para un target puntual) y los audita todos
**en paralelo**, un reporte por server:

```bash
./ares.sh full                       # discover + vet (cobertura máxima) de todo lo encontrado
./ares.sh full --mode scan --concurrency 5 --out-dir reportes/
```

También hay un dashboard web mínimo (mismo motor, progreso en vivo por
WebSocket, histórico de reportes) — guía campo por campo en [DASHBOARD.md](DASHBOARD.md):

```bash
./ares.sh serve   # http://127.0.0.1:8000
```

El scan genera dos archivos:
- `reporte.html`: reporte navegable con filtros por severidad, evidencia
  request/response de cada hallazgo, remediación sugerida, score 0-100,
  veredicto de policy (BLOCK/CONDITIONAL/ALLOW) e impacto de auth.
- `reporte.json`: mismo contenido en JSON, para integrarlo a CI/CD o a tu
  propio dashboard más adelante.
- `reporte.sarif` (con `--sarif-out`): para GitHub code scanning u otra
  herramienta de CI que consuma SARIF.

El veredicto de policy se controla con `policy.yaml` (reglas por test_id ×
ambiente `production`/`development`); editalo para ajustar qué hallazgos
bloquean un deploy en tu organización.

## Bases públicas consultadas (sin API key, sin vendors pagos)

Ares no depende de ningún servicio de terceros para operar — corre 100%
contra el MCP que estás auditando. Las únicas dos excepciones, ambas
opt-in y explícitas, consultan bases **públicas y gratuitas**, nunca Cisco
AI Defense ni Snyk (que sí usan algunas de las otras carpetas de este repo):

- **Dependencias vulnerables** (`supplychain.dependency_vulnerabilities`,
  opt-in vía `--source-path` + `--allow-network`): consulta
  [OSV.dev](https://osv.dev) (Google/OpenSSF, sin API key) detectando
  `requirements.txt` / `package.json` / `package-lock.json` bajo esa ruta.

  ```bash
  ./ares.sh scan --command python3 --args mi_servidor.py \
    --source-path ./mi_servidor --allow-network --out reporte.html
  ```

- **Patrones de secretos actualizados** (`supplychain.secret_exposure`):
  el banco de regex embebido siempre corre offline; para ampliarlo con el
  set público y mantenido de [gitleaks](https://github.com/gitleaks/gitleaks)
  (MIT, sin API key), corré explícitamente:

  ```bash
  ./ares.sh update-rules
  ```

  Esto cachea los patrones en `rules/secrets_patterns.json`. Los scans los
  usan automáticamente si el cache existe, pero ningún scan toca red por su
  cuenta para refrescarlo — el refresh es siempre una acción manual.

## Servidor de prueba (target_server.py)

Incluido un servidor MCP deliberadamente vulnerable para validar que el
motor detecta lo que dice detectar (tool poisoning en descripción, path
traversal, leak de stacktrace, SSRF, tool destructivo sin confirmación,
etc.). Úsalo como referencia/sandbox de pruebas, no en producción.

## Extender: agregar una prueba nueva

En el módulo de la categoría que corresponda (`engine/recon/tests.py`,
`engine/static/`, `engine/dynamic/`, `engine/adversarial/`):

```python
@register_test(
    id="adv.mi_prueba_nueva",
    name="Nombre legible",
    category=Category.ADVERSARIAL,
    description="Qué hace y qué detecta.",
    default_enabled=True,       # False si es intrusiva/opt-in
    requires_network=False,     # True si hace conexiones salientes reales
)
async def mi_prueba_nueva(target, ctx) -> list[Finding]:
    tools = ctx.get("tools") or await target.list_tools()
    # target.call_tool(name, args), target.read_resource(uri), etc.
    return [Finding(...)]
```

Se registra sola: aparece en `list-tests` y corre en el próximo scan.
Corré `pytest` después — el test suite (`tests/`) valida que los detectores
sigan sin falsos positivos/negativos contra los fixtures existentes.

## Resiliencia del motor contra un target hostil

No es lo mismo auditar un MCP vulnerable-pero-pasivo que uno que activamente
intenta colgar, mentirle o atacar al escáner. Confirmado empíricamente
(no solo documentado) en la ronda de hardening de 2026-10:

- **Aislamiento de proceso real** (`engine/core/sandbox.py`): `prlimit`
  (RLIMIT de memoria/CPU/procesos/FDs, verificado con `/proc/<pid>/limits`
  que los límites realmente aplican) + `bwrap` (namespaces de PID/IPC/UTS —
  el target no ve ni puede señalizar/`ptrace` al proceso de Ares ni a nada
  del host — y de red, cortada por completo salvo `--allow-network`,
  incluido loopback hacia el propio host). `--no-sandbox` para desactivarlo,
  `--sandbox-mem-mb`/`--sandbox-cpu-s`/`--sandbox-nproc`/`--sandbox-nofile`
  para ajustarlo.
- **Caps de tamaño** (`engine/core/limits.py`): una descripción de tool o una
  respuesta de varios MB no puede inflar el tiempo de análisis de forma
  desproporcionada (confirmado: sin esto, una descripción de 10MB hacía que
  un solo test tardara ~57s contra ~0.2s de baseline).
- **Circuit breaker**: tras N timeouts consecutivos (`--max-consecutive-timeouts`,
  default 3), el resto de la batería se saltea de una en vez de pagar el
  timeout completo test por test contra un target que dejó de responder.
- **Nunca un ALLOW silencioso**: un test que se cuelga genera un `Finding`
  real (`orchestrator.test_unresponsive`), no solo una línea en un log que
  nadie gatea — un target que logra resistir el análisis es, en sí mismo,
  una señal de riesgo.
- **Reset de sesión tras timeout**: la sesión (y el subprocess, si es stdio)
  que acaba de colgar un test se cierra y se reabre antes del siguiente test,
  para no arrastrar estado envenenado ni dejar un proceso hostil vivo.
- **Filesystem**: la ESCRITURA ya estaba cerrada (`--ro-bind / /` deja todo
  de solo lectura, confirmado contra el host real) pero el comentario viejo
  acá decía lo contrario -- corregido. La LECTURA general sigue abierta
  (ver Roadmap para el porqué), salvo un puñado de rutas de alto valor
  (SSH/cloud/configs de otros MCP) que se enmascaran con un canario
  sintético -- ver `engine/core/sandbox.py::credential_mask_bind_args`.

## Confiabilidad

- Cada finding trae un `confidence` (`verified`/`heuristic`) y un `risk`
  completo (CVSS + OWASP Risk Rating) — ver secciones 7 y 11 del manual.
- Test suite propio (`pytest`, corre en CI vía `.github/workflows/test.yml`)
  contra `target_server.py`/`target_server_http.py` (positivo) y
  `tests/fixtures/safe_server.py` (negativo, sin falsos positivos).
- `ares_version` estampado en cada reporte; evidencia redactada de secretos
  antes de persistir a disco.
- SSRF puede confirmarse por callback OOB real (`--oob-callback-host`, sin
  servicios de terceros) en vez de solo inferirse por patrón de respuesta.
- `--baseline reporte_anterior.json` para diffear contra un scan previo.

## Roadmap

Ordenado por impacto real, no por lo vistoso — ver la sección 12 del manual
para el detalle completo de qué se evaluó y por qué.

**Lo más importante, pendiente a propósito (no por descuido):**
- **Jail de LECTURA general para el subprocess stdio** — la escritura ya
  está cerrada (ver arriba); lo que falta es la lectura arbitraria del
  resto del filesystem. No se improvisó un allowlist general porque qué
  rutas de lectura hacen falta depende del `command`/runtime específico, y
  calcularlo mal genera falsos negativos silenciosos, peor que no tenerlo.
  Lo que SÍ se cerró, sin ese riesgo (diseño propio, no un parche): el
  enmascarado por canario sintético de las rutas de MAYOR valor conocido
  (SSH, cloud, configs de otros clientes MCP) — ver
  `engine/core/sandbox.py::credential_mask_bind_args` y el rediseño de
  `dynamic.credential_harvest_paths`, que ahora confirma por el canario
  propio de Ares en vez de depender de que el HOST donde corre el scan
  tenga secretos reales (antes: falso negativo si no los tenía, y un
  riesgo real de exfiltrar un secreto REAL del auditor si sí los tenía).

**Plataforma — decisión de alcance: por ahora Ares es Linux-only.** El
aislamiento de proceso (`prlimit` + `bwrap`) depende de Linux, y es parte de
lo que hace seguro auditar un server hostil. `ares.ps1`/`ares.bat` quedan en
el repo pero no están soportados ni probados; soportar macOS/Windows exigiría
un backend alternativo (Docker/Podman), y eso se retoma solo si cambia la decisión.

**Nivel "ya cerrado, pulido menor pendiente":**
- SAST/taint — `supplychain.source_sast` (semgrep, ruleset propio) ya cubre
  command injection/path traversal/eval-exec/deserialización insegura sobre
  el código fuente real, pero es un ruleset chico y curado a mano, no un
  motor SAST exhaustivo.
- Fuzzing de protocolo: **cubierto** por `protocol.jsonrpc_malformed_fuzz`,
  `protocol.batch_cancel_robustness` y `protocol.session_replay` (ver
  sección 12 del manual). Lo que sigue sin cubrirse: fuzzing del transporte
  SSE legado (solo stdio y streamable-http tienen canal crudo) y de la
  negociación de `protocolVersion`.
- Cadenas multi-step: **cubierto** por `adv.multistep_chain` (hasta 4 tools,
  cada eslabón probado con canario) y `adv.stored_injection_roundtrip`
  (escribe→lee). Límite real: la clasificación fuente/propagador/emisor es
  por nombre de tool; un server que nombra sus tools de forma opaca
  (`do_x`, `run_42`) no se analiza.
- Vigilancia automática: `.github/workflows/watch.yml` corre cada lunes
  `check-frameworks --verify --fail-if-stale 45` y `check-lists
  --fail-on-drift`; si algo cambió/venció, el job falla y avisa. Nada se
  actualiza solo -- decide un humano. Requiere haber commiteado
  `rules/framework_versions.json` (el baseline).
- Listas curadas: `ares check-lists` las contrasta contra OSV.dev (CVEs, con
  detección de CVEs nuevos), el repo oficial `modelcontextprotocol/servers`
  (paquetes legítimos) y gitleaks (patrones de secretos). **Siguen siendo
  manuales** las listas internas sin fuente pública verificable: el ruleset
  semgrep propio y los patrones de secretos propios (no-gitleaks).

**Ya cubierto (dejado acá para no reabrirlo sin releer esto primero):**
- Tool Shadowing cross-server (MCP09:2025) y Context Injection/Over-Sharing
  (MCP10:2025) — `crossserver.*`, `auth.resource_object_level`,
  `auth.cross_session_context_bleed`. Los 10 ítems de OWASP MCP Top 10
  tienen cobertura.
- Dashboard con gate de token opcional (`ARES_DASHBOARD_TOKEN`/`--token`) —
  no es RBAC multi-usuario, es el mínimo para no quedar abierto por
  accidente si se expone más allá de localhost.

**Fuera de alcance por diseño, no por falta de tiempo:**
- `engine/proxy/`: proxy MITM stdio/SSE para logging y bloqueo en runtime —
  es un producto distinto (gateway en línea), no un escáner.
- Empaquetado Docker (ya hay `pyproject.toml`, falta imagen de contenedor).
- RBAC/multi-usuario real para el dashboard.
