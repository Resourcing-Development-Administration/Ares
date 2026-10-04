# Manual de Ares

**Motor de pruebas de seguridad red-team para servidores MCP (Model Context
Protocol)** — 37 tests, terminal (CLI) y dashboard web, reportes HTML/JSON/SARIF.

Este documento es la referencia completa de uso. Para instalación exprés y
una descripción de una página, ver [README.md](README.md). Para cómo está
armado por dentro (árbol de archivos, flujo de datos, patrón de plugin de
test), ver [ARCHITECTURE.md](ARCHITECTURE.md).

**¿Primera vez acá?** Andá directo a la [§0 Referencia rápida](#0-referencia-rápida-qué-querés-hacer)
de abajo, o a [§3.1 Plantillas rápidas](#31-plantillas-rápidas-copiar-pegar-reemplazar-)
para copiar y pegar el comando que necesitás.

## Índice

**Empezar**
- [0. Referencia rápida — ¿qué querés hacer?](#0-referencia-rápida-qué-querés-hacer)
- [1. Conceptos básicos](#1-conceptos-básicos)
  - [1.1 Targets de práctica incluidos](#11-targets-de-práctica-incluidos)
  - [1.2 Catálogo completo de ataques/escaneos (los 37 tests)](#12-catálogo-completo-de-ataquesescaneos-los-37-tests)
- [2. Instalación](#2-instalación)

**Uso por terminal (CLI)**
- [3. Comandos](#3-uso-por-terminal-cli)
  - [3.1 Plantillas rápidas](#31-plantillas-rápidas-copiar-pegar-reemplazar-)
  - [3.2 Reducir ruido: allowlist y piso de confidence](#32-reducir-ruido-allowlist-y-piso-de-confidence)
  - [3.3 `list-tests` — qué hay para correr](#33-list-tests)
  - [3.4 `discover` — qué MCPs tengo configurados](#34-discover)
  - [3.5 `update-rules` — refrescar patrones de secretos](#35-update-rules)
  - [3.6 `scan` — el comando principal](#36-scan)
  - [3.7 `vet` — auditoría de máxima cobertura](#37-vet)
  - [3.8 `full` — varios targets en paralelo](#38-full)
  - [3.9 `serve` — levantar el dashboard web](#39-serve)
- [4. Uso por interfaz (dashboard web)](#4-uso-por-interfaz-dashboard-web)

**Guías y conceptos**
- [5. Escenarios de referencia](#5-escenarios-de-referencia)
  - [5.0 Paso a paso: probar CON auth y SIN auth](#50-paso-a-paso-probar-con-auth-y-sin-auth-las-dos-preguntas-que-importan)
- [8. Cómo leer el reporte](#8-cómo-leer-el-reporte)

**Referencia avanzada**
- [6. Mapeo a frameworks reconocidos](#6-mapeo-a-frameworks-reconocidos)
- [7. Metodología de riesgo (CVSS + OWASP Risk Rating)](#7-metodología-de-riesgo-cvss--owasp-risk-rating)
  - [7.1 AIVSS (complementario, aproximación declarada)](#71-aivss-complementario-aproximación-declarada)
- [9. Extender Ares (test nuevo)](#9-extender-ares-test-nuevo)
- [10. Qué toca red y qué no](#10-qué-toca-red-y-qué-no)
- [11. Confiabilidad del motor](#11-confiabilidad-del-motor)
- [12. Qué queda afuera de esta versión](#12-qué-queda-afuera-de-esta-versión)

---

## 0. Referencia rápida — ¿qué querés hacer?

| Quiero... | Comando / flag | Ver |
|---|---|---|
| Ver qué tests tiene Ares y cuáles corren por default | `./ares.sh list-tests` | [§3.3](#33-list-tests) |
| Encontrar MCPs ya configurados en esta máquina (Claude Desktop, Cursor, etc.) | `./ares.sh discover` | [§3.4](#34-discover) |
| Escanear un MCP propio o remoto (uso diario) | `./ares.sh scan ...` | [§3.6](#36-scan), plantillas en [§3.1](#31-plantillas-rápidas-copiar-pegar-reemplazar-) |
| Auditoría exhaustiva antes de poner un MCP en producción | `./ares.sh vet ...` | [§3.7](#37-vet) |
| Escanear varios MCPs a la vez, en paralelo | `./ares.sh full` | [§3.8](#38-full) |
| Usar una interfaz web en vez de la terminal | `./ares.sh serve` | [§3.9](#39-serve), [§4](#4-uso-por-interfaz-dashboard-web), guía campo por campo en [DASHBOARD.md](DASHBOARD.md) |
| Saber si mi autenticación protege de verdad o da lo mismo | `--compare-auth` | [§5.0](#50-paso-a-paso-probar-con-auth-y-sin-auth-las-dos-preguntas-que-importan) |
| No repetir en cada scan un hallazgo ya revisado/aceptado | `--allowlist` | [§3.2](#32-reducir-ruido-allowlist-y-piso-de-confidence) |
| Que solo lo confirmado (no lo heurístico) bloquee mi CI | `--min-confidence verified` | [§3.2](#32-reducir-ruido-allowlist-y-piso-de-confidence) |
| Comparar contra un scan anterior (¿mejoró o empeoró?) | `--baseline` | [§3.6](#36-scan) |
| Que me avisen (webhook) solo si algo empeoró | `--webhook-on-regression` | [§3.6](#36-scan), [§3.8](#38-full) |
| Mandar hallazgos a GitHub code scanning / otra CI | `--sarif-out` | [§8](#8-cómo-leer-el-reporte) |
| Chequear dependencias del código con CVEs reales | `--source-path` (`supplychain.dependency_vulnerabilities`) | [§3.6](#36-scan) |
| Auditar el código fuente del server, no solo el protocolo | `--source-path` + `semgrep` (`supplychain.source_sast`) | [§3.6](#36-scan), [§2](#2-instalación) |
| Ver si un agente real obedece una inyección (no solo si el server la refleja) | `adv.live_agent_injection` | [§3.6](#36-scan) |
| Detectar tools que se hacen pasar por otro server conectado | correlación cross-server (automática en `full`, 2+ targets) | [§3.8](#38-full) |
| Ver en vivo cada llamada real a los tools, no solo el resumen por test | `--verbose` | [§3.6](#36-scan) |
| Entender de dónde sale la severidad de un hallazgo | — | [§7](#7-metodología-de-riesgo-cvss--owasp-risk-rating) |
| Agregar un test propio a Ares | — | [§9](#9-extender-ares-test-nuevo) |
| Saber exactamente qué toca red y qué no | — | [§10](#10-qué-toca-red-y-qué-no) |

---

## 1. Conceptos básicos

- **Categoría de test**: `recon`, `static`, `dynamic`, `adversarial`, `auth`,
  `exposure`, `supplychain`. Cada una vive en `engine/<categoria>/tests.py`.
  37 tests en total, incluyendo ataques específicos de MCP documentados en
  2026: **Line Jumping** (`recon.suspicious_descriptions` escanea también las
  descripciones de PARÁMETROS, no solo la del tool — ATR-2026-00579),
  **Rug Pull** (`adv.rug_pull`, compara definiciones de tools por hash contra
  `--baseline` para detectar cambios post-aprobación), **falta de
  audit/telemetría** (`recon.audit_logging`, OWASP MCP08:2025), **BOLA con
  sesión autenticada real** (`auth.authz_object_level`, OWASP API1:2023 —
  no solo "¿tiene token?", sino "¿ese token puede ver objetos de otro
  usuario?"), **seguridad de OAuth 2.1/RFC 9728** (`auth.oauth_metadata_security`
  — el mecanismo de auth real que adoptó el spec de MCP), y **entropía del
  session ID** (`exposure.session_id_entropy`).
- **Modo autenticado vs sin autenticar**: `auth.unauthenticated_access` y
  `--compare-auth` cubren "¿qué puede hacer alguien SIN ninguna credencial?";
  `auth.authz_object_level` cubre "¿qué puede hacer alguien CON una
  credencial válida pero de bajo privilegio?" (autorización, no solo
  autenticación) — las dos preguntas que hacen falta para decidir si un MCP
  es seguro de implementar, no una sola.
- **Test**: función async registrada con `@register_test(id=..., ...)`. Un
  test produce una lista de `Finding`. `./ares.sh list-tests` los
  lista todos con su id, categoría, si corre por default y si toca red externa.
- **Finding**: un resultado. `passed=True` = no hay problema; `passed=False` =
  hallazgo confirmado (esto es lo que cuenta para el score/policy).
- **Score**: 0-100 + grade A-F, calculado por severidad de los hallazgos
  confirmados (`engine/reporting/scoring.py`).
- **Policy verdict**: `BLOCK` / `CONDITIONAL` / `ALLOW`, calculado contra
  `policy.yaml` para un `--environment` dado (`production` o `development`).
  Pensado para gating de CI: si es `BLOCK`, el server no es apto tal como
  está para ese ambiente.
- **Auth impact** (solo con `--compare-auth`): compara la corrida con y sin
  credenciales, y separa los hallazgos en "mitigados por auth" (desaparecen
  al autenticarse) vs "NO mitigados por auth" (persisten igual).
- **Confidence**: `verified` (hecho observado directamente: canario ejecutado,
  callback OOB recibido, CVE real en OSV.dev) o `heuristic` (regex/keyword/
  similitud — señal a revisar, no prueba). Ver `engine/core/confidence.py` y
  la sección 10.
- **Baseline diff** (solo con `--baseline`): compara contra un `reporte.json`
  anterior y separa hallazgos nuevos / resueltos / persistentes.
- **Suprimido** (`--allowlist`/`--min-confidence`, ver sección 3.2): un
  finding suprimido **nunca se borra ni se oculta** del reporte — sigue
  visible, marcado, auditable — pero deja de contar para score/policy/CI.
  Dos motivos: allowlist explícita (`.ares_allowlist.yml`, algo ya revisado
  y aceptado) o piso de confidence (`--min-confidence verified`, descarta lo
  heurístico del gate automatizado sin descartarlo del reporte).
- **Correlación cross-server** (solo `full` con 2+ targets, ver sección 3.8):
  todo lo demás en Ares audita UN server a la vez; esto mira el CONJUNTO —
  Tool Shadowing (MCP09:2025, un tool de un server colisiona o referencia
  directivamente a un tool de OTRO server conectado) y cadenas de
  exfiltración que cruzan servers distintos, invisibles para cualquier scan
  de un solo target.
- **Reportes**: cada scan produce HTML navegable + JSON + (opcional) SARIF,
  con la versión de Ares que lo generó (`ares_version`) y la evidencia cruda
  redactada de secretos antes de guardarse a disco.

### 1.1 Targets de práctica incluidos

Ares trae dos servidores MCP deliberadamente vulnerables para practicar sin
necesitar un target real:

- `target_server.py` — vía stdio (`--command python3 --args target_server.py`).
- `target_server_http.py` — vía streamable-http **sin autenticación**, en
  `http://127.0.0.1:8765/mcp` (`python target_server_http.py` en otra
  terminal, luego `--transport http --url http://127.0.0.1:8765/mcp`). Es el
  que conviene usar para probar `auth.*`, `exposure.*` y `--compare-auth`.

Ninguno de los dos debe usarse en producción — están armados a propósito
para que casi todos los tests disparen.

### 1.2 Catálogo completo de ataques/escaneos (los 37 tests)

Extraído en vivo de `./ares.sh list-tests` (siempre la fuente de verdad — si
corriste `list-tests` y ves algo distinto a esta tabla, confiá en la CLI, no
en este manual). ✅ = corre por default en `scan`/`vet`; ❌ = opt-in, hay que
pedirlo con `--tests` o correr `vet` (que los incluye a todos). 🌐 = hace
conexiones de red reales, requiere `--allow-network`. `verified`/`heuristic`
= confidence default de esa categoría de test (ver sección 1, y sección 7
para cómo se calcula el riesgo).

**`recon` — reconocimiento pasivo, no envía payloads:**

| Test | Qué hace | Default | Red | Confidence |
|---|---|:-:|:-:|:-:|
| `recon.enumerate` | Enumera tools/resources/prompts — la base para todos los demás tests | ✅ | | verified |
| `recon.suspicious_descriptions` | Tool poisoning y **line jumping**: busca instrucciones ocultas dirigidas al modelo en descripciones de tools Y de parámetros, más caracteres Unicode invisibles | ✅ | | heuristic |
| `recon.excessive_permissions` | Detecta tools cuyo nombre/descripción sugiere capacidades muy amplias (shell, SQL, filesystem) sin sandboxing aparente | ✅ | | heuristic |
| `recon.audit_logging` | ¿El server declara el capability `logging` del protocolo? Sin esto no hay rastro server-side de qué se invocó (OWASP MCP08:2025) | ✅ | | verified |

**`static` — análisis de la definición (JSON Schema), sin ejecutar nada:**

| Test | Qué hace | Default | Red | Confidence |
|---|---|:-:|:-:|:-:|
| `static.schema_permissive` | Parámetros sin tipo/enum/pattern/maxLength, o `additionalProperties: true` | ✅ | | verified |
| `static.no_schema` | Tools que no publican ningún `input_schema` útil | ✅ | | verified |
| `static.known_cve_check` | Compara `serverInfo.name/version` (autoreportado en `initialize`) contra un feed curado de CVEs reales de servers MCP oficiales (ver `engine/static/known_cves.py`) | ✅ | | heuristic |
| `static.typosquatting_check` | Requiere `--package-name`: similitud Jaro-Winkler (umbral 0.88) contra paquetes MCP oficiales conocidos — ¿`mcp-server-fetchh` en vez de `mcp-server-fetch`? | ❌ | | heuristic |

**`dynamic` — caja negra, ejecuta llamadas reales con inputs adversariales:**

| Test | Qué hace | Default | Red | Confidence |
|---|---|:-:|:-:|:-:|
| `dynamic.fuzz_tools` | Fuzzing edge-case por tool (tipos inválidos, overflow, unicode raro) — detecta crashes y leaks de stacktrace/paths | ✅ | | verified |
| `dynamic.fuzz_resources` | Igual que arriba pero contra URIs de resources (estáticos y **resource templates**, ej. `file:///{path}`) | ✅ | | verified |
| `dynamic.command_injection_confirmed` | Canario aleatorio en payloads de shell (`; echo`, backticks, PowerShell, etc.) — **confirma ejecución real**, no solo reflejo | ✅ | | verified |
| `dynamic.path_traversal_confirmed` | Payloads de traversal, confirma leyendo contenido real de `/etc/passwd` | ✅ | | verified |
| `dynamic.credential_harvest_paths` | Traversal dirigido a rutas de alto valor real (claves SSH, credenciales AWS/GCP/Azure, `.netrc`, configs de clientes MCP) — confirma por firma de contenido, no por inferencia | ✅ | | verified |
| `dynamic.rate_limit` | Ráfaga de 50 llamadas concurrentes — ¿hay throttling? | ❌ | | verified |

**`adversarial` — simula intención real de atacante:**

| Test | Qué hace | Default | Red | Confidence |
|---|---|:-:|:-:|:-:|
| `adv.injection_passthrough` | ¿Un tool almacena/refleja intacto un payload de prompt injection para que otro tool lo reconsuma? | ✅ | | heuristic |
| `adv.confused_deputy` | Tools "de lectura" que aceptan parámetros con alcance más amplio del esperado | ✅ | | heuristic |
| `adv.destructive_no_confirmation` | Tools destructivos (`delete`/`drop`/`wipe`) sin parámetro `confirm`/`dry_run` en el schema | ✅ | | verified |
| `adv.rug_pull` | Compara hash de descripción+schema contra `--baseline` — ¿el tool cambió de definición desde la última corrida? | ✅ | | verified |
| `adv.ssrf_exfil` | Prueba SSRF contra metadata endpoints (AWS/GCP/Azure/Alibaba/Oracle/DigitalOcean/K8s) + callback OOB opcional | ❌ | 🌐 | heuristic (→ verified con `--oob-callback-host`) |
| `adv.live_agent_injection` | Agente real (Anthropic/OpenAI/Ollama, ver `--live-agent-provider`) en el loop: ¿intenta ejecutar la acción que un payload inyectado le ordenó? | ❌ | 🌐 | heuristic (confirmado → verified) |
| `adv.stateful_chain_exfil` | **Multi-step, ejecuta la cadena real**: llama al tool lector, pasa un canario sintético al tool emisor — a diferencia de `supplychain.exfiltration_chain` (heurístico, solo coexistencia), esto CONFIRMA que el emisor acepta el dato sin validar procedencia | ❌ | | verified |

**`auth` — autenticación y autorización (solo http/sse salvo aclaración):**

| Test | Qué hace | Default | Red | Confidence |
|---|---|:-:|:-:|:-:|
| `auth.unauthenticated_access` | ¿El server responde sin ninguna credencial? La pregunta "atacante externo" | ✅ | | verified |
| `auth.weak_credentials` | Wordlist de tokens comunes (`test`, `admin`, `password`...) como Bearer | ❌ | | verified |
| `auth.authz_object_level` | **BOLA**: con la sesión actual, fuzzea parámetros tipo id — ¿devuelve datos de OTRO objeto/usuario? La pregunta "usuario autenticado de bajo privilegio" | ❌ | | heuristic |
| `auth.resource_object_level` | Mismo patrón que `auth.authz_object_level` pero sobre `resources/read` (placeholders `{id}`/`{user_id}` de resource templates) en vez de tools — MCP10:2025 parcial | ❌ | | heuristic |
| `auth.oauth_metadata_security` | Valida la cadena RFC 9728 (`WWW-Authenticate` → metadata → authorization server → PKCE) | ✅ | | verified |
| `auth.cross_session_context_bleed` | Requiere `--auth-token-b` (una segunda credencial/tenant): planta un canario de doble marcador con la sesión primaria y confirma si se filtra a una sesión NUEVA abierta con la segunda credencial, sin que nadie se lo haya dado ahí — MCP10:2025, por ejecución real | ❌ | | verified |

**`exposure` — superficie de red (solo http/sse):**

| Test | Qué hace | Default | Red | Confidence |
|---|---|:-:|:-:|:-:|
| `exposure.transport_security` | ¿El endpoint corre en `http://` plano en vez de `https://`? | ✅ | | verified |
| `exposure.cors_misconfig` | Preflight con Origin hostil — ¿wildcard o reflejo dinámico? | ✅ | | verified |
| `exposure.network_reachability` | Clasifica el host resuelto: IP privada (interno) vs pública (Internet) | ✅ | | verified |
| `exposure.session_id_entropy` | Entropía de Shannon del `Mcp-Session-Id` — ¿es adivinable/fuerza-bruteable? | ✅ | | verified |

**`supplychain` — secretos, dependencias, integridad de tools:**

| Test | Qué hace | Default | Red | Confidence |
|---|---|:-:|:-:|:-:|
| `supplychain.secret_exposure` | Banco de regex (API keys, DB URLs, private keys) sobre descripciones/schemas | ✅ | | heuristic |
| `supplychain.tool_squatting` | Similitud Jaro-Winkler entre nombres de tools (umbral 0.82) — typo-squatting/confused deputy | ✅ | | heuristic |
| `supplychain.exfiltration_chain` | ¿Coexisten tools "lectoras" (archivos/secretos) y "emisoras" (webhooks/email)? | ✅ | | heuristic |
| `supplychain.malicious_patterns` | Regex por categoría (tool poisoning, code exec, credential harvesting, exfiltración) tipo YARA | ✅ | | heuristic |
| `supplychain.dependency_vulnerabilities` | Requiere `--source-path`: detecta manifiestos y consulta CVEs reales en OSV.dev | ❌ | 🌐 | verified |
| `supplychain.source_sast` | Requiere `--source-path` + `semgrep` instalado: ruleset propio taint-aware (`rules/semgrep_mcp.yml`) — sigue el dato desde el parámetro de un tool MCP hasta un sink peligroso (shell, eval/exec, deserialización insegura) en el CÓDIGO FUENTE real, no solo la superficie del protocolo | ❌ | | verified |

**`crossserver` — correlación entre 2+ targets (solo modo `full`, no corre vía `--tests`):**

No están en `./ares.sh list-tests` (no son `@register_test` — la correlación
es N-a-N entre targets, no "un test sobre un target", ver sección 6 de
ARCHITECTURE.md) pero producen `Finding` reales con el mismo score/policy/
SARIF que cualquier otro, desde que se corrigió ese gap — ver sección 12.

| Test | Qué hace | Confidence |
|---|---|:-:|
| `crossserver.tool_shadowing` | Nombre idéntico/casi-idéntico entre tools de servers DISTINTOS, o descripción con lenguaje directivo ("usar X en vez de") que referencia un tool de OTRO server conectado — MCP09:2025 | heuristic |
| `crossserver.exfiltration_chain` | Tool lector en el server A + tool emisor en el server B, conectados en la misma sesión — invisible para `supplychain.exfiltration_chain` (solo mira dentro de un mismo server) — MCP09:2025/MCP10:2025 | heuristic |

## 2. Instalación

### 2.0 La forma más simple: `ares.sh`

```bash
cd Ares
./ares.sh list-tests
```

`ares.sh` es el punto de entrada único: la primera vez que lo corrés crea
`.venv`, instala todas las dependencias (`pip install -e .`) y recién
después ejecuta el subcomando pedido. En corridas siguientes, si
`pyproject.toml`/`requirements.txt` no cambiaron, salta directo a ejecutar
(no reinstala nada) — y si sí cambiaron, reinstala automáticamente antes de
correr. No hace falta activar el venv a mano nunca. Funciona desde cualquier
directorio (`/ruta/a/Ares/ares.sh scan ...`) y con symlinks.

Todos los ejemplos de este manual usan `./ares.sh <subcomando>`; son
intercambiables 1:1 con `python cli/main.py <subcomando>` si preferís
activar el venv vos mismo (sección 2.1) o con `ares <subcomando>` si
instalaste el paquete.

Variables de entorno que `ares.sh` respeta:
- `ARES_PYTHON=/ruta/a/python3.11+` — si tu `python3` del PATH es más viejo
  que 3.11 (`update-rules` usa `tomllib` de la stdlib).

### 2.0b Windows: `ares.ps1` / `ares.bat`

Mismo entry point, mismo comportamiento (crea `.venv`, instala dependencias
solo si cambiaron, delega a `cli\main.py`) — `ares.sh` es bash puro y no
corre nativamente en Windows, así que hay un equivalente en PowerShell:

```powershell
cd Ares
.\ares.ps1 list-tests
```

Si PowerShell bloquea el script por la política de ejecución (mensaje tipo
*"no se puede cargar porque la ejecución de scripts está deshabilitada"*),
una sola vez, como usuario (no hace falta administrador):

```powershell
Set-ExecutionPolicy -Scope CurrentUser RemoteSigned
```

o invocá ese script puntual sin tocar la política global:

```powershell
powershell -ExecutionPolicy Bypass -File .\ares.ps1 list-tests
```

Para quien prefiera `cmd.exe` o doble-click en vez de PowerShell, `ares.bat`
es un forwarder delgado a `ares.ps1` que ya hace ese bypass por sí mismo:

```bat
ares.bat list-tests
```

`$env:ARES_PYTHON` es el equivalente de `ARES_PYTHON` para Windows (misma
semántica: ruta a un `python.exe` 3.11+ si el que resuelve `py`/`python` en
el PATH es más viejo).

Alternativa sin PowerShell: instalar como paquete (`pip install -e .`) te
da un `ares.exe` real en `.venv\Scripts\` — ver sección 2.1 más abajo.

**Aislamiento de proceso (`engine/core/sandbox.py`) es Linux-only.**
`prlimit` (util-linux) y `bwrap` (bubblewrap) no existen en Windows — el
subprocess stdio del target corre sin el RLIMIT de memoria/CPU/procesos/FDs
ni los namespaces de PID/IPC/red que sí aplican en Linux. Ares lo detecta y
lo deja como error informativo en cada scan (nunca un fallo silencioso),
pero la mitigación real contra un target activamente hostil hoy depende de
Linux. Ver "Resiliencia del motor" en el [README](README.md) y la sección
12 de este manual.

### 2.1 Instalación manual (equivalente, más control)

```bash
cd Ares
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
```

En Windows (PowerShell), el equivalente es:

```powershell
cd Ares
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

Requiere Python 3.11+.

O como paquete instalable (`pyproject.toml`), que además te da el comando
`ares` en el PATH en vez de `./ares.sh`:

```bash
pip install -e ".[dev]"   # [dev] agrega pytest, para correr el test suite
ares list-tests
ares scan --command python3 --args target_server.py
```

**En Windows, esto es lo más parecido a "un ejecutable"**: `pip install -e .`
(o `pip install -e ".[dev]"`) genera un `ares.exe` real dentro de
`.venv\Scripts\` — un ejecutable nativo de Windows, sin PowerShell, sin
`ExecutionPolicy`, sin depender de `ares.ps1`/`ares.bat`. Sigue necesitando
Python instalado (no es un binario standalone que empaquete el intérprete
entero — eso sería un build con PyInstaller, que no está armado hoy porque
requiere compilarse y probarse en un Windows real, algo que no se puede
verificar desde este entorno de desarrollo). Con el venv activado
(`.venv\Scripts\Activate.ps1`) o llamando directo a
`.venv\Scripts\ares.exe`, queda disponible:

```powershell
.venv\Scripts\ares.exe list-tests
.venv\Scripts\ares.exe scan --command python --args target_server.py
```

Extras opcionales, cada uno solo si vas a usar ese test puntual:

| Extra | Habilita | Instalación |
|---|---|---|
| `[live-agent]` | `adv.live_agent_injection` con Anthropic (OpenAI/Ollama usan `httpx`, ya core dep, sin paquete extra) | `pip install -e ".[live-agent]"` |
| `[sast]` | `supplychain.source_sast` (semgrep) | `pip install -e ".[sast]"` — paquete pesado, no se instala por default |

## 3. Uso por terminal (CLI)

Todos los comandos se corren desde la carpeta `Ares/`:
`./ares.sh <subcomando> [flags]` (recomendado, no requiere activar el venv)
o `python cli/main.py <subcomando> [flags]` con el venv ya activado a mano.

### 3.1 Plantillas rápidas (copiar, pegar, reemplazar `<...>`)

Estas cuatro plantillas cubren el 90% de los casos: MCP propio local, MCP
remoto sin auth, MCP remoto con auth Bearer, y MCP remoto con auth por API
key / header custom. Sirven igual para `scan`, `vet` y `full` (mismos flags
de target/auth en los tres). `<PLACEHOLDER>` = reemplazar por tu valor real;
lo que no lleva `<>` se copia literal.

```bash
# 1) Servidor MCP propio/local, vía stdio (lo más común para desarrollo)
./ares.sh scan --command <COMANDO> --args "<ARGUMENTOS>" --out reporte.html
# ej: ./ares.sh scan --command python3 --args "mi_servidor.py" --out reporte.html
# ej: ./ares.sh scan --command node --args "servidor.js --puerto 3000" --out reporte.html

# 2) Servidor MCP remoto, SIN autenticación (la pregunta "atacante externo")
./ares.sh scan --transport http --url <URL> --out reporte.html
# ej: ./ares.sh scan --transport http --url http://127.0.0.1:8765/mcp --out reporte.html
# ej: ./ares.sh scan --transport http --url https://mcp.miempresa.com/mcp --out reporte.html

# 3) Servidor MCP remoto, CON autenticación Bearer (el caso más común de auth)
./ares.sh scan --transport http --url <URL> \
  --auth-token "<TOKEN>" --auth-type bearer --out reporte.html
# ej: ./ares.sh scan --transport http --url https://mcp.miempresa.com/mcp \
#       --auth-token "$MI_TOKEN" --auth-type bearer --out reporte.html

# 4) Servidor MCP remoto, CON autenticación por API key / header custom (no Bearer)
./ares.sh scan --transport http --url <URL> \
  --auth-token "<TOKEN>" --auth-type apikey --auth-header-name "<NOMBRE_DEL_HEADER>" \
  --out reporte.html
# ej: ./ares.sh scan --transport http --url https://mcp.miempresa.com/mcp \
#       --auth-token "$MI_API_KEY" --auth-type apikey --auth-header-name "X-API-Key" \
#       --out reporte.html
```

`--transport` puede ser `stdio` (default, para `--command`), `http` o `sse`
(para `--url`) — no se combinan: stdio usa `--command`/`--args`, http/sse
usa `--url`. Si el server exige un header no estándar sin usar el mecanismo
de `--auth-token` (ej. una cookie de sesión), usá `--header "Clave: Valor"`
(repetible) en vez de `--auth-token`.

**Con o sin URL, con o sin auth, en una tabla:**

| Tengo... | Flags de target | Flags de auth |
|---|---|---|
| Un server MCP propio que arranco yo (stdio) | `--command <COMANDO> --args "<ARGS>"` | ninguno (no aplica a stdio) |
| Una URL de MCP remoto SIN credenciales | `--transport http --url <URL>` | ninguno |
| Una URL de MCP remoto con Bearer token | `--transport http --url <URL>` | `--auth-token "<TOKEN>" --auth-type bearer` |
| Una URL de MCP remoto con API key en header | `--transport http --url <URL>` | `--auth-token "<TOKEN>" --auth-type apikey --auth-header-name "<HEADER>"` |
| Una URL de MCP remoto con header/cookie propietario | `--transport http --url <URL>` | `--header "Cookie: sesion=<VALOR>"` (repetible) |
| Quiero saber si la auth protege de verdad | (cualquiera de arriba con auth) | agregar `--compare-auth` — corre con y sin credenciales, ver [sección 5.0](#50-paso-a-paso-probar-con-auth-y-sin-auth-las-dos-preguntas-que-importan) |

### 3.2 Reducir ruido: allowlist y piso de confidence

Disponibles en `scan`/`vet`/`full`. Ninguno de los dos borra ni oculta un
finding — lo marcan `suppressed` (visible en el reporte, con la razón) y eso
es lo único que lo saca de score/policy/CI. Pensado para no re-litigar en
cada scan algo que el equipo ya revisó, y para que categorías heurísticas
no ahoguen un gate automatizado en falsos positivos.

```bash
# Copiar el ejemplo, editar las entries, y Ares lo auto-detecta sin flags:
cp .ares_allowlist.example.yml .ares_allowlist.yml

# O una ruta explícita (útil en CI, donde el cwd puede no ser el repo):
./ares.sh scan --command <COMANDO> --args "<ARGS>" --allowlist ./ci/allowlist.yml

# Solo lo 'verified' (hecho observado directamente) gatea CI; lo heurístico
# queda en el reporte pero no bloquea el build:
./ares.sh scan --transport http --url <URL> --min-confidence verified
```

`.ares_allowlist.yml` (ver `.ares_allowlist.example.yml` en la raíz del
proyecto para el formato completo):

```yaml
entries:
  - test_id: supplychain.tool_squatting
    target: "read_file,read_note"   # omitir 'target' = aplica a CUALQUIER target de ese test_id
    reason: "Nombres similares por diseño; aprobado por plataforma el 2026-09-20."
  - test_id: "adv.confused_deputy*"  # wildcard, igual estilo que policy.yaml
    reason: "Aceptado temporalmente, ticket SEC-482."
```

| Flag | Uso |
|---|---|
| `--allowlist <RUTA>` | ruta a un `.ares_allowlist.yml`; sin esto, se auto-detecta uno en el directorio actual si existe |
| `--min-confidence {heuristic,verified}` | default `heuristic` (todo cuenta); `verified` sube el piso — solo hechos observados directamente gatean score/policy |

### 3.3 `list-tests`

**Qué hace**: lista todos los tests disponibles (id, categoría, si corren
por default, y si tocan red externa real). No se conecta a ningún MCP —
solo lee el registro interno de tests (`engine/core/registry.py`).
**Salida**: solo terminal (tabla), no genera ningún archivo.

```bash
./ares.sh list-tests
```

### 3.4 `discover`

**Qué hace**: busca configs de clientes MCP conocidos en esta máquina
(Claude Desktop, Claude Code, Cursor, VSCode, Windsurf, Codex) y lista los
servers que tienen declarados (nombre, comando/URL, config de origen), sin
conectarse ni escanear nada todavía. Es el paso previo típico a `scan
--config` o a `full` sin argumentos.
**Salida**: solo terminal (tabla), no genera ningún archivo.

```bash
./ares.sh discover
```

### 3.5 `update-rules`

**Qué hace**: refresca el cache local de patrones de detección de secretos
consultando [gitleaks](https://github.com/gitleaks/gitleaks) (proyecto
público OSS, sin API key — nunca Cisco AI Defense ni Snyk). No escanea
ningún MCP, solo actualiza el banco de reglas.
**Salida**: escribe/sobreescribe `rules/secrets_patterns.json` (archivo, no
hay equivalente "solo terminal" porque su único propósito es persistir el
cache); los scans lo usan automáticamente si existe. Es la única acción de
Ares que toca red "para actualizarse a sí misma", y es siempre manual —
ningún scan la dispara solo.

```bash
./ares.sh update-rules
```

**Comando hermano, `check-frameworks`**: a diferencia de `update-rules`
(que descarga y APLICA patrones de secretos), `check-frameworks` solo AVISA
si OWASP MCP/LLM/API Top 10 o MITRE ATLAS cambiaron de versión públicamente
desde el último check — nunca actualiza ni mapeos ni tests solo, porque un
Top 10 nuevo puede implicar escribir un test, no solo refrescar un JSON. Ver
`engine/core/framework_watch.py`.

```bash
./ares.sh check-frameworks          # avisa si hay novedades, no toca el cache
./ares.sh check-frameworks --ack    # acepta el estado actual como nuevo baseline
```

### 3.6 `scan`

**Qué hace**: se conecta al MCP indicado, enumera su superficie (tools/
resources/prompts) y corre los tests seleccionados (o todos los
`default_enabled` si no se especifica `--tests`) contra esa superficie.
Es el comando de uso diario; para auditoría exhaustiva antes de producción
ver [`vet`](#37-vet), para correr contra varios targets a la vez ver
[`full`](#38-full).

Flags por grupo:

**Target (uno de los dos, ver también [plantillas de la sección 3.1](#31-plantillas-rápidas-copiar-pegar-reemplazar-)):**

| Flag | Uso |
|---|---|
| `--transport {stdio,sse,http}` | default `stdio` |
| `--command <COMANDO> --args "<ARGS>"` | para `--transport stdio`, ej. `--command python3 --args "mi_servidor.py"` |
| `--url <URL>` | para `--transport sse\|http`, ej. `--url https://mcp.miempresa.com/mcp` |
| `--config <RUTA>` | ignora lo anterior: lee un JSON estilo Claude Desktop (`mcpServers`) y escanea **todos** sus servers en batch, un reporte por cada uno |
| `--name <NOMBRE>` | nombre a mostrar (opcional) |

**Selección de tests:**

| Flag | Uso |
|---|---|
| `--tests id1,id2,...` | vacío = todos los `default_enabled` |
| `--max-fuzz-cases N` | casos de fuzzing por tool (default 25) |
| `--allow-network` | habilita tests marcados `requires_network` (SSRF real, `supplychain.dependency_vulnerabilities` contra OSV.dev, `adv.live_agent_injection`) |
| `--source-path RUTA` | ruta local al código del server, para `supplychain.dependency_vulnerabilities` y `supplychain.source_sast` (busca `requirements.txt`/`package.json`/`package-lock.json`, y corre semgrep si está instalado) |
| `--package-name "<NOMBRE>"` | nombre de paquete declarado (npm/pypi), para `static.typosquatting_check`, ej. `"mcp-server-fetch"` |
| `--request-delay-ms N` | pausa entre llamadas a tools; subilo si el target es sensible/productivo |
| `--test-timeout-s N` | segundos máximos por test antes de cortarlo y seguir con el resto (default 60) — fail-closed: un test colgado nunca cuelga el scan entero |
| `--verbose` | imprime en vivo cada llamada real (`list_tools`/`call_tool`/`read_resource`) con su request/response (truncados) y tiempo, no solo el resumen agregado al final de cada test — en `full`, cada línea sale con el prefijo `[nombre-del-target]` |
| `--oob-callback-host HOST:PUERTO` | levanta un listener local propio (sin servicios de terceros) alcanzable por el target, para que `adv.ssrf_exfil` confirme SSRF por callback real en vez de solo inferirlo — el finding sale con `confidence: verified` |

**Auth (solo sse/http) — ver también la tabla "con o sin auth" de la sección 3.1:**

| Flag | Uso |
|---|---|
| `--header "Clave: Valor"` | repetible, header HTTP crudo (cookies, headers propietarios no cubiertos por `--auth-token`) |
| `--auth-token "<TOKEN>"` | credencial a inyectar |
| `--auth-type {bearer,apikey,custom}` | default `bearer`. `bearer` → header `Authorization: Bearer <TOKEN>`; `apikey`/`custom` → header `--auth-header-name` con el token crudo |
| `--auth-header-name "<NOMBRE>"` | requerido con `apikey`/`custom`, ej `X-API-Key` |
| `--compare-auth` | corre el scan dos veces (con y sin `--auth-token`/headers) y agrega la sección de impacto de auth: qué hallazgos desaparecen al autenticarse vs cuáles persisten igual |
| `--auth-token-b "<TOKEN>"` (+ `--auth-type-b`/`--auth-header-name-b`, misma semántica que los de arriba) | una SEGUNDA credencial/tenant válido, independiente de `--auth-token` — habilita `auth.cross_session_context_bleed` (sección 12): sin esto, ese test se saltea solo |

**Policy / salida — cómo ver el resultado (archivo, terminal, o ambos):**

| Flag | Uso |
|---|---|
| `--environment {production,development}` | default `production`, usado por `policy.yaml` para el veredicto BLOCK/CONDITIONAL/ALLOW |
| `--out reporte.html` | escribe `reporte.html` navegable **y** `reporte.json` (mismo contenido estructurado) al lado. Comportamiento por default. |
| `--sarif-out reporte.sarif` | export adicional en SARIF 2.1.0, para GitHub code scanning u otra herramienta de CI |
| `--print` | **además** de los archivos de arriba, imprime en la terminal una tabla con cada hallazgo confirmado (severidad, confidence, test id, target, título, remediación) — para ver el resultado sin abrir el `.html` |
| `--no-file` | **no** escribe ningún archivo — el único resultado es la tabla de hallazgos en terminal (implica `--print`). Útil para chequeos rápidos o cuando estás corriendo Ares desde otro script y no te interesa persistir nada |
| `--baseline reporte_anterior.json` | agrega al reporte qué hallazgos son nuevos/resueltos/persisten desde esa corrida previa |
| `--webhook-on-regression <URL>` | requiere `--baseline`: si aparecen hallazgos NUEVOS respecto al baseline, hace **un solo** POST JSON a esa URL (nunca si no hay regresión, nunca uno por finding) — payload liviano (`test_id`/`severity`/`target`/`title`, nunca evidencia cruda). Pensado para correrlo desde un cron/systemd timer del SO — Ares no reinventa scheduling propio |
| `--allowlist <RUTA>` / `--min-confidence {heuristic,verified}` | ver [sección 3.2](#32-reducir-ruido-allowlist-y-piso-de-confidence) |
| `--live-agent-provider {auto,anthropic,openai,ollama,all}` | proveedor(es) para `adv.live_agent_injection`. `auto` (default) = el primero con credencial disponible; `all` = corre contra todos los disponibles (comparación cross-model real) |

Por default (sin `--print` ni `--no-file`) el detalle completo por hallazgo
solo está en `reporte.html`/`.json`; la terminal solo muestra el progreso
test-por-test y el resumen agregado (score, conteo por severidad, veredicto
de policy) — agregá `--print` si además querés el detalle línea por línea
ahí mismo.

**Ejemplos:**

```bash
# Scan local básico, todos los tests default
./ares.sh scan --command python3 --args target_server.py

# Solo algunos tests
./ares.sh scan --command python3 --args target_server.py \
  --tests recon.enumerate,dynamic.command_injection_confirmed,supplychain.secret_exposure

# Server remoto HTTP SIN auth
./ares.sh scan --transport http --url <URL> --out reporte.html

# Server remoto HTTP CON auth (Bearer) + comparación + veredicto de CI + SARIF
./ares.sh scan --transport http --url <URL> \
  --auth-token "<TOKEN>" --auth-type bearer \
  --compare-auth --environment production \
  --sarif-out reporte.sarif --out reporte.html

# Server remoto HTTP CON auth por API key / header custom
./ares.sh scan --transport http --url <URL> \
  --auth-token "<TOKEN>" --auth-type apikey --auth-header-name "X-API-Key" --out reporte.html

# Solo terminal, sin escribir nada a disco (chequeo rápido)
./ares.sh scan --command python3 --args target_server.py --no-file

# Archivo Y terminal a la vez (default es solo archivo; --print agrega la tabla en pantalla)
./ares.sh scan --transport http --url <URL> --out reporte.html --print

# Verbose: ver cada llamada real a los tools mientras corre, para debuguear qué está pasando
./ares.sh scan --transport http --url <URL> --no-file --verbose

# Dependencias vulnerables vía OSV.dev (pública, sin API key)
./ares.sh scan --command python3 --args mi_servidor.py \
  --source-path ./mi_servidor --allow-network --out reporte.html

# Batch: todos los servers de un config de Claude Desktop
./ares.sh scan --config ~/.config/Claude/claude_desktop_config.json --out reporte.html

# Confirmar SSRF por callback OOB real (necesitás que el target pueda alcanzar tu host:puerto)
./ares.sh scan --transport http --url <URL> \
  --tests adv.ssrf_exfil --allow-network --oob-callback-host 203.0.113.10:8899

# Target sensible/productivo: bajale el ritmo
./ares.sh scan --transport http --url <URL> --request-delay-ms 250

# Live-agent testing: ¿el agente real obedece la inyección? (opt-in, gasta cuota de tu API key)
export ANTHROPIC_API_KEY=sk-ant-...
./ares.sh scan --command python3 --args mi_servidor.py \
  --tests adv.live_agent_injection --allow-network

# Comparar contra el scan de la semana pasada
./ares.sh scan --command python3 --args mi_servidor.py \
  --baseline reporte_semana_pasada.json --out reporte.html
```

### 3.7 `vet`

**Qué hace**: auditoría de **máxima cobertura**, pensada para el gate
"¿implemento este MCP en mi operación o no?". A diferencia de `scan`, corre
**todos** los tests registrados (incluidos los opt-in: `dynamic.rate_limit`,
`auth.weak_credentials`, `adv.ssrf_exfil`, `adv.stateful_chain_exfil`,
`supplychain.dependency_vulnerabilities`, `supplychain.source_sast` (si diste
`--source-path` y tenés `semgrep` instalado), `adv.live_agent_injection`), con
`--allow-network` y `--environment production` forzados, `--compare-auth`
automático si das `--auth-token`, `--max-fuzz-cases` más alto (50 por
default), y SARIF siempre. Mismos flags de target/auth/reducción-de-ruido que
`scan` (ver [plantillas de la sección 3.1](#31-plantillas-rápidas-copiar-pegar-reemplazar-)
y [3.2](#32-reducir-ruido-allowlist-y-piso-de-confidence)) — incluido
`--webhook-on-regression` si además das `--baseline`.

Es intrusivo a propósito (ráfagas de rate-limit, intentos de credenciales,
SSRF, command injection) — pensado para correr **antes** de poner el MCP en
producción, no contra algo que ya sirve tráfico real sin que lo sepas.
Confirmá que tenés autorización para el target antes de correrlo.

**Salida** (mismos flags que `scan`, sección 3.6): `--out` (default
`reporte_vet.html` + `.json`, siempre agrega `.sarif`), `--print` (agrega la
tabla de hallazgos en terminal) y `--no-file` (solo terminal, no escribe
nada a disco).

```bash
# Servidor propio, stdio, reporte a archivo (default)
./ares.sh vet --command python3 --args "mi_servidor.py" --out reporte_vet.html

# Servidor remoto CON auth Bearer + código fuente para chequear dependencias
./ares.sh vet --transport http --url <URL> \
  --auth-token "<TOKEN>" --source-path ./codigo_del_server --out reporte_vet.html

# Servidor remoto SIN auth, resultado archivo + terminal
./ares.sh vet --transport http --url <URL> --print

# Chequeo rápido de máxima cobertura, sin guardar nada a disco
./ares.sh vet --command python3 --args "mi_servidor.py" --no-file
```

### 3.8 `full`

Modo batch: encadena `discover` con `scan`/`vet` de **todos** los targets
encontrados, corriéndolos **en simultáneo** (hasta `--concurrency` a la vez,
default 3) en vez de invocar cada modo a mano uno por uno. Pensado para
"auditame todo lo que tengo configurado" de una sola pasada.

Resolución del target, en este orden:
1. `--config RUTA` — igual que en `scan`, lee un JSON estilo Claude Desktop.
2. `--command`/`--url` explícito — un único target puntual.
3. Sin ninguno de los dos — auto-discover (igual que `discover`) contra los
   clientes MCP conocidos en la máquina.

```bash
# Todo lo que discover encuentra, auditoría de máxima cobertura (default)
./ares.sh full

# Solo tests default (más rápido), 5 targets a la vez, reportes en reportes/
./ares.sh full --mode scan --concurrency 5 --out-dir reportes/

# Un batch definido a mano
./ares.sh full --config ~/.config/Claude/claude_desktop_config.json
```

| Flag | Uso |
|---|---|
| `--mode {scan,vet}` | `vet` (default) = cobertura máxima por target, igual que `vet`; `scan` = solo tests `default_enabled`, más rápido |
| `--concurrency N` | targets corridos en simultáneo (default 3) |
| `--out-dir RUTA` | carpeta donde cae `<server>.html/.json` por cada target (default `reportes_full/`) |
| `--print` | además de los archivos por target, imprime en terminal la tabla de hallazgos confirmados de **cada** target a medida que termina |
| `--no-file` | no escribe ningún archivo para ningún target — el único resultado es la tabla en terminal por target (implica `--print`); tampoco crea `--out-dir` |
| `--config <RUTA>`/`--command <COMANDO>`+`--args "<ARGS>"`/`--url <URL>`/`--transport`/`--name` | mismos que `scan`, para fijar un target puntual en vez de auto-discover |
| `--allowlist <RUTA>` / `--min-confidence {heuristic,verified}` | aplicado a **cada** target de la corrida — ver [3.2](#32-reducir-ruido-allowlist-y-piso-de-confidence) |
| `--live-agent-provider {auto,anthropic,openai,ollama,all}` | aplicado a cada target, para `adv.live_agent_injection` si está seleccionado |
| `--baseline-dir <RUTA>` | carpeta con un `reporte.json` anterior **por target** (mismo nombre de archivo que generaría `--out-dir`, ej. `stdio_practica.json`); si existe, diffea igual que `--baseline` en `scan`/`vet` |
| `--webhook-on-regression <URL>` | requiere `--baseline-dir`: **un solo** POST JSON agregando TODOS los targets con hallazgos nuevos (nunca uno por target, nunca si nadie tuvo regresión) — ver el mismo mecanismo en la sección 3.6 |
| `--no-cross-server` | no corre la correlación cross-server al terminar (ver debajo) |
| resto de flags (`--auth-token "<TOKEN>"`, `--header`, `--source-path`, `--environment`, `--max-fuzz-cases`, `--request-delay-ms`, `--oob-callback-host`, `--allow-network`) | se aplican igual a **cada** target de la corrida |

Al terminar imprime una tabla resumen (hallazgos, grade, policy verdict, ruta
del reporte o `(--no-file)`) por cada target, además de los reportes
individuales en `--out-dir` (salvo que se use `--no-file`). Un error en un
target (conexión rechazada, timeout) no aborta los demás — queda marcado
como `error` en el resumen.

**Correlación cross-server** (automática con 2+ targets, salvo
`--no-cross-server`): después de escanear cada target por separado, analiza
el CONJUNTO — algo que ningún scan de un solo target puede ver:

- **Tool shadowing** (MCP09:2025): un tool con nombre idéntico o casi
  idéntico en dos servers distintos (el agente no puede saber a cuál le
  habla), o una descripción que menciona con lenguaje directivo ("usar X en
  vez de", "siempre llamar a") el tool de OTRO server conectado — el patrón
  donde un server malicioso reprograma, vía su propia descripción, cómo el
  agente usa tools de servers legítimos ya conectados.
- **Cadenas de exfiltración cross-server**: un tool lector en el server A +
  un tool emisor en el server B — invisible para `supplychain.exfiltration_chain`
  (que solo mira dentro de un mismo server) y para cualquier scan que audite
  un MCP a la vez.

Se imprime en terminal y (salvo `--no-file`) se guarda el dict plano en
`<out-dir>/cross_server_correlation_raw.json` **y además** un reporte
completo (`cross_server_correlation.html/.json/.sarif`) con score, policy
verdict y tags de framework -- cada hallazgo de acá es un `Finding` real
(`crossserver.tool_shadowing` / `crossserver.exfiltration_chain`), no solo
texto de consola.

```bash
# Todo lo que discover encuentra, con el detalle de cada target también en terminal
./ares.sh full --print

# Batch definido a mano, CON auth Bearer para todos los targets del config, sin escribir archivos
./ares.sh full --config <RUTA_AL_CONFIG> --auth-token "<TOKEN>" --auth-type bearer --no-file

# Re-auditoría periódica: solo avisa (un webhook) si algo empeoró desde la vez pasada
./ares.sh full --baseline-dir ./baselines/ --webhook-on-regression https://hooks.miempresa.com/ares
```

### 3.9 `serve`

**Qué hace**: levanta el dashboard web (ver [sección 4](#4-uso-por-interfaz-dashboard-web))
— mismo motor que la CLI, sin lógica duplicada.

```bash
./ares.sh serve                  # http://127.0.0.1:8000
./ares.sh serve --port 9000
```

Bindea a `127.0.0.1` por default a propósito. Si le pasás `--host` distinto
de localhost, Ares imprime una advertencia: el dashboard puede lanzar
procesos locales (stdio) y abrir conexiones salientes reales según los tests
elegidos — no lo expongas a una red no confiable sin auth/proxy encima.

Esa "auth" existe: `--token "<secreto>"` (o `ARES_DASHBOARD_TOKEN` en el
entorno) exige ese token en **toda** request al dashboard — HTTP (header
`X-Ares-Token` o `?token=`) y WebSocket por igual:

```bash
./ares.sh serve --host 0.0.0.0 --token "$(openssl rand -hex 16)"
```

Sin `--token`/`ARES_DASHBOARD_TOKEN`, el dashboard queda abierto a quien
llegue al host/puerto, sin ningún gate — bien para `127.0.0.1` (default),
nunca para un `--host` expuesto. No es RBAC ni multi-usuario (un token
único, sin roles) — es el mínimo para no quedar abierto por accidente.

## 4. Uso por interfaz (dashboard web)

**Guía dedicada, campo por campo (qué poner y para qué sirve cada uno):
[DASHBOARD.md](DASHBOARD.md).** Acá el resumen.

`./ares.sh serve` y abrir `http://127.0.0.1:8000`. Dos pestañas:

**Nuevo scan**
1. Elegí transporte (`stdio` o `http`/`sse`) y completá comando+args, o URL.
   El botón **"Descubrir servers configurados localmente"** llama al mismo
   descubrimiento que `discover` en CLI y te deja rellenar el formulario con
   un click sobre cualquier resultado.
2. Sección **Autenticación**: token/tipo/header, headers extra en texto
   libre (`Clave: Valor` por línea), y el checkbox **`--compare-auth`**.
3. Sección **Opciones**: ambiente (policy), `max-fuzz-cases`, `--source-path`,
   y el checkbox **`--allow-network`**.
4. Sección **Tests**: checkboxes agrupados por categoría, precargados según
   `default_enabled` de cada test (igual que `list-tests`); los marcados con
   ⚠️ tocan red externa real.
5. **▶ Correr scan** abre un WebSocket (`/ws/scan`), transmite la config, y
   el panel de log muestra cada test en vivo (mismo formato que la consola
   CLI). Al terminar aparecen: hallazgos confirmados, score, banner de
   veredicto de policy (rojo=BLOCK, ámbar=CONDITIONAL, verde=ALLOW), impacto
   de auth si corresponde, y links a HTML/JSON/SARIF.

**Reportes anteriores**: tabla de todos los scans corridos desde el
dashboard (persistidos en `reports/<scan_id>/`), con score, policy verdict y
link al HTML. `reports/index.json` es el índice; `reports/` está en
`.gitignore`.

Endpoints usados internamente (útiles si querés automatizar contra el
dashboard en vez de la CLI): `GET /api/tests`, `GET /api/discover`,
`GET /api/reports`, `WS /ws/scan`, `GET /reports/{scan_id}/{archivo}`.

## 5. Escenarios de referencia

### 5.0 Paso a paso: probar CON auth y SIN auth (las dos preguntas que importan)

Ares separa explícitamente dos preguntas — no alcanza con responder una sola:

1. **"¿Qué puede hacer alguien que no tiene NINGUNA credencial?"** — el
   atacante externo. La responden `auth.unauthenticated_access`,
   `auth.oauth_metadata_security`, `exposure.*`, y corriendo `scan` sin pasar
   `--auth-token`.
2. **"¿Qué puede hacer alguien que SÍ tiene una credencial válida, pero de
   bajo privilegio?"** — el usuario malicioso o comprometido. La responde
   `auth.authz_object_level` (BOLA) corriendo `scan` CON `--auth-token`.

Paso a paso con el fixture incluido (`target_server_http.py`, sin auth real
— cualquier token "funciona" porque no valida nada, lo cual es en sí mismo
el hallazgo del paso 1):

```bash
# Terminal 1: levantar el target
python target_server_http.py     # http://127.0.0.1:8765/mcp

# Terminal 2, paso 1 -- CERO credenciales, la vista del atacante externo
./ares.sh scan --transport http --url http://127.0.0.1:8765/mcp \
  --tests auth.unauthenticated_access,auth.oauth_metadata_security,exposure.transport_security \
  --out sin_auth.html
# -> auth.unauthenticated_access sale CRITICAL/confirmado: cualquiera enumera
#    y ejecuta la superficie completa sin loguearse.

# paso 2 -- CON una credencial (cualquiera, para ver si la valida de verdad)
./ares.sh scan --transport http --url http://127.0.0.1:8765/mcp \
  --auth-token "un-token-cualquiera" --auth-type bearer \
  --tests auth.authz_object_level \
  --out con_auth.html
# -> auth.authz_object_level fuzzea parámetros tipo id CON esa sesión --
#    si devuelve datos de otro objeto/cuenta sin validar ownership, confirmado.

# paso 3 -- las dos corridas en una sola invocación + el diff entre ambas
./ares.sh scan --transport http --url http://127.0.0.1:8765/mcp \
  --auth-token "un-token-cualquiera" --compare-auth \
  --out reporte.html
# -> genera reporte.html (con auth) y reporte.sin_auth.html (sin auth), y
#    agrega la sección "Impacto de autenticación": qué hallazgos DESAPARECEN
#    al autenticarse (la auth sí protege eso) vs cuáles PERSISTEN igual (la
#    auth no protege eso -- falso sentido de seguridad).
```

Contra un server que SÍ valida bien la auth, el paso 1 debería fallar la
conexión misma (rechazo antes de `initialize`) — Ares lo maneja sin abortar
el scan entero: `auth.unauthenticated_access` sale como finding positivo
("Conexión sin credenciales RECHAZADA"), y los tests que no necesitan sesión
viva (`exposure.*`, `auth.oauth_metadata_security`) igual corren y producen
resultado.

**"¿Puede un atacante sin cuenta hacer algo?"** → `scan` contra el endpoint
público sin pasar `--auth-token`. Revisá `auth.unauthenticated_access` y
`exposure.*`.

**"¿La autenticación protege de verdad, o da lo mismo?"** → `--compare-auth`
con tus credenciales reales. Mirá la sección "Impacto de autenticación": si
la lista de "NO mitigados por auth" no está vacía, esos hallazgos son
explotables igual estando logueado.

**"¿Este MCP es apto para producción?"** → `--environment production`, mirá
el veredicto de policy. `BLOCK` = no apto tal como está.

**"¿Está exponiendo secretos o dependencias con CVEs?"** →
`--tests supplychain.secret_exposure,supplychain.dependency_vulnerabilities
--source-path ./codigo --allow-network` (correr antes `update-rules` para el
set de secretos más fresco).

**"¿Esto mejoró o empeoró desde la última vez que lo audité?"** →
`--baseline reporte_anterior.json`. Mirá la sección "Comparación contra
baseline": si "Nuevos" no está vacío, alguien introdujo una regresión desde
el último scan.

**"¿Un agente real realmente va a obedecer esta inyección, o solo el server
no la sanitiza?"** → `--tests adv.live_agent_injection` con
`ANTHROPIC_API_KEY` seteada. Es la diferencia entre "el server refleja el
payload intacto" (`adv.injection_passthrough`) y "un LLM real intentó
ejecutar la acción que el payload le ordenó" (confirmación mucho más fuerte).

## 6. Mapeo a frameworks reconocidos

Cada hallazgo trae tags de a qué frameworks de seguridad aplica
(`engine/core/frameworks.py`, única fuente de verdad — se ven en el HTML como
chips de color debajo del título, y en JSON/SARIF como `frameworks`/`tags`).
Revisado y actualizado (2026-10) contra las versiones vigentes de cada
framework, leyendo el texto oficial de cada categoría/técnica (no un
resumen de terceros) antes de citarla:

- **OWASP MCP Top 10 (2025)** — `MCP01:2025` … `MCP10:2025`, el Top 10
  oficial y numerado dedicado específicamente a Model Context Protocol
  (owasp.org/www-project-mcp-top-10). Es el más específico al dominio de
  los cuatro. **Los 10 tienen al menos un test que los cite**:
  MCP01 (secretos), MCP02 (scope creep), MCP03 (tool poisoning), MCP04
  (supply chain), MCP05 (command injection), **MCP06 — "Intent Flow
  Subversion" (nombre corregido; antes decía "Prompt Injection via
  Contextual Payloads", una paráfrasis imprecisa)**, MCP07 (auth).
  **MCP08 (audit/telemetría)**: cobertura PARCIAL inherente al modelo
  black-box — `recon.audit_logging` solo puede verificar si el server
  DECLARA soporte de logging, nunca si audita cada llamada de verdad (eso
  requiere acceso a los logs del lado del server). Techo real del enfoque,
  no negligencia. **MCP09 (Shadow MCP Servers)**: CERRADO — antes solo
  corría en modo `full` (2+ targets) como un dict suelto impreso en
  terminal sin pasar por score/policy/SARIF; ahora es un Finding real
  (`crossserver.tool_shadowing`) con el mismo pipeline que cualquier otro,
  ver sección 12. **MCP10 (Context Injection & Over-Sharing)**: CERRADO —
  tres tests complementarios: `crossserver.exfiltration_chain` (datos
  cruzando el aislamiento entre servers DISTINTOS), `auth.resource_object_level`
  (BOLA en resources DENTRO de una sesión) y `auth.cross_session_context_bleed`
  (bleed ENTRE sesiones/tenants del MISMO server — planta un canario con una
  credencial y confirma con una segunda si aparece sin que nadie se lo haya
  dado; requiere `--auth-token-b`, opt-in e intrusivo, ver sección 3.6).
- **OWASP Top 10 for LLM Applications (2025)** — `LLM01:2025` … `LLM10:2025`,
  **los 10 con al menos un test**. LLM08 (Vector/Embedding Weaknesses) y
  LLM09 (Misinformation) son los dos únicos sin tests dedicados -- son
  riesgos de la capa de aplicación LLM (embeddings, alucinación del modelo),
  no algo que un servidor MCP exponga por protocolo; deliberadamente fuera
  de alcance, no un olvido.
- **OWASP API Security Top 10 (2023)** — `API1:2023` … `API10:2023` (aplica
  porque un server MCP sobre http/sse es, en los hechos, una API).
- **MITRE ATLAS (v5.6.0)** — técnicas puntuales **solo** donde hay un ID
  confirmado directamente contra `atlas-data` (no un resumen), incluyendo
  `AML.T0110` (AI Agent Tool Poisoning) — la única técnica de ATLAS que
  **nombra "Model Context Protocol" explícitamente** en su propia
  descripción oficial — además de `AML.T0053`, `AML.T0098`, `AML.T0101`,
  `AML.T0109`, `AML.T0080`, `AML.T0055`, `AML.T0034.002`, `AML.T0051`/
  `.001`, `AML.T0084.001`, `AML.T0011.002`, `AML.T0085.001` y `AML.T0086`.
  Para el resto de los tests se usa la táctica general (Reconnaissance,
  Exfiltration, etc.). ATLAS es un documento vivo — cruzar contra
  [atlas.mitre.org](https://atlas.mitre.org/matrices/ATLAS) antes de
  citarlo en un informe formal.
- **OWASP GenAI Security Project — Agentic AI Threats and Mitigations** —
  guía emergente, todavía no un Top-10 numerado y cerrado. Se usa solo para
  lo que el MCP Top 10 todavía no cubre (ej. resource exhaustion, human-in-
  the-loop bypass), citado por nombre de amenaza, no por ID.

`tests/test_unit.py::test_every_registered_test_has_framework_coverage`
corre en cada cambio y falla si algún test nuevo queda sin ningún tag —
"que ninguno se nos escape" dejó de depender de acordarse.

## 7. Metodología de riesgo (CVSS + OWASP Risk Rating)

Antes, la severidad de cada finding era un valor elegido a mano por archivo
(`Severity.CRITICAL` puesto directamente en el código de cada test) — sin
ningún estándar detrás, inconsistente entre módulos. Ares ahora la **calcula**
desde dos estándares reconocidos (`engine/core/risk.py`, única fuente de
verdad, un test_id no puede "elegir" su severidad, solo ajustar el vector
cuando tiene evidencia real de que ESA instancia es distinta al caso típico):

- **CVSS v3.1** (FIRST.org, la misma fórmula oficial que cualquier
  calculadora de NVD/GitHub — implementada en `engine/core/cvss.py` y
  verificada contra vectores de referencia públicos, incluido el 10.0 exacto
  de Log4Shell). De acá sale: el score/severidad técnica, y la **facilidad
  de explotación** en texto plano (vector de ataque, complejidad, privilegios
  requeridos, interacción de usuario — los 4 sub-componentes de CVSS).
- **OWASP Risk Rating Methodology** (owasp.org/www-community/OWASP_Risk_Rating_Methodology)
  para el **impacto al negocio** (financiero/reputacional/compliance/
  privacidad, cada uno low/medium/high) y el **rating de riesgo agregado**:
  Likelihood × Impact → Note/Low/Medium/High/Critical, con la matriz 3×3
  exacta que publica OWASP. La severidad final del finding (`Severity`,
  la que ves en el badge de color) sale de este rating, no del CVSS score
  solo — un finding puede tener CVSS "medium" pero terminar en riesgo "High"
  si el impacto al negocio de esa categoría es alto (o al revés).
- **Esfuerzo de remediación** (`trivial`/`low`/`medium`/`high`): la única
  pieza que **no** es un estándar externo — es una estimación propia de Ares
  de cuánto trabajo de ingeniería típico requiere el fix, con la razón
  siempre visible al lado, para poder priorizar (riesgo alto + fix trivial =
  lo primero que arreglás).

**Matiz por instancia**: cuando un test tiene evidencia real de que ESE
hallazgo puntual es distinto al caso típico (ej. `adv.injection_passthrough`
sabe si el payload fue *aceptado* o solo *citado en un rechazo*;
`exposure.cors_misconfig` sabe si además reflejó credentials; `adv.ssrf_exfil`
sabe si hubo un callback OOB real), ajusta el vector CVSS y/o el impacto al
negocio de esa instancia puntual (`cvss_vector_override`/
`business_impact_override` en el `Finding`) en vez de forzar un valor fijo.

**Riesgo de implementación**: el veredicto de policy (sección "Conceptos
básicos") ahora también se muestra **por hallazgo individual** en el reporte
HTML (chip junto al panel de riesgo), no solo agregado — así ves directamente
si ESE finding puntual bloquea el "apto para producción" o no.

Todo esto viaja en el JSON de cada finding bajo la clave `risk` (`cvss_vector`,
`cvss_score`, `cvss_severity`, `business_impact`, `technical_impact`,
`likelihood`, `impact`, `risk_rating`, `remediation_effort`), en el HTML como
un panel expandible "Riesgo" debajo de cada card, y en SARIF como
`properties.cvss_vector`/`owasp_risk_rating`/`security-severity` (esta
última, la convención que usa GitHub code scanning para rankear alertas).

Para `supplychain.dependency_vulnerabilities`, cuando OSV.dev publica un CVSS
real para esa CVE puntual, Ares usa **ese** vector (fuente real, mismo motor
de cálculo) en vez de la tabla genérica — nunca fabrica un CVSS donde no
existe uno publicado.

### 7.1 AIVSS (complementario, aproximación declarada)

Cada finding confirmado trae además un score **AIVSS** (`aivss.owasp.org`,
OWASP AI Vulnerability Scoring System) bajo `risk.aivss` — **no reemplaza**
el CVSS+OWASP Risk Rating de arriba, que sigue siendo la severidad oficial
del finding (el badge de color, lo que gatea policy). AIVSS extiende el
CVSS base con contexto agéntico: qué tan autónomo es el sistema, cuánto usa
herramientas, y cuán no-determinista es su comportamiento amplifican el
impacto real de un hallazgo *dentro de un agente*, algo que el CVSS por sí
solo no captura (un schema permisivo en `static` no es igual de riesgoso
que una inyección que un agente real puede terminar obedeciendo en
`adversarial`).

Fórmula (publicada por OWASP): `AARS = (10 − CVSS_base) × (factor_sum / 10)
× threat_multiplier`, luego `AIVSS = (CVSS_base + AARS) × mitigation_factor`.
Ares lo marca explícitamente con `is_approximation: true` en cada resultado
porque, a diferencia del CVSS base (fórmula 100% verificable desde el
vector), acá **no hay forma de observar** mitigaciones reales del target ni
un AARS calculado por un tercero independiente — por eso
`mitigation_factor` queda fijo en `1.0` (sin mitigaciones conocidas
asumidas) y los 3 factores agénticos (autonomía/uso de herramientas/no
determinismo, 0-10 cada uno) son un default **por categoría de test**
(`engine/core/risk.py::_AGENTIC_FACTORS`) — `adversarial` amplifica mucho
más que `static`, y `threat_multiplier` se amortigua a `0.6` cuando el
finding es `heuristic` en vez de `verified` (una amenaza sin confirmar no
debería pesar igual que una confirmada). Visible en el panel "Riesgo" del
HTML y en SARIF como `properties.aivss_score`.

## 8. Cómo leer el reporte

- **En terminal** (con `--print` o `--no-file`, ver sección 3.6): una tabla
  compacta con cada hallazgo confirmado — severidad (con color), confidence,
  test id, target, título y remediación. Es el equivalente en texto plano de
  las cards del HTML, sin evidencia request/response ni el panel de riesgo
  expandido (para eso, el `.html`/`.json`).
- **Cards** ordenadas por severidad; cada una tiene, además del badge de
  severidad, un badge de **confidence** (`verified` verde / `heuristic`
  ámbar — pasá el mouse para el tooltip), evidencia request/response, y
  remediación sugerida.
- **Panel "Riesgo"** (expandible, debajo de la descripción de cada finding
  confirmado): vector y score CVSS v3.1, facilidad de explotación en texto
  plano, chips de impacto al negocio, esfuerzo de remediación, y el chip de
  veredicto de policy **de ese hallazgo puntual** — ver sección 7.
- **Banner de policy**: veredicto agregado + cuántos hallazgos se evaluaron.
- **Comparación contra baseline** (si usaste `--baseline`): tres listas
  expandibles — nuevos / resueltos / persisten.
- **Impacto de auth** (si usaste `--compare-auth`): dos listas expandibles.
- **Filtros** arriba de las cards: todos / solo hallazgos / por severidad.
- El `.json` tiene la misma info estructurada (`summary`, `score`,
  `policy_verdict`, `auth_impact`, `baseline_diff`, `ares_version`,
  `findings[]` — cada finding con `confidence`, `frameworks` y `risk`) para
  pipear a otra cosa.
- El `.sarif` (si pediste `--sarif-out`) es para GitHub code scanning u otra
  herramienta de CI que consuma SARIF 2.1.0; los tags de framework,
  confidence y riesgo (CVSS/OWASP) quedan en `properties`, incluido
  `security-severity` (convención de GitHub para rankear alertas).
- La evidencia cruda (request/response/notes) se **redacta de secretos**
  antes de guardarse a disco (`engine/reporting/redact.py`) — si un tool
  devolvió un token real durante el scan, el reporte mismo no lo expone.

## 9. Extender Ares (test nuevo)

Ver la sección "Extender" en [README.md](README.md#extender-agregar-una-prueba-nueva).
Un test nuevo = una función `@register_test` más en el módulo de la
categoría que corresponda; aparece solo en `list-tests`, en el CLI y en el
dashboard (que lee la misma registry vía `/api/tests`).

## 10. Qué toca red y qué no

Ver la sección "Bases públicas consultadas" en [README.md](README.md#bases-públicas-consultadas-sin-api-key-sin-vendors-pagos).
Resumen actualizado — todo corre offline contra el MCP que estás auditando,
salvo estas acciones explícitas y opt-in:

| Acción | A dónde llama | Nota |
|---|---|---|
| `update-rules` | raw.githubusercontent.com (gitleaks, OSS público) | nunca automático, siempre manual |
| `supplychain.dependency_vulnerabilities` (`--allow-network`) | api.osv.dev (Google/OpenSSF, público) | nunca Cisco AI Defense ni Snyk |
| `adv.ssrf_exfil` con `--oob-callback-host` | el listener que **vos mismo** levantás | sin servicios de "collaborator" de terceros |
| `adv.live_agent_injection` | api.anthropic.com y/o api.openai.com (según credencial/`--live-agent-provider`), con tu propia API key; u Ollama LOCAL (`OLLAMA_HOST`, típicamente `localhost`, no sale a Internet) | consume tu cuota (Anthropic/OpenAI) o requiere el daemon local corriendo; nunca corre por default |
| `supplychain.source_sast` | ninguna — corre `semgrep` con `--config <ruta local>` (nunca `--config auto/p/ci`, que sí pegan al registro público de semgrep.dev) | 100% offline aunque `semgrep` esté instalado |
| `--webhook-on-regression <URL>` | la URL que **vos** des | nunca automático; solo si pasás el flag, y solo un POST cuando hay regresión real |
| `adv.stateful_chain_exfil` | ninguna directamente — pero llama tools de "envío" REALES del target (podrían salir a red por su cuenta) | opt-in, intrusivo por diseño (ver sección 1.2) |

## 11. Confiabilidad del motor

Ares tiene su propio test suite (`tests/`, pytest) que valida que cada
detector encuentra lo que dice encontrar contra `target_server.py`/
`target_server_http.py` (positivo) y que **no** dispara falsos positivos
contra `tests/fixtures/safe_server.py`, un server bien construido a propósito
(negativo). Sin esto, un refactor futuro podría romper detección en silencio.

```bash
pip install -e ".[dev]"
pytest -v
```

92 tests (+2 que se saltean solos si falta una dependencia opcional):
detectores end-to-end (stdio + http, incluidos rug pull, line jumping, BOLA
en tools y en resources, fuga de contexto cross-session por canario de
doble marcador, audit logging, la cadena de exfiltración multi-step
confirmada por ejecución real, SAST vía semgrep -- se saltea automáticamente
si `semgrep` no está instalado -- que un test colgado se corta por timeout
sin tumbar el scan, el circuit breaker tras varios timeouts seguidos, y que
el aislamiento de proceso -- prlimit/bwrap -- compone bien sin romper nada)
más unitarios puros (Jaro-Winkler, strip-reflections del canario, CVSS v3.1
contra vectores de referencia públicos, matriz OWASP Risk Rating, AIVSS,
scoring, policy engine, allowlist/piso de confidence, correlación
cross-server como Finding real, feed de CVEs conocidos, typosquatting, el
gate de token del dashboard contra HTTP y WebSocket reales). Corre en CI en cada
push (`.github/workflows/test.yml`) en `ubuntu-latest` y `windows-latest`
(matriz), más un job aparte que prueba `ares.ps1`/`ares.bat` de punta a
punta en un Windows real -- la única verificación de Windows que existe
hoy, nunca se corrió en una máquina Windows real fuera de CI (ver sección 2.0b).

Otras piezas de confiabilidad:

- **`confidence` por finding** (`verified`/`heuristic`, sección 1) — para no
  hacer pasar una señal heurística por una confirmación.
- **`ares_version`** estampado en cada reporte, para trazabilidad de auditoría.
- **Redacción de secretos en la evidencia** antes de persistir a disco.
- **CVSS real** (nunca fabricado) cuando OSV.dev lo publica para una
  dependencia vulnerable — si OSV no tiene CVSS para esa vulnerabilidad
  puntual, el campo sale `null`, no se inventa un número.
- **Confirmación OOB para SSRF**: con `--oob-callback-host`, un finding de
  `adv.ssrf_exfil` puede pasar de heurístico a `verified` porque recibiste
  una conexión saliente real del target, no porque "el texto de la respuesta
  sonaba a que se conectó".
- **Feed de CVEs conocidos verificado, nunca inventado** (`static.known_cve_check`):
  cada entrada de `engine/static/known_cves.py` se contrastó contra una
  fuente pública real (avisos de seguridad, GitHub Security Advisories)
  antes de agregarse — nunca un número de CVE fabricado.
- **Fail-closed por timeout**: ningún test puede colgar el scan completo —
  `--test-timeout-s` (default 60) corta el test individual y el resto sigue.

## 12. Qué queda afuera de esta versión

Ninguna herramienta de seguridad está completa. Esto es lo que se evaluó y
se decidió NO construir todavía en esta pasada, y por qué:

- **Análisis estático de código fuente (SAST/taint)** — `supplychain.source_sast`
  (semgrep, ruleset propio taint-aware) cubre AHORA command injection, path
  traversal, eval/exec y deserialización insegura sobre el código real, pero
  es un ruleset chico y curado a mano, no un motor SAST completo — sigue
  siendo una brecha frente a herramientas dedicadas (`mcp-guard`, Semgrep
  Pro/registro público) para recall exhaustivo.
- **Ataques multi-step/stateful** — `adv.stateful_chain_exfil` cubre AHORA el
  patrón más importante (lector→emisor, confirmado por ejecución real con
  canario), pero sigue siendo un patrón puntual de dos llamadas; encadenar
  N tools arbitrarios en secuencias más largas/genéricas sigue sin cubrirse.
- **Fuzzing a nivel protocolo** (frames JSON-RPC malformados, replay/
  predictibilidad del `Mcp-Session-Id` en streamable-http).
- **Grafo de exfiltración cross-server** — cubierto AHORA por la correlación
  cross-server del modo `full` (sección 3.8): con 2+ targets en la misma
  corrida, detecta cadenas lector(server A)→emisor(server B) que
  `supplychain.exfiltration_chain` no puede ver (solo mira dentro de un
  mismo server). Desde esta ronda, esto genera `Finding` reales
  (`crossserver.exfiltration_chain`) que SÍ pasan por score/policy/SARIF —
  antes era un dict suelto solo impreso en terminal, invisible para CI.
  Sigue siendo básico: correlación por keyword/similitud, no un grafo
  completo con múltiples saltos.
- **Tool Shadowing (MCP09:2025)** — mismo fix: `crossserver.tool_shadowing`
  ahora es un `Finding` real (colisión de nombres entre servers distintos,
  y descripciones que referencian directivamente tools de OTRO server
  conectado). Lo que sigue faltando: comparar contra una allowlist de
  servers "aprobados" (gobernanza formal) — `discover` los encuentra, pero
  no hay ese concepto de aprobación todavía.
- **BOLA sobre resources** (`auth.resource_object_level`) — mismo patrón
  que `auth.authz_object_level` pero sobre `resources/read` en vez de
  tools.
- **Bleed entre sesiones/tenants** (`auth.cross_session_context_bleed`,
  nuevo) — la pieza de MCP10:2025 que antes se daba por no verificable sin
  un harness de 2+ identidades: planta un canario con doble marcador (id +
  secreto, nunca el mismo valor -- un solo canario daba falso positivo por
  simple eco de argumento, ej. `read_file` fallando con "no existe el
  archivo '<canario>'") usando la sesión PRIMARIA, abre una sesión nueva
  con `--auth-token-b` (una segunda credencial/tenant), y confirma si el
  secreto aparece sin que esa segunda sesión lo haya plantado. Requiere
  transporte http/sse (stdio no tiene noción de sesión separable) y que el
  usuario aporte una segunda credencial válida -- Ares no puede inventar un
  segundo tenant que no existe, pero si el usuario tiene dos, esto SÍ lo
  verifica con ejecución real, no heurística.
- **Resumen ejecutivo/PDF** para stakeholders no técnicos — hoy el reporte es
  HTML/JSON/SARIF, pensado para uso técnico.
- **Empaquetado Docker** — hay `pyproject.toml` (`pip install -e .`), pero no
  imagen de contenedor.
- **`adv.live_agent_injection` sin verificación end-to-end real** — ahora
  soporta Anthropic/OpenAI/Ollama (`--live-agent-provider`), pero NINGUNO de
  los tres caminos (solo el "sin credencial") se probó de punta a punta
  contra una API/daemon real en el entorno de desarrollo de Ares, por no
  tener credenciales/Ollama disponibles ahí. Antes de confiar en su
  resultado en un pentest real, correlo primero contra tus propios fixtures
  conocidos.
- **Ataques cross-server más allá de shadowing/exfil** — MCP10:2025
  (Context Injection & Over-Sharing) sigue sin cubrirse: requiere testear
  con múltiples sesiones concurrentes y comparar qué ve cada una; Ares hoy
  corre una sesión a la vez por target, incluso en `full`.
