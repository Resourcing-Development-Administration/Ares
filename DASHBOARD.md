# Manual del dashboard web

**Interfaz web de Ares** (`./ares.sh serve`) — mismo motor que la CLI
(`engine/orchestrator.py`, sin lógica duplicada), corriendo `scan`, `vet` o
`full` desde el navegador con progreso en vivo, en vez de la terminal.

Este documento es la referencia completa del dashboard: qué va en cada
campo, por qué, y para qué sirve — con la misma profundidad que
[MANUAL.md](MANUAL.md) (la referencia de la CLI). Para instalación, ver
[README.md](README.md).

**¿Primera vez acá?** Andá directo a [§0 Referencia rápida](#0-referencia-rápida-qué-querés-hacer)
o a [§2 Cómo está organizada la pantalla](#2-cómo-está-organizada-la-pantalla).

## Índice

**Empezar**
- [0. Referencia rápida — ¿qué querés hacer?](#0-referencia-rápida-qué-querés-hacer)
- [1. Arrancar el dashboard](#1-arrancar-el-dashboard)
- [2. Cómo está organizada la pantalla](#2-cómo-está-organizada-la-pantalla)
- [3. Los tres modos, en detalle](#3-los-tres-modos-en-detalle)
  - [3.1 `scan`](#31-scan)
  - [3.2 `vet`](#32-vet)
  - [3.3 `full`](#33-full)

**Los campos, uno por uno**
- [4. Target (`scan`/`vet`)](#4-target-scanvet)
- [5. Targets para `full`](#5-targets-para-full)
- [6. Autenticación](#6-autenticación)
- [7. Opciones](#7-opciones)
- [8. Avanzado: reducir ruido, live-agent, baseline/webhook](#8-avanzado-reducir-ruido-live-agent-baselinewebhook)
- [9. Tests (solo `scan`)](#9-tests-solo-scan)

**Resultados y reportes**
- [10. Correr y leer el resultado](#10-correr-y-leer-el-resultado)
  - [10.1 Resultado de `scan`/`vet`](#101-resultado-de-scanvet)
  - [10.2 Resultado de `full`](#102-resultado-de-full)
- [11. Pestaña "Reportes anteriores"](#11-pestaña-reportes-anteriores)

**Referencia**
- [12. Lo poco que sigue siendo CLI-only](#12-lo-poco-que-sigue-siendo-cli-only)
- [13. Flujos de ejemplo completos](#13-flujos-de-ejemplo-completos)

---

## 0. Referencia rápida — ¿qué querés hacer?

| Quiero... | Modo | Dónde |
|---|---|---|
| Escanear un MCP propio o remoto, elegir qué tests corren | `scan` | [§3.1](#31-scan), campos en [§4](#4-target-scanvet) |
| Auditoría exhaustiva antes de poner un MCP en producción | `vet` | [§3.2](#32-vet) |
| Escanear varios MCPs a la vez, en paralelo | `full` | [§3.3](#33-full), targets en [§5](#5-targets-para-full) |
| Encontrar MCPs ya configurados en esta máquina | botón "Descubrir" | [§4](#4-target-scanvet) |
| Probar sin ninguna credencial (vista del atacante externo) | dejar **Token** vacío | [§6](#6-autenticación) |
| Saber si mi autenticación protege de verdad | tildar `--compare-auth` | [§6](#6-autenticación) |
| No repetir en cada scan un hallazgo ya aceptado | `--allowlist` (en "Avanzado") | [§8](#8-avanzado-reducir-ruido-live-agent-baselinewebhook) |
| Que solo lo confirmado bloquee mi CI, no lo heurístico | `--min-confidence verified` | [§8](#8-avanzado-reducir-ruido-live-agent-baselinewebhook) |
| Comparar contra un scan anterior | `--baseline` | [§8](#8-avanzado-reducir-ruido-live-agent-baselinewebhook) |
| Que me avisen solo si algo empeoró | `--webhook-on-regression` (requiere `--baseline`) | [§8](#8-avanzado-reducir-ruido-live-agent-baselinewebhook) |
| Chequear dependencias con CVEs reales / auditar el código fuente | `--source-path` | [§7](#7-opciones) |
| Detectar un paquete typosquateado | `--package-name` | [§7](#7-opciones) |
| Ver si un agente real obedece una inyección | elegir tests en [§9](#9-tests-solo-scan) o correr `vet` | [§8](#8-avanzado-reducir-ruido-live-agent-baselinewebhook) (`--live-agent-provider`) |
| Detectar un server que se hace pasar por otro ya conectado | `full` con 2+ targets | [§10.2](#102-resultado-de-full) |
| Ver resultados de corridas anteriores | pestaña "Reportes anteriores" | [§11](#11-pestaña-reportes-anteriores) |
| Ver exactamente qué se le manda a cada tool y qué responde, en vivo | tildar `--verbose` en Opciones | [§7](#7-opciones) |
| Algo que no está en el dashboard | — | [§12](#12-lo-poco-que-sigue-siendo-cli-only) |

---

## 1. Arrancar el dashboard

```bash
./ares.sh serve                  # abre en http://127.0.0.1:8000
./ares.sh serve --port 9000      # otro puerto
```

**Qué pasa al arrancarlo**: `ares.sh` prepara el venv si hace falta y
levanta un servidor FastAPI local con `uvicorn`. Abrís la URL que imprime
en cualquier navegador — no hay instalación de cliente, ni build de JS, es
un único HTML servido tal cual.

Bindea a `127.0.0.1` (localhost) por default, **a propósito**: el dashboard
puede lanzar procesos locales (`stdio`) y abrir conexiones salientes reales
según el modo/tests/flags que uses. Si le pasás `--host` distinto de
localhost, Ares imprime una advertencia en la terminal donde corre `serve`
— no lo expongas a una red compartida sin ponerle autenticación/proxy
encima.

## 2. Cómo está organizada la pantalla

De arriba hacia abajo, siempre en este orden:

```
🛡️ Ares — Dashboard
[ Nuevo scan ]  [ Reportes anteriores ]      ← dos pestañas

  ┌─ scan ─┐ ┌─ vet ─┐ ┌─ full ─┐            ← elegís el modo (§3)
  └────────┘ └───────┘ └────────┘

  ┌─ Target ───────────────────┐             ← a qué le apuntás (§4/§5)
  │ transporte, comando/url... │
  └─────────────────────────────┘

  ┌─ Autenticación ─────────────┐            ← credenciales, si aplica (§6)
  └──────────────────────────────┘

  ┌─ Opciones ───────────────────┐           ← fuzz, source-path, etc. (§7)
  │  ▸ Avanzado (colapsado)      │           ← reducir ruido, baseline... (§8)
  └───────────────────────────────┘

  ┌─ Tests ──────────────────────┐           ← solo en modo scan (§9)
  └───────────────────────────────┘

  [ ▶ Correr ]

  ┌─ log en vivo ────────────────┐           ← progreso test por test (§10)
  └───────────────────────────────┘
  ┌─ resultado ──────────────────┐           ← score, policy, links a reportes
  └───────────────────────────────┘
```

Cada fieldset (recuadro con título celeste) agrupa campos relacionados —
las secciones siguientes de este manual van en ese mismo orden.

## 3. Los tres modos, en detalle

Los tres botones grandes arriba de todo eligen qué comando de la CLI corre
por debajo. Es la decisión más importante del formulario: cambia qué
secciones aparecen después.

### 3.1 `scan`

**Qué hace**: corre contra **un** target los tests que elijas en la sección
Tests (§9) — o todos los `default_enabled` si no tocás nada ahí. Es el modo
de uso diario, equivalente a `./ares.sh scan` por CLI.

**Cuándo usarlo**: para un chequeo puntual, rápido, o cuando ya sabés
exactamente qué tests te interesan (por ejemplo, solo los de `auth.*` para
responder "¿la autenticación protege de verdad?").

### 3.2 `vet`

**Qué hace**: auditoría de **máxima cobertura** contra **un** target — corre
**todos** los tests registrados, incluidos los opt-in (`dynamic.rate_limit`,
`auth.weak_credentials`, `adv.ssrf_exfil`, `adv.stateful_chain_exfil`,
`supplychain.dependency_vulnerabilities`, `supplychain.source_sast`,
`adv.live_agent_injection`, `static.typosquatting_check`, etc.). Por eso el
fieldset "Tests" (§9) se oculta: no hay nada para elegir, corre todo.
Además fuerza automáticamente: `--allow-network`, ambiente `production`, y
sube "Max fuzz cases" a 50 (en vez de 25) si lo dejás vacío.

**Cuándo usarlo**: antes de poner un MCP en producción, o para el gate
"¿este server es apto para mi operación?" — es intrusivo a propósito
(intentos de credenciales, SSRF, fuzzing agresivo). Confirmá que tenés
autorización para el target antes de correrlo.

### 3.3 `full`

**Qué hace**: corre `scan` o `vet` (elegible) contra **varios targets a la
vez, en paralelo**, y al terminar corre además una correlación entre todos
ellos que ningún scan de un solo target puede ver — ver [§10.2](#102-resultado-de-full).
Equivalente a `./ares.sh full` por CLI.

**Cuándo usarlo**: para auditar de una sola pasada todo lo que tenés
configurado (varios clientes MCP en la misma máquina), o para chequear si
algún server se está "haciendo pasar" por otro que ya tenés conectado.

---

## 4. Target (`scan`/`vet`)

*Visible en modo `scan` o `vet`. Oculto en `full` (que usa §5 en su lugar).*

*A quién le vas a apuntar el scan.*

| Campo | Qué es | Qué poner | Para qué sirve |
|---|---|---|---|
| **Transporte** | Cómo se conecta Ares al MCP | `stdio` si es un proceso que vos lanzás local; `http` (o `sse`) si es una URL remota o local por red | Cambia qué campos aparecen abajo (Comando/Args, o URL) — igual que `--transport` en la CLI |
| **Nombre (opcional)** | Solo etiqueta visual | Cualquier texto, ej. `mi-servidor-prod` | No cambia el scan en nada; es el nombre que vas a ver después en "Reportes anteriores" y en `target_name` del JSON. Vacío = usa el comando o la URL como nombre |
| **Comando** *(solo si Transporte=stdio)* | El ejecutable que levanta el server MCP | Ej. `python3`, `node`, `.venv/bin/python` | Lo primero que Ares ejecuta para hablarle al server por stdin/stdout — igual que `--command` |
| **Args** *(solo si Transporte=stdio)* | Argumentos del comando, separados por espacio | Ej. `mi_servidor.py`, o `servidor.js --puerto 3000` | Se le pasan tal cual al comando de arriba — igual que `--args` |
| **URL** *(solo si Transporte=http/sse)* | Dirección del MCP remoto o local por red | Ej. `http://127.0.0.1:8765/mcp`, `https://mcp.miempresa.com/mcp` | A dónde se conecta Ares por HTTP/SSE — igual que `--url` |
| **Descubrir servers configurados localmente** (botón) | Atajo, no un campo | Click | Lista los MCPs ya declarados en Claude Desktop/Cursor/VSCode/Windsurf/Codex en esta máquina (mismo motor que `./ares.sh discover`). Cada fila trae un botón **"usar en scan/vet"** que rellena Comando/Args/URL de una, y un checkbox a la izquierda que se usa solo en modo `full` (§5) |

## 5. Targets para `full`

*Visible solo en modo `full` — reemplaza al fieldset Target de §4.*

Dos formas de elegir los targets — si pegás algo en el **Config JSON**,
**tiene prioridad** sobre los checkboxes de abajo:

| Campo | Qué es | Qué poner | Para qué sirve |
|---|---|---|---|
| **Config JSON** | Un batch definido a mano, mismo formato que un `claude_desktop_config.json` | `{"mcpServers": {"nombre": {"command": "...", "args": [...]}, "otro": {"url": "..."}}}` | Equivale a `full --config archivo.json` — útil para un batch fijo que no está declarado en ningún cliente MCP de esta máquina |
| Checkboxes en la tabla de "Descubrir" (§4) | Selección de targets ya detectados | Tildá los que querés incluir | Si el Config JSON está vacío, `full` corre sobre estos — primero hacé click en "Descubrir servers configurados localmente" para que aparezca la tabla con checkboxes |
| **Modo por target** | `vet` o `scan`, aplicado a CADA target del batch | `vet` (default, cobertura máxima) o `scan` (más rápido, solo tests default) | Igual que `--mode` en `./ares.sh full` |
| **Concurrencia** | Cuántos targets corren al mismo tiempo | Número, default `3` | Igual que `--concurrency` — subilo si tenés muchos targets y CPU/red de sobra, bajalo si querés ir con más cuidado |

Al terminar, si corriste 2+ targets, el dashboard corre además la
**correlación cross-server** automáticamente — ver [§10.2](#102-resultado-de-full).

## 6. Autenticación

*Solo aplica si el target es `http`/`sse` — un MCP `stdio` no usa nada de
esta sección (es un proceso que vos ya controlás, no tiene "credencial").
En `full`, esta configuración se aplica a **todos** los targets del batch
por igual.*

| Campo | Qué es | Qué poner | Para qué sirve |
|---|---|---|---|
| **Tipo** | Cómo se arma el header de auth | `bearer` (lo más común) → `Authorization: Bearer <token>`; `apikey`/`custom` → el token crudo en el header que pongas abajo | Define el formato del header que Ares manda en cada request |
| **Token / credencial** | La credencial en sí | Tu token/API key real, o **dejalo vacío** si querés probar sin auth | Vacío = el scan corre SIN ninguna credencial — es intencional, no un error: así respondés la pregunta "¿qué puede hacer un atacante externo?" (ver [MANUAL §5.0](MANUAL.md#50-paso-a-paso-probar-con-auth-y-sin-auth-las-dos-preguntas-que-importan)) |
| **Nombre de header (apikey/custom)** | El nombre literal del header HTTP | Ej. `X-API-Key` | Solo se usa si Tipo es `apikey` o `custom`; con `bearer` se ignora (siempre es `Authorization`) |
| **Headers extra** | Headers HTTP crudos adicionales, uno por línea | Formato `Clave: Valor` por línea, ej. `Cookie: sesion=abc123` | Para credenciales que no son ni Bearer ni API key (cookies de sesión, headers propietarios) |
| **`--compare-auth`** (checkbox, no disponible en `full`) | Corre el scan DOS veces | Tildalo si tenés Token cargado y querés saber si esa auth protege de verdad | Corre una vez CON el token y otra vez SIN nada, y compara: qué hallazgos desaparecen al autenticarse (auth sí protege) vs cuáles quedan igual (auth no protege eso). Sin Token cargado, tildarlo no hace nada — las dos corridas serían idénticas |

**Avanzado — Segunda identidad** (colapsado, click en "Avanzado: segunda
identidad"): una SEGUNDA credencial/tenant válido contra el **mismo**
server, independiente de la de arriba.

| Campo | Qué es | Qué poner | Para qué sirve |
|---|---|---|---|
| **Tipo (segunda identidad)** | Mismo formato de header que "Tipo" de arriba, para esta segunda credencial | `bearer`/`apikey`/`custom` | Define cómo se autentica la SEGUNDA sesión |
| **Token / credencial (segunda identidad)** | Una credencial distinta a la de arriba — otro usuario/tenant válido | Vacío = `auth.cross_session_context_bleed` se saltea solo | Habilita el único test que confirma fuga de contexto **entre sesiones/tenants** del mismo server (MCP10:2025): planta un canario con la sesión primaria y confirma si aparece en una sesión nueva abierta con esta credencial, sin que nadie se lo haya dado ahí. Solo aplica a transporte http/sse |
| **Nombre de header (apikey/custom)** | Igual que el de arriba, para esta segunda credencial | Ej. `X-API-Key` | Solo se usa si Tipo (segunda identidad) es `apikey`/`custom` |

## 7. Opciones

| Campo | Qué es | Qué poner | Para qué sirve |
|---|---|---|---|
| **Ambiente (policy)** | Contra qué reglas de `policy.yaml` se evalúa el veredicto | `production` (default, más estricto) o `development` — en `vet`/`full vet` queda forzado a `production` | Cambia el veredicto BLOCK/CONDITIONAL/ALLOW final — las mismas reglas pueden bloquear en `production` y solo advertir en `development` |
| **Max fuzz cases por tool** | Cuántos casos de fuzzing genera `dynamic.fuzz_tools`/`dynamic.fuzz_resources` por tool | Número; vacío = 25 en `scan`, 50 en `vet`/`full` | Controla la profundidad del fuzzing, no afecta a los demás tests |
| **Delay entre llamadas a tools (ms)** | Pausa entre cada llamada a un tool | `0` default; subilo (ej. `250`) si el target es sensible/productivo | Equivale a `--request-delay-ms` — para no saturar un server real |
| **`--source-path`** | Ruta **local** (en la máquina donde corre `ares.sh serve`, no en tu navegador) al código fuente del server que auditás | Ej. `./mi_servidor` o una ruta absoluta | Habilita `supplychain.dependency_vulnerabilities` (busca manifiestos y consulta CVEs reales en OSV.dev) y `supplychain.source_sast` (semgrep, si está instalado) — sin esta ruta, esos dos tests no tienen nada que mirar |
| **`--package-name`** | Nombre de paquete npm/pypi declarado | Ej. `mcp-server-fetch` | Habilita `static.typosquatting_check` — compara contra una lista curada de paquetes MCP oficiales conocidos, por similitud Jaro-Winkler |
| **`--oob-callback-host`** | `host:puerto` alcanzable por el target, que vos mismo levantás (sin servicios de terceros) | Ej. `192.168.1.50:8899` | Para que `adv.ssrf_exfil` confirme SSRF por un callback real en vez de solo inferirlo — el finding sale como `confidence: verified` |
| **`--ca-bundle`** (solo `http`/`sse`) | Ruta **local** (en la máquina donde corre `ares.sh serve`) a un bundle de CA en PEM | Ej. `/etc/ssl/certs/ca-corporativa.pem`; vacío = trust store por defecto (certifi), con fallback a la variable de entorno `SSL_CERT_FILE` | Valida el certificado TLS del server contra una CA **interna/corporativa** sin desactivar la verificación — para auditar un server interno cuyo cert no está firmado por una CA pública. El tipo de certificado detectado se muestra en el resultado (ver [§10.1](#101-resultado-de-scanvet)) y en el reporte (`exposure.certificate_type`) |
| **`--trust-presented-cert`** (checkbox, solo `http`/`sse`) | Traer y fijar el cert que presenta el server para conectarse igual | Tildalo cuando el target tiene cert self-signed/CA interna y **no** tenés el bundle a mano, pero querés que el scan corra igual | Si el TLS no valida y no diste `--ca-bundle`, Ares trae el certificado presentado y lo **fija** (pinning TOFU) para completar el handshake y correr todas las pruebas. **No valida identidad** (si había un MITM, fija su cert) y el certificado se sigue reportando self-signed/riesgo. Solo para targets internos que controlás — para validación real usá `--ca-bundle` |
| **`--allow-network`** (checkbox) | Gate explícito para tests marcados `requires_network` | Tildalo solo si sabés lo que hacés | Sin esto, tests como `adv.ssrf_exfil` o `supplychain.dependency_vulnerabilities` se saltean aunque los tildes en Tests (§9) — es un gate separado a propósito, para que un efecto de red real nunca sea "sin querer". En `vet`/`full vet` ya viene forzado |
| **`--verbose`** (checkbox) | Ver cada llamada real, no solo el resumen por test | Tildalo cuando algo no anda como esperás y necesitás ver exactamente qué se mandó y qué respondió el target | Agrega al log en vivo una línea `→` (request) y `←` (response) por cada `list_tools`/`call_tool`/`read_resource` real que hace cada test — en `full`, cada línea sale con el prefijo `[nombre-del-target]`. Útil para diagnosticar un error de conexión o por qué un test no encuentra lo que esperás |

## 8. Avanzado: reducir ruido, live-agent, baseline/webhook

*Colapsado por default — hacé click en "Avanzado" para desplegarlo. Son los
flags más nuevos/específicos; no los necesitás para un scan del día a día.*

| Campo | Qué es | Qué poner | Para qué sirve |
|---|---|---|---|
| **`--allowlist`** | Ruta a un `.ares_allowlist.yml` | Vacío = auto-detecta uno en el directorio del proyecto si existe; o una ruta explícita | Suprime findings ya revisados y aceptados por el equipo — **nunca se borran del reporte**, solo dejan de contar para score/policy/CI. Ver `.ares_allowlist.example.yml` en la raíz del proyecto para el formato |
| **`--min-confidence`** | Piso de confidence que gatea score/policy | `heuristic` (default, todo cuenta) o `verified` (solo hechos observados directamente) | Sube el piso de lo que bloquea un build automatizado sin perder visibilidad de lo heurístico en el reporte — gran reductor de ruido en CI |
| **`--live-agent-provider`** | Proveedor de agente real para `adv.live_agent_injection` (si ese test corre, por selección en §9 o forzado por `vet`) | `auto` (el primero con credencial disponible), `anthropic`/`openai`/`ollama` (forzar uno), o `all` (compara los 3) | Solo importa si ese test corre. Sin ninguna de `ANTHROPIC_API_KEY`/`OPENAI_API_KEY`/`OLLAMA_HOST` en el entorno donde corre `ares.sh serve`, el test se saltea igual con un finding informativo |
| **`--test-timeout-s`** | Segundos máximos por test antes de cortarlo | Default `60` | Fail-closed: un test colgado (ej. un tool del target que nunca responde) se corta solo y el resto del scan sigue |
| **`--baseline`** | Ruta a un `reporte.json` de una corrida anterior | En `scan`/`vet`: el archivo de la corrida pasada, ej. `reporte_semana_pasada.json`. En `full`: la ruta del reporte por-target que ya generaste antes (ej. `reports/<scan_id>/report.<nombre>.json`) | Agrega al resultado qué hallazgos son nuevos / resueltos / persisten desde esa corrida — en `full` se aplica igual a cada target |
| **`--webhook-on-regression`** | URL propia a la que avisar | Ej. `https://hooks.miempresa.com/ares` | Requiere `--baseline`: si aparecen hallazgos **nuevos** respecto al baseline, hace un POST JSON liviano (nunca evidencia cruda — solo `test_id`/`severity`/`target`/`title`). En `full`, el webhook se manda por target (a diferencia de la CLI, que lo agrega en uno solo al final) |

**Avanzado — Aislamiento del subprocess y resiliencia** (colapsado, click en
"Avanzado: aislamiento del subprocess y resiliencia"; solo aplica a
transporte **stdio**, el proceso que Ares lanza). Los defaults ya son
seguros — esto es para **ajustar**, no para "activar" protección que de
otro modo no estaría: por default, el subprocess corre con límites reales
de memoria/CPU/procesos/FDs (`prlimit`) y namespaces aislados de PID/IPC/red
(`bwrap`) — no puede ver ni señalizar al proceso de Ares ni a nada del
host, y no tiene red real salvo que tildes `--allow-network` (§7).

| Campo | Qué es | Qué poner | Para qué sirve |
|---|---|---|---|
| **`--no-sandbox`** (checkbox) | Desactiva TODO el aislamiento de proceso | Casi nunca hace falta tildarlo | Apaga `prlimit` + `bwrap` por completo — existe para debuggear o para un host donde ninguno de los dos está disponible de todas formas |
| **`--sandbox-mem-mb`** | Tope de memoria virtual (MB) del subprocess | Vacío = `512` | Vía `prlimit` (`RLIMIT_AS`) — de sobra para cualquier server MCP legítimo |
| **`--sandbox-cpu-s`** | Tope de tiempo de CPU (segundos) | Vacío = `120` | Vía `prlimit` (`RLIMIT_CPU`) |
| **`--sandbox-nproc`** | Tope de procesos/threads — bloquea fork bombs | **Dejalo vacío** (recomendado) | Vacío = calculado dinámicamente como "lo que el host ya tiene corriendo + margen" — `RLIMIT_NPROC` es un tope sobre el TOTAL de procesos del usuario en todo el host, no por proceso hijo; un número fijo puesto a mano puede romper la corrida si el host ya tiene más procesos que ese número |
| **`--sandbox-nofile`** | Tope de file descriptors abiertos | Vacío = `256` | Vía `prlimit` (`RLIMIT_NOFILE`) |
| **`--max-consecutive-timeouts`** | Circuit breaker: tras N timeouts seguidos, saltea el resto de la batería de una | Vacío = `3`; `0` = sin límite | Evita pagar `--test-timeout-s` completo test por test contra un target que dejó de responder de forma sostenida |
| **`--max-text-for-analysis`** | Tope de caracteres analizados con regex (descripciones de tools, schemas) | Vacío = `200000` | Un target hostil con una descripción de varios MB puede inflar el tiempo de análisis a propósito — este cap lo evita |
| **`--max-response-content`** | Tope de caracteres de una respuesta de `call_tool`/`read_resource` | Vacío = `2000000` | Mismo motivo que el de arriba, para respuestas en vez de descripciones |
| **`--no-session-reset`** (checkbox) | No cerrar/reabrir la sesión tras un timeout | Casi nunca hace falta tildarlo | Por default, tras un timeout Ares cierra la sesión vieja (matando el subprocess que la colgó, si es stdio) y abre una nueva antes del siguiente test, para no arrastrar estado envenenado |

## 9. Tests (solo `scan`)

*Oculto en `vet`/`full` — en esos modos corren todos, no hay nada para elegir.*

Checkboxes agrupados por categoría (`recon`, `static`, `dynamic`,
`adversarial`, `auth`, `exposure`, `supplychain`), cargados en vivo desde el
motor (`GET /api/tests` — mismo registro interno que `./ares.sh list-tests`,
así que un test nuevo que agregues al código aparece acá solo, sin tocar
el HTML).

- Vienen **pre-tildados** los que tienen `default_enabled=true` — los
  mismos que correrían con `./ares.sh scan` sin pasar `--tests`. Podés
  destildar cualquiera, o tildar los opt-in (los que vienen sin marcar) si
  los querés incluir.
- El ícono **⚠️ red externa** al lado de un test significa que además
  necesita el checkbox **`--allow-network`** de Opciones (§7) tildado — si
  no, ese test se salta aunque esté tildado acá.
- No hay un botón "marcar todos" — para correr TODO (incluidos los
  opt-in), usá el modo `vet` en vez de tildar uno por uno.

---

## 10. Correr y leer el resultado

### 10.1 Resultado de `scan`/`vet`

**▶ Correr** abre una conexión WebSocket (`/ws/scan`), manda toda la config
de una vez, y desde ahí:

- El panel de **log** (caja negra) muestra cada test en vivo, mismo formato
  que la consola de la CLI: `▶ test_id — nombre` al arrancar,
  `🔴`/`🟢` + conteo de findings al terminar cada uno, errores o timeouts
  si algún test falla, y una línea de "reducción de ruido" si el
  allowlist/piso de confidence suprimió algo. Con **`--verbose`** tildado
  (§7), además aparece una línea `→` (request) y `←` (response) por cada
  llamada real que hace el test — `list_tools`, `call_tool`, `read_resource`
  — con el tiempo que tardó.
- Al terminar aparece el **resultado**: cantidad de hallazgos confirmados
  (y suprimidos, si aplica `--allowlist`/`--min-confidence`), score 0-100 +
  grade, un banner de color con el veredicto de policy (rojo=`BLOCK`,
  ámbar=`CONDITIONAL`, verde=`ALLOW`), el resumen de baseline si diste
  `--baseline`, el resumen de impacto de auth si tildaste `--compare-auth`,
  y links directos a los tres formatos de reporte: **HTML** (navegable),
  **JSON** (estructurado) y **SARIF** (para CI). Si corriste
  `--compare-auth`, aparece además el link al reporte de la corrida SIN auth.
- Para un target `http`/`sse` con TLS, aparece también una **tarjeta de
  certificado** que identifica el tipo de certificado que presenta el server,
  sin tener que abrir el HTML:
  - **Normal — firmado por CA pública** (borde verde): valida contra el trust
    store estándar.
  - **Normal — firmado por CA interna/privada** (borde verde): valida contra
    la CA que pasaste en `--ca-bundle` (§7).
  - **Autofirmado (self-signed)** (borde ámbar): emisor == sujeto, no lo
    respalda ninguna CA.
  - **Cadena desconocida / no confiable** o **EXPIRADO** (borde ámbar).

  La tarjeta muestra además emisor, sujeto, validez, versión de TLS,
  algoritmo de firma y tipo de clave (si `cryptography` está instalada), y el
  fingerprint SHA-256. Es el mismo dato que el test `exposure.certificate_type`
  deja en el reporte.

  La tarjeta trae además un **Dictamen** minucioso y graduado en tres niveles,
  con el color del borde según el veredicto:
  - **NO es un riesgo** (verde): cadena de confianza (CA pública, o autofirmado
    validado con tu `--ca-bundle`), vigente y con criptografía sana.
  - **Riesgo posible pero MANEJABLE** (ámbar): autofirmado en un endpoint
    **interno** (IP privada/loopback), por lo demás sano — el MITM requiere estar
    en esa red; se recomienda formalizar la confianza (CA interna o pinning).
  - **RIESGO** (rojo): autofirmado público, cadena desconocida, o confiable pero
    defectuoso (expirado, firma SHA-1/MD5, clave <2048, hostname que no coincide).

  Debajo del dictamen, una fila **Factores** enumera cada señal evaluada con su
  signo (✓/⚠/✗/ℹ): cadena de confianza, vigencia, hostname, firma, clave y
  alcance de red. Cuando hay riesgo, la fila **Riesgo** muestra la severidad
  (Medium para manejable, High para riesgo real; con CVSS) y los frameworks que
  lo marcan — **MCP07:2025** (Transport Security), **API8:2023** (Security
  Misconfiguration) y **CWE-295** (Improper Certificate Validation).
- Los reportes se guardan solos en `reports/<scan_id>/` — no hay opción de
  "no guardar" desde el dashboard (para eso, la CLI con `--no-file`).

### 10.2 Resultado de `full`

**▶ Correr full** abre `/ws/full` y corre todos los targets seleccionados
en simultáneo (hasta la Concurrencia que pusiste):

- El log muestra el progreso de **cada target por separado**, con prefijo
  `[nombre-del-target]` en cada línea, para no perderte entre corridas en
  paralelo.
- Al terminar aparece una **tabla resumen**: un renglón por target con
  hallazgos confirmados, grade, veredicto de policy, y links a su HTML/JSON
  — un target que falló (conexión rechazada, timeout) aparece marcado como
  `error` sin abortar a los demás.
- Si 2+ targets terminaron bien, aparece además el panel de
  **correlación cross-server** — algo que ningún scan de un solo target
  puede ver:
  - **Tool shadowing** (MCP09:2025): un tool con nombre idéntico o casi
    idéntico en dos servers distintos, o una descripción que menciona con
    lenguaje directivo ("usar X en vez de", "siempre llamar a") el tool de
    OTRO server conectado.
  - **Cadenas de exfiltración cross-server**: un tool lector en el server A
    + un tool emisor en el server B — invisible para
    `supplychain.exfiltration_chain` (que solo mira dentro de un mismo
    server).
  - Se guarda también en `reports/<scan_id>/cross_server_correlation.json`.
  - Si no hay 2+ targets ok, o no se encontró nada, el panel avisa
    explícitamente "sin indicios" — nunca queda en silencio.

## 11. Pestaña "Reportes anteriores"

Tabla de todos los scans corridos desde **este** dashboard (no los que
corriste por CLI — esos van a `reporte.html`/`.json` donde les hayas dicho
con `--out`, no a `reports/`). Por cada uno: target, modo (`scan`/`vet`/`full`),
fecha, score, veredicto de policy, y un link **"ver"** al HTML — los
targets que vinieron de una corrida `full` aparecen marcados con la
etiqueta `full` al lado del nombre. El índice completo vive en
`reports/index.json` (carpeta que está en `.gitignore`, no se versiona).

---

## 12. Lo poco que sigue siendo CLI-only

El dashboard ya cubre los tres modos y prácticamente todos los flags de la
CLI. Lo que queda afuera, a propósito, es lo que no tiene sentido en un
formulario de scan interactivo:

| Solo por CLI | Por qué no está en el dashboard |
|---|---|
| `--no-file` / `--print` | El dashboard siempre guarda en `reports/` y siempre muestra el resultado en pantalla — no existe un "modo silencioso" para algo interactivo |
| `--baseline-dir` (baseline distinto por-target, automático en `full`) | En el dashboard, el `--baseline` de `full` (§8) se aplica igual a TODOS los targets del batch; para un baseline distinto por target, usá la CLI |
| `--no-cross-server` | El dashboard siempre corre la correlación cross-server si hay 2+ targets; para desactivarla, usá la CLI |
| `update-rules` / `check-frameworks` como comandos sueltos | No tienen campos que llenar (refrescan/verifican un cache) — corré directo por terminal: `./ares.sh update-rules` / `./ares.sh check-frameworks` |
| `serve --token` / `ARES_DASHBOARD_TOKEN` | Es un flag de ARRANQUE del dashboard (gate de acceso a TODO el dashboard), no un parámetro de scan — se configura al correr `./ares.sh serve --token ...`, antes de abrir el navegador, no desde un formulario adentro |

`list-tests` **sí** está cubierto — es exactamente la lista de checkboxes
de la sección Tests (§9), cargada en vivo del mismo registro.

## 13. Flujos de ejemplo completos

**Auditar un MCP remoto con token, comparando qué protege la auth de verdad:**
1. Modo `scan`.
2. Target (§4): Transporte `http` → URL de tu server.
3. Autenticación (§6): Tipo `bearer` → Token con tu credencial real →
   tildás **`--compare-auth`**.
4. Opciones (§7) y Tests (§9): dejás todo en default.
5. **▶ Correr scan** → mirás "impacto de auth" en el resultado: si hay
   hallazgos que **NO** se mitigan con la auth, son explotables igual
   estando logueado — abrís el reporte HTML para el detalle completo.

**Auditoría exhaustiva antes de poner un MCP en producción:**
1. Modo `vet`.
2. Target (§4): tu server (stdio o http).
3. Si tenés el código a mano, `--source-path` en Opciones (§7) para sumar
   chequeo de dependencias + SAST.
4. **▶ Correr vet** → revisás el banner de policy: `BLOCK` = no apto tal
   como está.

**Auditar todo lo que tengo conectado, y detectar si un server se hace pasar por otro:**
1. Modo `full`.
2. Click en "Descubrir servers configurados localmente" (§4) y tildás los
   que querés incluir (o pegás un Config JSON en §5).
3. Dejás Modo por target en `vet` (default) y Concurrencia en `3`.
4. **▶ Correr full** → además de la tabla resumen por target, revisás el
   panel de correlación cross-server.

**Re-auditar algo que ya escaneaste antes, y enterarte solo si empeoró:**
1. Modo `scan` o `vet`, el target de siempre.
2. Avanzado (§8): `--baseline` apuntando al `reporte.json` de la corrida
   anterior, y `--webhook-on-regression` con tu URL si querés que te avisen
   sin tener que mirar el dashboard.
3. **▶ Correr** → si no hay hallazgos nuevos, no se manda ningún webhook;
   si hay, revisás el resumen de baseline en el resultado.
