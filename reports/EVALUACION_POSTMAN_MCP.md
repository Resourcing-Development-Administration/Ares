# Evaluación de `postman-mcp-server` para infraestructura crítica

**Fecha:** 2026-11-12
**Target evaluado:** `postman-mcp-server` (Postman, Inc.) — tier "minimal" en producción real
(`mcp.postman.com/minimal`) y tier "full" (234 tools) en una instancia local aislada del código
open source oficial.
**Reportes crudos:** ver `reports/index.json` → entradas `27954cf5` (minimal, live),
`945f00c3` (full, local, recon/schema/destructivo), `0ca92e83` (SAST + dependencias). Visibles
en el dashboard (`./ares.sh serve`) bajo "[Evaluación Postman MCP]".

## Resumen ejecutivo

Evaluado en dos frentes: el servidor real de Postman (tier "minimal", solo-lectura/recon,
contra producción con autorización del dueño de la cuenta) y una instancia **local y
completamente aislada** del código open-source oficial (tier "full", incluidos los tools
destructivos), montada contra un backend simulado para poder correr el espectro completo sin
riesgo a la cuenta real ni a la infraestructura de Postman.

**Veredicto: no apto para integrarlo "as-is" contra infraestructura crítica sin mitigaciones.**
No es una vulnerabilidad única y dramática — es un patrón sistemático de falta de barreras de
seguridad en las capas que el tier "full" expone.

## Hallazgos confirmados (por severidad de negocio)

### 🔴 Crítico — tools destructivos sin ningún freno a nivel de protocolo
**25 tools reales** (`deleteCollection`, `deleteWorkspace`, `deleteEnvironment`, `deleteMock`,
`removeTeamMembers`, `removeWorkspaceFromPrivateNetwork`, etc.) **no tienen ningún parámetro
`confirm`/`dry_run` en su schema MCP**. `confidence: verified` — hecho sobre el schema real, no
una sospecha.

Un agente de IA conectado con el tier "full" puede ser inducido (prompt injection indirecto,
alucinación, bug del agente) a borrar permanentemente un workspace/colección/entorno/equipo
**sin ningún punto de control del lado del protocolo**. La única barrera posible es
client-side.

### 🟠 Alto — dependencias vulnerables reales (de producción)
- **`uuid` 13.0.0** — CVSS 7.5 (GHSA-w5hq-g745-h8pq), bounds-check faltante en v3/v5/v6.
- **`zod` 3.25.76** — CVSS 7.5 (GHSA-mrhx-c7xc-m3w5), agotamiento de memoria (DoS) validando
  colecciones muy grandes. `zod` valida el env y probablemente argumentos de tools.
- *(`vitest` 9.8 y 5.9 CVSS también aparecen, pero son del framework de TESTING -- no corren en
  producción. Mencionado para que no quede expuesto el dev server por error, no como riesgo de
  producción real.)*

### 🟡 Medio — permisividad de schema sistemática (verified)
**206 de 234 tools (88%)** tienen parámetros string sin `pattern`/`maxLength`/`enum` --
incluyendo IDs de workspace/colección/environment. No prueba explotación por sí sola, pero es
la superficie típica para inyección si el backend real no revalida estrictamente (no se pudo
confirmar desde este lado).

### 🟡 Medio — sin capability `logging` MCP
Ningún canal estándar de auditoría del lado del cliente.

### ⚪ Descartado tras revisión manual (ruido, no reportar sin verificar)
- 115 hallazgos de "secret_exposure" -- regla genérica de gitleaks conocida por falsos
  positivos; el fragmento redactado no muestra nada concluyente.
- El tier "minimal" (el de uso habitual) **no tiene ningún tool de borrado** -- los 25
  destructivos viven solo en el tier "full".

### 🔧 Hallazgo operacional (no es una vulnerabilidad de Postman)
Bajo sandboxing de memoria estricto (contenedores con límites ajustados, común en infra
crítica), el proceso Node.js puede **crashear por completo** (OOM del compilador WASM de
V8/undici) bajo volumen alto de llamadas HTTP salientes reales. Confirmado que es un problema
de Node/V8 bajo memoria acotada, no un bug de Postman -- pero si se va a correr en un
contenedor con límites de memoria ajustados, probar el comportamiento bajo carga real antes de
confiar en que no se cae.

## Recomendación de viabilidad

- **Tier "minimal": viable con mitigaciones menores** (schema validation, revisar logging).
- **Tier "full": NO conectar a un agente autónomo sin human-in-the-loop explícito** para
  cualquier tool que matchee `delete*`/`remove*` -- el MCP mismo no los protege.
- Reportar a Postman: ausencia de `confirm`/`dry_run` en los 25 tools destructivos del tier
  full, y las 2 CVEs de dependencias de producción (`uuid`, `zod`).

## Metodología y limitaciones (transparencia)

- No se corrió el nivel destructivo/intrusivo contra el endpoint real compartido de Postman
  (autorización no verificable sobre infraestructura de un tercero) -- se usó una instancia
  local del mismo código oficial en su lugar, más representativa para esta pregunta de todos
  modos (evalúa el software, no solo pokea el SaaS).
- El servidor real de Postman tiene rate limiting (`RateLimit-Limit: 100;w=60`) y corta
  conexiones largas bajo volumen -- varios tests (`dynamic.command_injection_confirmed`,
  `dynamic.path_traversal_confirmed`, `dynamic.credential_harvest_paths`, fuzzing de protocolo)
  no pudieron completar contra el tier minimal real por esto.
- Durante esta evaluación se encontraron y corrigieron 7 bugs reales en Ares (BaseExceptionGroup
  no atrapado, circuit breaker incompleto, `vet` sin flags de sandbox, stderr de subprocess no
  expuesto, falsos positivos de regex en `recon.excessive_permissions`/
  `supplychain.malicious_patterns`, calibración de `api.rate_limit`, descubrimiento de
  `semgrep`). Todos documentados en el historial de commits de Ares; la suite completa de tests
  quedó en verde (146 passed) antes de cerrar esta evaluación.
