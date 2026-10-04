# ares-range

Rango de práctica propio (no el lab externo de `vulnerable-mcp-servers-lab/`,
que es un repo de terceros clonado aparte) — servers MCP escritos a mano para
auditar a Ares de punta a punta: cobertura de detección real + resiliencia
del propio motor contra un target hostil. Todo lo que hay acá se construyó
y se corrió en la ronda de hardening de 2026-10-03 (ver `reports/` para los
resultados reales, no hipotéticos).

## Qué hay

- **`enterprise_source/server.py`** ("acme-internal-tools") — el target
  flagship: un server interno de empresa ficticio que acumula, a propósito,
  casi todas las clases de vulnerabilidad que Ares detecta en una sola
  corrida (secret_exposure, tool poisoning/line jumping, command injection
  confirmado, path traversal confirmado, BOLA, destructivo sin confirmación,
  code execution vía `eval`, tool squatting, cadena de exfiltración,
  schema/no-schema permisivo) + `requirements.txt` con dependencias viejas
  con CVEs reales (para `supplychain.dependency_vulnerabilities` vía
  OSV.dev) y código que matchea el ruleset semgrep propio (para
  `supplychain.source_sast`).
- **`hostile_to_scanner.py`** — el fixture de resiliencia: ataca al propio
  Ares (no a un agente) con una descripción de tool de ~10MB, una respuesta
  de 300MB, y un tool que nunca responde. Es el regresion-test vivo de la
  ronda de hardening de hoy (ver abajo).
- **`run_range.sh`** — corre Ares contra los 4 targets (los dos de acá +
  `target_server.py`/`target_server_http.py` ya existentes en la raíz del
  repo) y deja reporte HTML/JSON/SARIF por target en `reports/`.
- **`reports/`** — la última corrida real. `03_acme_internal_tools.html` es
  el más representativo para mostrar cobertura end-to-end.

## Qué encontró y corrigió esta ronda sobre el propio Ares

Corriendo esto de verdad (no en teoría) contra el motor:

1. **DoS por tamaño en descripciones/schemas** — una tool con descripción de
   10MB hacía que `supplychain.secret_exposure` (~200 regex) tardara ~57s
   contra ~0.2s de baseline. Fix: `engine/core/limits.py` (cap_text),
   aplicado en `engine/core/client.py` y en los blob-builders de
   `recon/supplychain`. **57s → 2.8s.**
2. **Falso ALLOW cuando el target cuelga un test** — un timeout (ya existía,
   fail-closed) solo quedaba en `report.errors` (texto libre, invisible
   para score/policy): el scan terminaba 100/A/ALLOW igual que un server
   limpio. Fix: el timeout ahora emite un `Finding` real
   (`orchestrator.test_unresponsive`).
3. **Circuit breaker ausente** — un solo tool que nunca responde hacía que
   CADA test que lo toca pagara el timeout completo por separado (4 tests
   default = 4 minutos reales contra `hostile_to_scanner.py`). Fix:
   `ScanConfig.max_consecutive_timeouts` (default 3) corta el resto de la
   batería de una, con un `Finding` propio
   (`orchestrator.target_unresponsive_sustained`) marcando la corrida como
   incompleta.
4. **15 tracebacks duplicados cuando la conexión inicial falla** — cada test
   que asume sesión viva explotaba con un `AttributeError` genérico y
   distinto; el reporte quedaba lleno de ruido. Fix: un mensaje limpio de
   una línea en vez del traceback completo.
5. **Falso positivo "CONFIRMADO" real** — `notify_webhook()` (solo hace
   `urllib.request`, cero sink de shell) salió marcado como command
   injection/path traversal CONFIRMADO. Causa raíz: el payload
   `"\necho {canary}\n"` llega sin los saltos de línea al eco (`urllib.parse`
   le hace `strip()` a una URL inválida antes de citarla en su propio
   error), y `strip_reflections` comparaba el payload exacto sin esa
   normalización — el canario "sobrevivía" sin que nada se haya ejecutado.
   Fix: `payloads/canary.py` ahora prueba también la variante `.strip()`.

Los 5 quedan como tests de regresión en `tests/test_detectors.py` y
`tests/test_unit.py` — correr `pytest tests/` después de cualquier cambio al
motor.

## Uso

```bash
./run_range.sh
```
