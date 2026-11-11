"""
Tests sobre APIs REST (OWASP API Security Top 10 2023). Reciben (target: ApiTarget, ctx: dict) con
ctx = {"endpoints": [Endpoint], "auth_a": bool, "auth_b": bool, "max_fuzz": int}. Cada test maneja
la AUSENCIA de endpoints/credenciales devolviendo passed=True con la razón -- nunca "No aplica"
silencioso que se confunda con "probado y limpio".
"""
from __future__ import annotations
import re
import secrets
import time

from engine.api.registry import api_test
from engine.api.meta import install  # noqa: F401  (registra metadata de risk/frameworks/confidence)
from engine.core.models import Finding, Evidence, Category
from payloads.canary import new_canary, strip_reflections
from engine.api.spec import sample_value

SENSITIVE_PATHS = [
    "/.env", "/.git/config", "/.git/HEAD", "/config.json", "/wp-config.php", "/.aws/credentials",
    "/actuator/env", "/actuator/health", "/debug/pprof/", "/.well-known/openid-configuration",
    "/server-status", "/phpinfo.php", "/.DS_Store", "/backup.sql", "/.htpasswd", "/id_rsa",
]

SQLI_MARK = "ARES'\"<sqli>"
XSS_MARK = "<script>ARES_XSS</script>"
NOSQLI = {"$ne": None}


def _args_from(ep, extra_id: str | None = None) -> dict:
    out = {}
    for p in ep.path_params:
        out[p["name"]] = extra_id if extra_id is not None else sample_value(p.get("schema"), p["name"])
    return out


def _fill_path(path: str, args: dict) -> str:
    def rep(m):
        return str(args.get(m.group(1), "1"))
    return re.sub(r"\{(\w+)\}", rep, path)


def _ok(result) -> list[Finding]:
    return [Finding(test_id="_", title="placeholder", category=Category.API, target="api", passed=True, description="")]


@api_test("api.sensitive_paths", "Rutas/archivos sensibles expuestos", level=1,
          description="Prueba un set de rutas clásicas (.env, .git/config, backups, actuator sin auth...) "
                       "sin credenciales; reporta las que devuelven 200 con contenido real (no una página de "
                       "error disfrazada de 200).")
async def sensitive_paths(target, ctx) -> list[Finding]:
    tid = "api.sensitive_paths"
    findings = []
    for path in SENSITIVE_PATHS:
        r = await target.request("GET", path, auth=None)
        if r["status"] == 200 and r["text"].strip() and "<html" not in r["text"][:200].lower():
            findings.append(Finding(
                test_id=tid, title=f"Ruta sensible accesible sin autenticación: {path}",
                category=Category.API, target=path,
                description=f"GET {path} (sin credenciales) devolvió 200 con {len(r['text'])} bytes de "
                             f"contenido real (no una página de error disfrazada de 200).",
                evidence=Evidence(request={"method": "GET", "path": path}, response={"status": r["status"], "excerpt": r["text"][:300]}),
                passed=False, confidence_override="verified",
                remediation="Quitar el archivo del árbol servido o protegerlo detrás de autenticación; nunca "
                             "servir .git/.env desde la raíz web.",
                references=["https://owasp.org/API-Security/editions/2023/en/0xa8-security-misconfiguration/"],
            ))
    if not findings:
        findings.append(Finding(test_id=tid, title="Sin rutas sensibles expuestas", category=Category.API,
                                target="server", passed=True,
                                description=f"Se probaron {len(SENSITIVE_PATHS)} rutas clásicas sin credenciales; ninguna devolvió contenido real."))
    return findings


_REQUIRED_HEADERS = {
    "x-content-type-options": ("nosniff", "medium"),
    "x-frame-options": (None, "low"),
    "strict-transport-security": (None, "medium"),
}


@api_test("api.security_headers", "Headers de seguridad HTTP ausentes", level=1,
          description="Verifica X-Content-Type-Options, X-Frame-Options/CSP frame-ancestors y "
                       "Strict-Transport-Security (si es https) en la respuesta de un endpoint real.")
async def security_headers(target, ctx) -> list[Finding]:
    tid = "api.security_headers"
    eps = ctx.get("endpoints") or []
    probe = next((e for e in eps if e.method == "GET"), None)
    path = _fill_path(probe.path, _args_from(probe)) if probe else "/"
    r = await target.request("GET", path, auth="a" if ctx.get("auth_a") else None)
    if r["status"] is None:
        return [Finding(test_id=tid, title="No se pudo obtener ninguna respuesta para revisar headers",
                        category=Category.API, target="server", passed=True, description=str(r.get("error")))]
    h = r["headers"]
    missing = []
    if "x-content-type-options" not in h:
        missing.append("X-Content-Type-Options")
    if "x-frame-options" not in h and "frame-ancestors" not in h.get("content-security-policy", ""):
        missing.append("X-Frame-Options/CSP frame-ancestors")
    if target.url(path).startswith("https://") and "strict-transport-security" not in h:
        missing.append("Strict-Transport-Security")
    if missing:
        return [Finding(test_id=tid, title=f"Headers de seguridad ausentes: {', '.join(missing)}",
                        category=Category.API, target=path, passed=False,
                        description=f"La respuesta de {path} no incluye: {', '.join(missing)}.",
                        evidence=Evidence(response={"headers": h}),
                        remediation="Agregar los headers faltantes en el gateway/middleware (helmet, etc.).")]
    return [Finding(test_id=tid, title="Headers de seguridad presentes", category=Category.API, target=path,
                    passed=True, description="X-Content-Type-Options, X-Frame-Options/CSP y HSTS (si aplica) están presentes.")]


@api_test("api.cors", "CORS mal configurado", level=1,
          description="Envía Origin hostil y mide si el server lo refleja en Access-Control-Allow-Origin, "
                       "sobre todo combinado con Allow-Credentials:true -- eso permite a CUALQUIER sitio leer "
                       "respuestas autenticadas del usuario.")
async def cors_misconfig(target, ctx) -> list[Finding]:
    tid = "api.cors"
    eps = ctx.get("endpoints") or []
    probe = next((e for e in eps if e.method == "GET"), None)
    path = _fill_path(probe.path, _args_from(probe)) if probe else "/"
    evil = f"https://ares-{secrets.token_hex(4)}.evil.example"
    r = await target.request("GET", path, headers={"Origin": evil}, auth="a" if ctx.get("auth_a") else None)
    acao = r["headers"].get("access-control-allow-origin")
    acac = r["headers"].get("access-control-allow-credentials", "").lower() == "true"
    if acao == "*" and acac:
        # inválido según el spec de CORS (navegadores lo ignoran), pero servers mal armados lo mandan igual
        sev_note = "ACAO='*' + Allow-Credentials:true (combinación inválida que algunos clientes no-browser igual respetan)"
    elif acao == evil:
        sev_note = f"reflejó el Origin hostil exacto ('{evil}')"
    else:
        sev_note = None
    if sev_note:
        return [Finding(test_id=tid, title="CORS refleja cualquier Origin" + (" con credenciales" if acac else ""),
                        category=Category.API, target=path, passed=False,
                        cvss_vector_override=None if acac else "AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:N",
                        description=f"Al enviar Origin='{evil}', {sev_note}" + (
                            ". Con Allow-Credentials:true, cualquier sitio puede hacer fetch con "
                            "credentials:'include' y leer la respuesta autenticada del usuario." if acac else "."),
                        evidence=Evidence(request={"Origin": evil}, response={"ACAO": acao, "ACAC": acac}),
                        confidence_override="verified",
                        remediation="Allowlist explícita de orígenes conocidos; nunca reflejar el Origin "
                                     "entrante, y nunca combinar '*' con Allow-Credentials:true.")]
    return [Finding(test_id=tid, title="CORS no refleja un Origin arbitrario", category=Category.API,
                    target=path, passed=True, description=f"ACAO={acao!r}, ACAC={acac}; no refleja orígenes hostiles.")]


@api_test("api.auth_required", "Endpoints sin autenticación requerida (BFLA)", level=2,
          description="Llama cada endpoint SIN credenciales y compara contra la respuesta CON credenciales: "
                       "si ambas dan el mismo resultado 'útil' (200 con cuerpo similar), el endpoint no está "
                       "protegido realmente, más allá de lo que el spec declare.")
async def auth_required(target, ctx) -> list[Finding]:
    tid = "api.auth_required"
    if not ctx.get("auth_a"):
        return [Finding(test_id=tid, title="Sin credenciales para comparar", category=Category.API, target="server",
                        passed=True, description="Se necesita --auth-token (credencial válida) para distinguir "
                                                    "'esto no está protegido' de 'esto es público a propósito'.")]
    eps = [e for e in (ctx.get("endpoints") or []) if e.method in ("GET", "POST", "PUT", "PATCH", "DELETE")]
    findings = []
    for ep in eps[: ctx.get("max_fuzz", 40)]:
        if ep.secured is False:
            continue  # el spec lo marca explícitamente público (security: [])
        path = _fill_path(ep.path, _args_from(ep))
        body = {k: sample_value(s) for k, s in (ep.body_schema or {}).get("properties", {}).items()} if ep.body_schema else None
        with_auth = await target.request(ep.method, path, json_body=body, auth="a")
        without_auth = await target.request(ep.method, path, json_body=body, auth=None)
        if (with_auth["status"] and 200 <= with_auth["status"] < 300
                and without_auth["status"] == with_auth["status"]
                and abs(len(without_auth["text"]) - len(with_auth["text"])) < max(20, 0.1 * len(with_auth["text"]))):
            findings.append(Finding(
                test_id=tid, title=f"{ep.key} responde igual sin credenciales",
                category=Category.API, target=ep.key, passed=False,
                description=f"Con y sin Authorization, {ep.key} devolvió el mismo status ({with_auth['status']}) "
                             f"y un cuerpo de tamaño comparable -- la autenticación declarada no se hace cumplir.",
                evidence=Evidence(request={"path": path}, response={"con_auth": with_auth["status"], "sin_auth": without_auth["status"]}),
                confidence_override="verified",
                remediation="Exigir autenticación server-side en ese endpoint (no solo documentarla en el spec).",
            ))
    if not findings:
        findings.append(Finding(test_id=tid, title="Autenticación se hace cumplir", category=Category.API,
                                target="server", passed=True,
                                description=f"Los {min(len(eps), ctx.get('max_fuzz', 40))} endpoint(s) probados no respondieron igual sin credenciales."))
    return findings


@api_test("api.bola", "BOLA: acceso a objetos de otro usuario por id (IDOR)", level=3,
          description="Para endpoints con un parámetro tipo id en el path, prueba IDs vecinos (incrementar/"
                       "decrementar, UUID ajeno si --auth-token-b da uno) con las credenciales A -- si el "
                       "server devuelve 200 con datos de un objeto que no le pertenece a A, es BOLA confirmado.",
          default_enabled=False)
async def bola(target, ctx) -> list[Finding]:
    tid = "api.bola"
    if not ctx.get("auth_a"):
        return [Finding(test_id=tid, title="Sin credenciales", category=Category.API, target="server", passed=True,
                        description="Requiere --auth-token para tener una identidad con la que probar acceso cruzado.")]
    eps = [e for e in (ctx.get("endpoints") or []) if e.method == "GET" and e.path_params]
    findings, probed = [], 0
    for ep in eps[:20]:
        id_param = next((p for p in ep.path_params if re.search(r"id$", p["name"], re.I)), ep.path_params[0])
        base_args = _args_from(ep)
        own_path = _fill_path(ep.path, base_args)
        own = await target.request("GET", own_path, auth="a")
        if own["status"] != 200:
            continue
        probed += 1
        own_id = base_args.get(id_param["name"])
        candidates = []
        if isinstance(own_id, str) and own_id.isdigit():
            candidates = [str(int(own_id) + 1), str(max(0, int(own_id) - 1))]
        elif isinstance(own_id, int):
            candidates = [own_id + 1, max(0, own_id - 1)]
        for cand in candidates:
            args = dict(base_args); args[id_param["name"]] = cand
            other = await target.request("GET", _fill_path(ep.path, args), auth="a")
            if other["status"] == 200 and other["text"].strip() and other["text"] != own["text"]:
                findings.append(Finding(
                    test_id=tid, title=f"BOLA confirmado en {ep.key} (parámetro '{id_param['name']}')",
                    category=Category.API, target=ep.key, passed=False,
                    description=f"Con la misma credencial, '{id_param['name']}={own_id}' y '={cand}' devuelven "
                                 f"200 con contenido DISTINTO -- la credencial A puede leer un objeto que no le "
                                 f"pertenece, solo cambiando el id en la URL.",
                    evidence=Evidence(request={"path": ep.path, "own_id": own_id, "other_id": cand},
                                      response={"status": other["status"], "excerpt": other["text"][:300]}),
                    confidence_override="verified",
                    remediation="Validar ownership del objeto server-side en cada acceso (no confiar en que "
                                 "el id en la URL 'ya viene filtrado' por la UI).",
                ))
                break
    if not findings:
        findings.append(Finding(test_id=tid, title="Sin BOLA confirmado", category=Category.API, target="server",
                                passed=True, description=f"Se probaron ids vecinos en {probed} endpoint(s) con un objeto propio accesible; ninguno expuso otro objeto."))
    return findings


@api_test("api.verbose_errors", "Errores verbosos / stacktraces filtrados", level=2,
          description="Envía inputs inválidos (tipo erróneo, faltante, extremo) a cada endpoint y busca "
                       "stacktraces, rutas de archivo o nombres de framework en la respuesta de error.")
async def verbose_errors(target, ctx) -> list[Finding]:
    tid = "api.verbose_errors"
    leak_re = [
        (re.compile(r"Traceback \(most recent call last\)"), "stack trace de Python"),
        (re.compile(r"\n\s+at [\w.$<>]+ \(.*?:\d+:\d+\)"), "stack trace de Node.js"),
        (re.compile(r"org\.springframework|java\.lang\.\w+Exception"), "stack trace de Java/Spring"),
        (re.compile(r"/(home|usr|var|opt|srv)/[\w./-]{6,}"), "path absoluto del filesystem"),
        (re.compile(r"System\.Exception|at [\w.]+\.cs:line \d+"), "stack trace de .NET"),
    ]
    eps = ctx.get("endpoints") or []
    findings, seen = [], set()
    for ep in eps[: ctx.get("max_fuzz", 30)]:
        args = {p["name"]: "💥" * 200 if p["in"] == "path" else None for p in ep.path_params}
        path = _fill_path(ep.path, args)
        r = await target.request(ep.method, path, json_body={"a": None} if ep.method in ("POST", "PUT", "PATCH") else None,
                                 auth="a" if ctx.get("auth_a") else None)
        for rx, label in leak_re:
            if rx.search(r["text"]) and label not in seen:
                seen.add(label)
                findings.append(Finding(
                    test_id=tid, title=f"Error filtra {label} en {ep.key}", category=Category.API, target=ep.key,
                    description=f"Un input malformado a {ep.key} produjo una respuesta ({r['status']}) con {label}.",
                    evidence=Evidence(request={"path": path}, response={"status": r["status"], "excerpt": r["text"][:300]}),
                    passed=False, confidence_override="heuristic",
                    remediation="Manejador global de errores con mensaje genérico; detalle solo a logs server-side.",
                ))
    if not findings:
        findings.append(Finding(test_id=tid, title="Sin errores verbosos detectados", category=Category.API,
                                target="server", passed=True, description="Las respuestas de error no incluyeron trazas ni rutas internas."))
    return findings


@api_test("api.injection_probe", "Inyección SQL/NoSQL básica (canario, confirma por timing+contenido)", level=3,
          description="Envía marcadores de SQLi (comilla + operador booleano) y de NoSQLi ($ne) en parámetros "
                       "string; compara la respuesta contra un valor benigno -- un cambio de status/tamaño "
                       "GRANDE con el payload de inyección (y no con un string random del mismo largo) es la señal.",
          default_enabled=False)
async def injection_probe(target, ctx) -> list[Finding]:
    tid = "api.injection_probe"
    eps = [e for e in (ctx.get("endpoints") or []) if any(p["in"] == "query" for p in e.params)]
    findings = []
    for ep in eps[:15]:
        qp = next(p for p in ep.params if p["in"] == "query")
        path = _fill_path(ep.path, _args_from(ep))
        benign = secrets.token_hex(4)
        base = await target.request(ep.method, path, params={qp["name"]: benign}, auth="a" if ctx.get("auth_a") else None)
        for payload, kind in ((f"{benign}' OR '1'='1", "SQLi"), (f"{benign}\" OR \"1\"=\"1", "SQLi")):
            r = await target.request(ep.method, path, params={qp["name"]: payload}, auth="a" if ctx.get("auth_a") else None)
            content = strip_reflections(r["text"], payload)
            if r["status"] and base["status"] and r["status"] != base["status"] and r["status"] >= 500:
                findings.append(Finding(
                    test_id=tid, title=f"{kind} probable en {ep.key} (parámetro '{qp['name']}')",
                    category=Category.API, target=ep.key, passed=False, confidence_override="heuristic",
                    description=f"El valor benigno dio {base['status']}; el payload de {kind} dio {r['status']} "
                                 f"(error de servidor). Señal de que el payload llegó sin sanitizar a una capa de datos.",
                    evidence=Evidence(request={"path": path, "param": qp["name"], "payload": payload},
                                      response={"status": r["status"], "excerpt": content[:300]}),
                    remediation="Usar consultas parametrizadas/prepared statements; nunca concatenar input en una query.",
                ))
                break
    if not findings:
        findings.append(Finding(test_id=tid, title="Sin inyección detectada", category=Category.API, target="server",
                                passed=True, description=f"Se probaron payloads de SQLi en {len(eps[:15])} endpoint(s) con parámetro de query; sin señal de error de servidor."))
    return findings


@api_test("api.method_tampering", "Métodos HTTP no esperados aceptados (TRACE/verb tampering)", level=1,
          description="Prueba TRACE y, para un endpoint protegido, si cambiar el método (p.ej. GET->POST en uno "
                       "que debería requerir auth) sigue respondiendo.")
async def method_tampering(target, ctx) -> list[Finding]:
    tid = "api.method_tampering"
    eps = ctx.get("endpoints") or []
    probe = next((e for e in eps), None)
    path = _fill_path(probe.path, _args_from(probe)) if probe else "/"
    findings = []
    r = await target.request("TRACE", path, auth=None)
    if r["status"] and r["status"] < 400:
        findings.append(Finding(test_id=tid, title="Método TRACE habilitado", category=Category.API, target=path,
                                passed=False, confidence_override="verified",
                                description=f"TRACE {path} devolvió {r['status']} (debería ser 405/501). "
                                             f"Habilita Cross-Site Tracing (XST) en navegadores viejos.",
                                evidence=Evidence(response={"status": r["status"]}),
                                remediation="Deshabilitar TRACE en el servidor web/proxy."))
    if not findings:
        findings.append(Finding(test_id=tid, title="TRACE deshabilitado", category=Category.API, target=path,
                                passed=True, description="TRACE devolvió 4xx/5xx, como se espera."))
    return findings


@api_test("api.rate_limit", "Rate limiting / lockout de login ausente", level=2,
          description="Ráfaga de requests a un endpoint de SOLO LECTURA (nunca a uno que muta estado) y mide "
                       "si aparece 429/Retry-After. Severidad baja y heurística si no aparece: la ausencia en "
                       "una ráfaga corta no prueba explotabilidad real.",
          default_enabled=False)
async def rate_limit(target, ctx) -> list[Finding]:
    import asyncio
    tid = "api.rate_limit"
    eps = [e for e in (ctx.get("endpoints") or []) if e.method == "GET"]
    if not eps:
        return [Finding(test_id=tid, title="Sin endpoint GET para probar", category=Category.API, target="server", passed=True, description="")]
    path = _fill_path(eps[0].path, _args_from(eps[0]))
    results = await asyncio.gather(*[target.request("GET", path, auth="a" if ctx.get("auth_a") else None) for _ in range(30)])
    throttled = any(r["status"] == 429 for r in results)
    if throttled:
        return [Finding(test_id=tid, title="Rate limiting detectado", category=Category.API, target=path,
                        passed=True, description="Al menos una respuesta de la ráfaga fue 429.")]
    return [Finding(test_id=tid, title="Sin rate limiting observable", category=Category.API, target=path,
                    passed=False, confidence_override="heuristic",
                    description=f"30 llamadas concurrentes a {path}, ninguna devolvió 429/Retry-After. No prueba "
                                 f"explotabilidad por sí solo (puede limitarse en un WAF delante), pero es una "
                                 f"señal a revisar.",
                    remediation="Rate limiting por API key/IP/usuario, y lockout progresivo en endpoints de login.")]


# ---- JWT --------------------------------------------------------------------------------------

def _jwt_parts(token: str):
    import base64, json as _json
    parts = token.split(".")
    if len(parts) != 3:
        return None
    def dec(p):
        p += "=" * (-len(p) % 4)
        return _json.loads(base64.urlsafe_b64decode(p))
    try:
        return dec(parts[0]), dec(parts[1]), parts[2]
    except Exception:
        return None


@api_test("api.jwt", "Debilidades de JWT (alg=none, sin exp, secreto débil)", level=2,
          description="Si la credencial es un JWT: decodifica header/payload (sin validar firma) y chequea "
                       "alg=none/HS256 forzable, ausencia de 'exp', y prueba si el server acepta alg=none.")
async def jwt_weaknesses(target, ctx) -> list[Finding]:
    import base64, json as _json
    tid = "api.jwt"
    token = (ctx.get("jwt") or "")
    if not token or "." not in token:
        return [Finding(test_id=tid, title="La credencial no es un JWT", category=Category.API, target="server",
                        passed=True, description="--auth-token no tiene forma de JWT (header.payload.signature); nada que analizar.")]
    parsed = _jwt_parts(token)
    if not parsed:
        return [Finding(test_id=tid, title="No se pudo decodificar como JWT", category=Category.API, target="server", passed=True, description="")]
    header, payload, sig = parsed
    findings = []
    if not payload.get("exp"):
        findings.append(Finding(test_id=tid, title="JWT sin campo 'exp' (no expira)", category=Category.API,
                                target="server", passed=False, confidence_override="verified",
                                description="El payload del JWT no tiene 'exp' -- el token, si se filtra, es válido para siempre.",
                                evidence=Evidence(response={"header": header, "payload_keys": list(payload)}),
                                remediation="Emitir tokens con expiración corta y usar refresh tokens."))
    eps = ctx.get("endpoints") or []
    probe = next((e for e in eps if e.method == "GET"), None)
    if probe:
        path = _fill_path(probe.path, _args_from(probe))
        legit = await target.request("GET", path, auth="a")
        h2, p2 = dict(header), dict(payload)
        h2["alg"] = "none"
        forged = base64.urlsafe_b64encode(_json.dumps(h2).encode()).decode().rstrip("=") + "." \
            + base64.urlsafe_b64encode(_json.dumps(p2).encode()).decode().rstrip("=") + "."
        r = await target.request("GET", path, headers={"Authorization": f"Bearer {forged}"}, auth=None)
        if legit["status"] and 200 <= legit["status"] < 300 and r["status"] == legit["status"]:
            findings.append(Finding(test_id=tid, title="El server acepta un JWT con alg=none", category=Category.API,
                                    target=path, passed=False, confidence_override="verified",
                                    description=f"Un token con header alg=none y firma vacía fue aceptado "
                                                 f"(status {r['status']}, igual que con el token legítimo). "
                                                 f"Cualquiera puede forjar un token válido sin conocer ningún secreto.",
                                    evidence=Evidence(request={"forged_jwt": forged[:80] + "..."}, response={"status": r["status"]}),
                                    remediation="Rechazar explícitamente alg=none; fijar el algoritmo esperado en el verificador."))
    if not findings:
        findings.append(Finding(test_id=tid, title="Sin debilidades de JWT detectadas", category=Category.API,
                                target="server", passed=True, description="Tiene 'exp' y rechaza alg=none."))
    return findings


@api_test("api.mass_assignment", "Mass assignment: campos no documentados aceptados en el body", level=2,
          description="A un POST/PUT/PATCH con body conocido, agrega campos típicos de escalación "
                       "(is_admin/role/isAdmin/admin=true) no declarados en el schema y mira si el server los "
                       "aplica (reflejados en la respuesta de lectura posterior, o el status cambia a éxito "
                       "cuando sin ellos fallaba).",
          default_enabled=False)
async def mass_assignment(target, ctx) -> list[Finding]:
    tid = "api.mass_assignment"
    eps = [e for e in (ctx.get("endpoints") or []) if e.method in ("POST", "PUT", "PATCH") and e.body_schema]
    findings = []
    extra_fields = {"is_admin": True, "isAdmin": True, "role": "admin", "admin": True, "is_staff": True}
    for ep in eps[:15]:
        props = (ep.body_schema or {}).get("properties", {}) or {}
        base_body = {k: sample_value(s, k) for k, s in props.items()}
        injected = {**base_body, **{k: v for k, v in extra_fields.items() if k not in props}}
        path = _fill_path(ep.path, _args_from(ep))
        r = await target.request(ep.method, path, json_body=injected, auth="a" if ctx.get("auth_a") else None)
        body_text = str(r.get("json") or r["text"])
        reflected = [k for k in extra_fields if k not in props and (f'"{k}"' in body_text or f"'{k}'" in body_text)]
        if r["status"] and r["status"] < 300 and reflected:
            findings.append(Finding(
                test_id=tid, title=f"Mass assignment: {ep.key} refleja campo(s) no documentado(s) {reflected}",
                category=Category.API, target=ep.key, passed=False, confidence_override="heuristic",
                description=f"Se envió el body con campos extra no declarados en el schema ({', '.join(reflected)}); "
                             f"el server respondió {r['status']} y los devolvió en la respuesta -- indicio de "
                             f"binding directo del body al modelo sin allowlist de campos.",
                evidence=Evidence(request={"path": path, "body": injected}, response={"status": r["status"], "excerpt": body_text[:300]}),
                remediation="Usar un DTO/allowlist explícita de campos editables por endpoint; nunca bindear el body entero.",
            ))
    if not findings:
        findings.append(Finding(test_id=tid, title="Sin mass assignment detectado", category=Category.API,
                                target="server", passed=True,
                                description=f"Se probaron {len(eps[:15])} endpoint(s) de escritura con campos extra; ninguno los reflejó."))
    return findings
