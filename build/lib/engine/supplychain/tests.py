"""
Tests de supply-chain: secretos filtrados en definiciones, tool squatting /
confused deputy, cadenas de exfiltración lector->emisor, patrones de contenido
malicioso tipo YARA (regex propio, sin dependencia externa), y dependencias
vulnerables (opt-in, requiere --source-path).

Fuentes portadas:
- MCP-Scanner/src/checks/secrets.ts (SECRET_PATTERNS)
- mcp-red-team/src/checks/manifest.ts (jaroWinkler + checkExfiltrationChain)
- mcp-scanner/mcpscanner/core/analyzers/yara_analyzer.py (categorías de reglas,
  reimplementadas acá como regex puro)
- mcp-scanner/mcpscanner/core/analyzers/vulnerable_package_analyzer.py (pip-audit)
"""
from __future__ import annotations
import json
import re

from engine.core.models import Finding, Evidence, Category
from engine.core.risk import build_vector, base_vector_for
from engine.core.registry import register_test
from engine.supplychain.similarity import jaro_winkler
from engine.supplychain.rule_sources import load_secret_patterns
from engine.core.limits import cap_text

# --- secretos ---------------------------------------------------------------

SECRET_PATTERNS = [
    (r"sk-ant-[a-zA-Z0-9\-_]{20,}", "Anthropic API key"),
    (r"sk-[a-zA-Z0-9]{32,}", "OpenAI-style API key"),
    (r"AKIA[0-9A-Z]{16}", "AWS Access Key ID"),
    (r"gh[pousr]_[A-Za-z0-9]{20,}", "GitHub token"),
    (r"xox[baprs]-[A-Za-z0-9-]{10,}", "Slack token"),
    (r"-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----", "Private key block"),
    (r"(postgres|postgresql|mysql|mongodb)://[^:\s]+:[^@\s]+@", "DB URL con credenciales embebidas"),
    (r"Bearer [A-Za-z0-9\-_.]{20,}", "Bearer token embebido"),
    (r"(?i)(api[_-]?key|secret|password)\s*[:=]\s*['\"][^'\"\s]{8,}['\"]", "secreto/password literal"),
]


def _all_text_blobs(tools, resources, prompts, server_info) -> list[tuple[str, str]]:
    # cap_text en cada blob ANTES de que vuelva acá: aunque client.py ya acota la
    # descripción del tool, el schema serializado (json.dumps) puede seguir siendo
    # enorme (ej. un enum con miles de valores) -- esto es lo que corre ~200 regex
    # de secret_exposure encima, así que el cap tiene que estar en el punto donde
    # se arma el blob final, no solo en la fuente. Confirmado: sin esto, una sola
    # descripción de 10MB hacía que supplychain.secret_exposure tardara ~57s.
    blobs = []
    if server_info:
        blobs.append(("server", cap_text(json.dumps(server_info, default=str))))
    for t in tools:
        blob = t.get("description", "") + " " + json.dumps(t.get("input_schema", {}))
        blobs.append((t.get("name", "tool"), cap_text(blob)))
    for r in resources:
        blobs.append((r.get("uri", "resource"), cap_text(r.get("description", "") + " " + r.get("name", ""))))
    for p in prompts:
        blobs.append((p.get("name", "prompt"), cap_text(p.get("description", ""))))
    return blobs


@register_test(
    id="supplychain.secret_exposure",
    name="Secretos expuestos en definiciones",
    category=Category.SUPPLYCHAIN,
    description="Escanea nombre/descripción/schema de tools, resources y prompts en busca de API keys, "
                 "tokens, private keys, o URLs de DB con credenciales embebidas.",
)
async def secret_exposure(target, ctx) -> list[Finding]:
    tools = ctx.get("tools") or await target.list_tools()
    resources = ctx.get("resources") or []
    prompts = ctx.get("prompts") or []
    findings = []
    patterns = SECRET_PATTERNS + load_secret_patterns()  # + cache de 'update-rules' (gitleaks), si existe

    for name, blob in _all_text_blobs(tools, resources, prompts, None):
        for pattern, label in patterns:
            m = re.search(pattern, blob)
            if m:
                sample = m.group(0)
                sample = sample[:6] + "…" + sample[-4:] if len(sample) > 12 else "…"
                findings.append(Finding(
                    test_id="supplychain.secret_exposure",
                    title=f"{label} expuesto en '{name}'",
                    category=Category.SUPPLYCHAIN,
                    target=name,
                    description=f"Se detectó un patrón de {label} en la definición de '{name}'. Muestra: {sample}",
                    passed=False,
                    remediation="Nunca embeber secretos en descripciones/schemas de tools. Usar variables de "
                                 "entorno o un vault, y rotar cualquier credencial expuesta inmediatamente.",
                ))

    if not findings:
        findings.append(Finding(
            test_id="supplychain.secret_exposure", title="Sin secretos detectados",
            category=Category.SUPPLYCHAIN, target="server",
            description="No se encontraron patrones de secretos conocidos en las definiciones analizadas.",
            passed=True,
        ))
    return findings


# --- tool squatting / confused deputy ---------------------------------------

DESTRUCTIVE_KEYWORDS = {"delete", "drop", "remove", "destroy", "wipe", "truncate", "purge", "kill"}
READ_KEYWORDS = {"get", "read", "list", "fetch", "search", "view", "show"}
NAME_SIMILARITY_THRESHOLD = 0.82


@register_test(
    id="supplychain.tool_squatting",
    name="Tool squatting / confused deputy",
    category=Category.SUPPLYCHAIN,
    description="Compara nombres de tools por similitud Jaro-Winkler (umbral 0.82). Pares muy similares "
                 "con intención cruzada (uno destructivo, el otro de lectura) son el vector clásico de "
                 "'confused deputy': el agente llama la tool equivocada por parecido de nombre.",
)
async def tool_squatting(target, ctx) -> list[Finding]:
    tools = ctx.get("tools") or await target.list_tools()
    names = [t["name"] for t in tools]
    findings = []

    for i in range(len(names)):
        for j in range(i + 1, len(names)):
            a, b = names[i], names[j]
            if a == b:
                continue
            sim = jaro_winkler(a.lower(), b.lower())
            if sim < NAME_SIMILARITY_THRESHOLD:
                continue

            a_destructive = any(k in a.lower() for k in DESTRUCTIVE_KEYWORDS)
            b_destructive = any(k in b.lower() for k in DESTRUCTIVE_KEYWORDS)
            a_read = any(k in a.lower() for k in READ_KEYWORDS)
            b_read = any(k in b.lower() for k in READ_KEYWORDS)
            cross_intent = (a_destructive and b_read) or (b_destructive and a_read)

            findings.append(Finding(
                test_id="supplychain.tool_squatting",
                title=f"Nombres de tool casi idénticos: '{a}' / '{b}' (similitud {sim:.3f})",
                category=Category.SUPPLYCHAIN,
                target=f"{a},{b}",
                # intención cruzada (uno destructivo, el otro de lectura) -> el agente podría llamar
                # al destructivo por error; sin eso, es solo un typo-squat sospechoso de menor impacto.
                cvss_vector_override=(build_vector(base_vector_for("supplychain.tool_squatting"), I="H")
                                        if cross_intent else None),
                description=(
                    f"Similitud Jaro-Winkler {sim:.3f} (umbral {NAME_SIMILARITY_THRESHOLD}). "
                    + ("Intención cruzada detectada: uno destructivo y el otro de lectura — riesgo real de "
                       "que el agente invoque el tool equivocado." if cross_intent else
                       "Revisar si ambos nombres son intencionales o uno es un typo-squat.")
                ),
                passed=False,
                remediation="Renombrar para maximizar la distancia léxica entre tools de intención distinta; "
                             "evitar pares de nombres a una edición de distancia.",
            ))

    if not findings:
        findings.append(Finding(
            test_id="supplychain.tool_squatting", title="Sin squatting de nombres detectado",
            category=Category.SUPPLYCHAIN, target="server",
            description="Ningún par de tools superó el umbral de similitud de nombre.",
            passed=True,
        ))
    return findings


# --- cadena de exfiltración lector -> emisor --------------------------------

READER_RE = re.compile(r"read|file|env|secret|config|credential|key|token|password", re.IGNORECASE)
SENDER_RE = re.compile(r"send|post|http|request|webhook|email|upload|exfil|transmit|notify", re.IGNORECASE)


@register_test(
    id="supplychain.exfiltration_chain",
    name="Cadena de exfiltración lector -> emisor",
    category=Category.SUPPLYCHAIN,
    description="Detecta si el servidor expone simultáneamente tools que leen datos sensibles (archivos, "
                 "env, secretos) y tools que envían datos afuera (webhooks, email, HTTP), lo que habilita "
                 "una cadena de exfiltración con dos llamadas de tool encadenadas.",
)
async def exfiltration_chain(target, ctx) -> list[Finding]:
    tools = ctx.get("tools") or await target.list_tools()
    readers = [t["name"] for t in tools if READER_RE.search(t["name"] + " " + t.get("description", ""))]
    senders = [t["name"] for t in tools if SENDER_RE.search(t["name"] + " " + t.get("description", ""))]

    if readers and senders:
        return [Finding(
            test_id="supplychain.exfiltration_chain",
            title="Posible cadena de exfiltración: tools lectoras + tools emisoras",
            category=Category.SUPPLYCHAIN,
            target="server",
            description=f"Tools lectoras de datos sensibles: {readers}. Tools que envían datos afuera: "
                         f"{senders}. Un agente comprometido (vía prompt injection indirecta) puede "
                         f"encadenar lector->emisor para exfiltrar datos sin que ninguna tool individual "
                         f"sea 'maliciosa' por sí sola.",
            passed=False,
            remediation="Requerir confirmación humana explícita antes de que datos leídos de fuentes "
                         "sensibles se pasen a una tool de red/envío en el mismo flujo del agente.",
        )]
    return [Finding(
        test_id="supplychain.exfiltration_chain", title="Sin cadena de exfiltración evidente",
        category=Category.SUPPLYCHAIN, target="server",
        description="No coexisten tools lectoras y emisoras según la heurística de keywords.",
        passed=True,
    )]


# --- patrones maliciosos tipo YARA (regex propio) ---------------------------

MALICIOUS_PATTERN_RULES = [
    ("tool_poisoning", r"ignore (all|previous|the) (instructions|prompt)|do not (tell|inform|mention) the user|secretly|silently"),
    ("code_execution", r"\beval\(|\bexec\(|subprocess\.|os\.system\(|child_process|execSync"),
    ("credential_harvesting", r"(?i)send (your|the) (password|api[_ ]?key|token|credentials)"),
    ("data_exfiltration", r"(?i)(upload|post|send) .{0,30}(to|at) https?://"),
    ("sql_injection_marker", r"(?i)(\bor\b\s+['\"]?1['\"]?\s*=\s*['\"]?1|union\s+select)"),
    ("command_injection_marker", r";\s*(cat|ls|rm|curl|wget)\s|\$\(.*\)|`[^`]+`"),
]


@register_test(
    id="supplychain.malicious_patterns",
    name="Patrones de contenido malicioso (heurística tipo YARA)",
    category=Category.SUPPLYCHAIN,
    description="Banco de regex por categoría (tool poisoning, ejecución de código, robo de credenciales, "
                 "exfiltración, marcadores de SQLi/command injection) aplicado sobre descripciones/schemas. "
                 "Reimplementación propia sin dependencia de yara-python, inspirada en las categorías de "
                 "reglas de mcp-scanner (Cisco).",
)
async def malicious_patterns(target, ctx) -> list[Finding]:
    tools = ctx.get("tools") or await target.list_tools()
    resources = ctx.get("resources") or []
    prompts = ctx.get("prompts") or []
    findings = []

    for name, blob in _all_text_blobs(tools, resources, prompts, None):
        hits = []
        for category, pattern in MALICIOUS_PATTERN_RULES:
            if re.search(pattern, blob):
                hits.append(category)
        if hits:
            findings.append(Finding(
                test_id="supplychain.malicious_patterns",
                title=f"Contenido sospechoso en '{name}': {', '.join(hits)}",
                category=Category.SUPPLYCHAIN,
                target=name,
                description=f"Categorías de regla que matchearon: {hits}.",
                passed=False,
                remediation="Revisar manualmente el contenido; si es legítimo, documentar el falso positivo. "
                             "Si no, tratar como indicador de tool maliciosa/comprometida.",
            ))

    if not findings:
        findings.append(Finding(
            test_id="supplychain.malicious_patterns", title="Sin patrones maliciosos detectados",
            category=Category.SUPPLYCHAIN, target="server",
            description="Ninguna categoría de regla matcheó el contenido analizado.",
            passed=True,
        ))
    return findings


# --- dependencias vulnerables (opt-in, requiere --source-path + --allow-network) --

@register_test(
    id="supplychain.dependency_vulnerabilities",
    name="Dependencias vulnerables (OSV.dev)",
    category=Category.SUPPLYCHAIN,
    description="Si se pasó --source-path, detecta requirements.txt/package.json/package-lock.json y "
                 "consulta OSV.dev (base pública de CVE/GHSA/PYSEC, sin API key — NO Cisco AI Defense ni "
                 "Snyk) por cada dependencia. Requiere red saliente hacia api.osv.dev: opt-in y gateado "
                 "también por --allow-network, no solo por --source-path.",
    default_enabled=False,
    requires_network=True,
)
async def dependency_vulnerabilities(target, ctx) -> list[Finding]:
    source_path = ctx.get("source_path")
    if not source_path:
        return []

    from engine.supplychain.manifest_parsers import discover_packages
    from engine.supplychain.osv import query_batch, fetch_vuln_details, fixed_versions_of, cvss_of

    packages = discover_packages(source_path)
    if not packages:
        return [Finding(
            test_id="supplychain.dependency_vulnerabilities", title="Sin manifiestos de dependencias reconocidos",
            category=Category.SUPPLYCHAIN, target="server",
            description=f"No se encontró requirements.txt/package.json/package-lock.json en '{source_path}'.",
            passed=True,
        )]

    try:
        by_pkg = await query_batch(packages)
        all_vuln_ids = [vid for ids in by_pkg.values() for vid in ids]
        details = await fetch_vuln_details(all_vuln_ids) if all_vuln_ids else {}
    except Exception as e:
        return [Finding(
            test_id="supplychain.dependency_vulnerabilities", title="Consulta a OSV.dev falló",
            category=Category.SUPPLYCHAIN, target="server",
            description=f"No se pudo consultar api.osv.dev: {e}", passed=True,
        )]

    findings = []
    for pkg in packages:
        key = f"{pkg['ecosystem']}:{pkg['name']}:{pkg.get('version') or '*'}"
        for vid in by_pkg.get(key, []):
            vuln = details.get(vid, {"id": vid})
            fixed = fixed_versions_of(vuln)
            cvss = cvss_of(vuln)
            # OSV también publica vectores CVSS v4.0 (y a veces v2.0) para algunas CVEs, no solo
            # v3.1 -- calculate_base_score() es específicamente v3.1 (engine/core/cvss.py), así
            # que cvss["base_score"] viene en None cuando el vector no es v3.1 (_cvss_base_score
            # ya lo atrapa). BUG REAL encontrado corriendo Ares contra un target vivo: antes acá
            # se pasaba cvss["vector"] como cvss_vector_override SIN chequear base_score, así que
            # un vector v4.0 real (sintácticamente válido, solo que de otra versión del estándar)
            # llegaba sin filtrar hasta risk_for()/calculate_base_score() y tumbaba el scan ENTERO
            # con un ValueError no atrapado. Mostramos el vector real igual (nunca lo escondemos),
            # pero solo lo usamos para *puntuar* cuando Ares lo sabe calcular.
            cvss_usable = cvss and cvss["base_score"] is not None
            if cvss_usable:
                cvss_suffix = f" — CVSS {cvss['base_score']} ({cvss['vector']})"
            elif cvss:
                cvss_suffix = f" — CVSS publicado por OSV (vector no v3.1, no usado para el score): {cvss['vector']}"
            else:
                cvss_suffix = ""
            findings.append(Finding(
                test_id="supplychain.dependency_vulnerabilities",
                title=f"{pkg['name']} {pkg.get('version') or ''}: {vid}{cvss_suffix}",
                category=Category.SUPPLYCHAIN,
                target=pkg["name"],
                # si OSV publicó CVSS v3.1 real para ESTA CVE puntual, usamos ESE vector (fuente
                # real, calculado con la misma fórmula oficial) en vez del fallback genérico de la
                # tabla -- pero solo si es un vector que Ares sabe puntuar (ver nota arriba).
                cvss_vector_override=cvss["vector"] if cvss_usable else None,
                description=(vuln.get("summary") or vuln.get("details") or "")[:500],
                evidence=Evidence(response={"id": vid, "ecosystem": pkg["ecosystem"], "cvss": cvss}),
                passed=False,
                remediation=f"Actualizar a: {fixed}" if fixed else "Sin fix publicado todavía; monitorear el advisory.",
                references=[f"https://osv.dev/vulnerability/{vid}"],
            ))

    if not findings:
        findings.append(Finding(
            test_id="supplychain.dependency_vulnerabilities", title="Sin CVEs conocidos en las dependencias",
            category=Category.SUPPLYCHAIN, target="server",
            description=f"OSV.dev no reportó vulnerabilidades para las {len(packages)} dependencia(s) detectadas.",
            passed=True,
        ))
    return findings


# --- SAST del código fuente (opt-in, requiere --source-path + semgrep instalado) --

_SAST_SEVERITY = {"ERROR": "high", "WARNING": "medium", "INFO": "low"}


@register_test(
    id="supplychain.source_sast",
    name="Análisis estático del código fuente (semgrep, ruleset propio)",
    category=Category.SUPPLYCHAIN,
    description="Si se pasó --source-path, corre un ruleset semgrep propio y curado a mano "
                 "(rules/semgrep_mcp.yml, taint-aware: sigue el dato desde el parámetro de un "
                 "tool MCP hasta un sink peligroso) sobre el código fuente REAL del server -- "
                 "command injection, path traversal, eval/exec, deserialización insegura. "
                 "A diferencia de todo el resto de Ares (que solo mira la superficie del "
                 "protocolo), esto mira el código. 100% offline: usa el ruleset local, nunca "
                 "--config auto/p/ci de semgrep (esas sí pegan al registro público). Requiere "
                 "'semgrep' instalado (pip install -e \".[sast]\"), opt-in por ser un extra pesado.",
    default_enabled=False,
    requires_network=False,
)
async def source_sast(target, ctx) -> list[Finding]:
    source_path = ctx.get("source_path")
    if not source_path:
        return []

    from engine.supplychain.sast import run_semgrep, semgrep_available

    if not semgrep_available():
        return [Finding(
            test_id="supplychain.source_sast", title="'semgrep' no instalado",
            category=Category.SUPPLYCHAIN, target="server",
            description="Correr 'pip install -e \".[sast]\"' (o 'pip install semgrep') para habilitar este test.",
            passed=True,
        )]

    outcome = await run_semgrep(source_path)
    if not outcome["ok"]:
        return [Finding(
            test_id="supplychain.source_sast", title="semgrep no pudo correr",
            category=Category.SUPPLYCHAIN, target="server",
            description=outcome["error"], passed=True,
        )]

    findings = []
    for r in outcome["results"]:
        sev_hint = _SAST_SEVERITY.get(r["severity"], "medium")
        findings.append(Finding(
            test_id="supplychain.source_sast",
            title=f"{r['category']}: {r['rule_id']} en {r['path']}:{r['line']}",
            category=Category.SUPPLYCHAIN,
            target=f"{r['path']}:{r['line']}",
            description=r["message"],
            evidence=Evidence(response=r["snippet"], notes=f"semgrep severity: {r['severity']}"),
            passed=False,
            # matiz por instancia: ERROR de semgrep -> impacto técnico alto (I:H); WARNING/INFO
            # se quedan con el baseline de la tabla -- ver engine/core/risk.py.
            cvss_vector_override=(
                build_vector(base_vector_for("supplychain.source_sast"), I="H") if sev_hint == "high" else None
            ),
            remediation="Revisar la línea señalada: sanitizar/validar antes del sink, o usar una API que no "
                         "interprete el input como código/comando/ruta sin restricción (ver "
                         "dynamic.command_injection_confirmed / dynamic.path_traversal_confirmed para la "
                         "confirmación black-box equivalente, si aplica).",
        ))

    if not findings:
        findings.append(Finding(
            test_id="supplychain.source_sast", title="Sin hallazgos del ruleset semgrep de Ares",
            category=Category.SUPPLYCHAIN, target="server",
            description=f"Ruleset propio (command injection, path traversal, eval/exec, deserialización "
                         f"insegura) no matcheó nada en '{source_path}'. No reemplaza un SAST/taint completo "
                         f"(ver sección 12 del manual) -- es un ruleset chico y curado, no exhaustivo.",
            passed=True,
        ))
    return findings
