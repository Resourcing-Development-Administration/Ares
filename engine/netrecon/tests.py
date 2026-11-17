"""
Tests de reconocimiento de red — integración ARTEX→Ares.

Cada test recibe (target: NetworkTarget, ctx: dict) y devuelve list[Finding].
ctx contiene:
  timeout_s          int   timeout por herramienta en segundos (default 120)
  nuclei_severity    list  severidades a incluir: ["critical","high","medium",...]
  rate_limit         int   peticiones/seg máximas (0 = sin límite)

Orden de ejecución (all_net_tests() ordena por level):
  level 1: httpx_probe, subfinder, bbot_osint, katana_crawl
  level 2: nuclei_scan, ffuf_fuzz, dalfox_xss
  level 3: sqlmap_sqli

Los tests NO lanzan excepciones: si la herramienta no está instalada o falla,
devuelven un Finding informativo con passed=True (no bloquea el score).
"""
from __future__ import annotations
import asyncio
import glob
import json
import os
import re
import tempfile
from typing import Any

from engine.core.models import Finding, Evidence, Category
from engine.netrecon.registry import net_test
from engine.netrecon.target import NetworkTarget
from engine.tools.paths import find_tool
from engine.ingest.router import ingest_scanner_output


# ── helpers ──────────────────────────────────────────────────────────────────

async def _run(cmd: list[str], timeout_s: int = 120) -> tuple[int, str, str]:
    """Ejecuta un subproceso y devuelve (returncode, stdout, stderr)."""
    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout_b, stderr_b = await asyncio.wait_for(
            proc.communicate(), timeout=timeout_s
        )
        return proc.returncode or 0, stdout_b.decode(errors="replace"), stderr_b.decode(errors="replace")
    except asyncio.TimeoutError:
        try:
            proc.kill()
        except Exception:
            pass
        return -1, "", f"timeout después de {timeout_s}s"
    except Exception as exc:
        return -2, "", str(exc)


def _ingest_to_ctx(ctx: dict, tool: str, content: str, target: str) -> None:
    """Parsea output de scanner y acumula assets/facts en ctx['ingest_results']."""
    if not content or not content.strip():
        return
    try:
        result = ingest_scanner_output(tool, content, target)
        ctx.setdefault("ingest_results", []).append(result)
        ctx.setdefault("extra_assets", []).extend(result.all_asset_values())
    except Exception:
        pass


def _tool_missing(tool_name: str, test_id: str, target_url: str) -> Finding:
    return Finding(
        test_id=test_id,
        title=f"{tool_name} no instalado",
        category=Category.NETWORK,
        target=target_url,
        description=(
            f"El binario '{tool_name}' no se encontró en ~/.ares/bin/ ni en PATH. "
            f"Ejecuta 'ares install-tools --tools {tool_name}' para instalarlo."
        ),
        passed=True,
    )


def _timeout_finding(tool_name: str, test_id: str, target_url: str, timeout_s: int) -> Finding:
    return Finding(
        test_id=test_id,
        title=f"{tool_name} timeout",
        category=Category.NETWORK,
        target=target_url,
        description=f"El tool tardó más de {timeout_s}s y fue interrumpido.",
        passed=True,
    )


# ── net.httpx_probe ──────────────────────────────────────────────────────────

@net_test(
    id="net.httpx_probe",
    level=1,
    name="HTTP Probe (httpx)",
    category="network",
    description=(
        "Verifica si el host responde por HTTP/HTTPS y recoge cabeceras de seguridad. "
        "Reporta ausencias de HSTS, CSP, X-Frame-Options, X-Content-Type-Options y "
        "Referrer-Policy como findings."
    ),
)
async def httpx_probe(target: NetworkTarget, ctx: dict[str, Any]) -> list[Finding]:
    tool = find_tool("httpx")
    if not tool:
        return [_tool_missing("httpx", "net.httpx_probe", target.normalized_url)]

    timeout_s = ctx.get("timeout_s", 120)

    cmd = [
        tool,
        "-u", target.normalized_url,
        "-json",
        "-follow-redirects",
        "-timeout", str(min(timeout_s, 30)),
        "-no-color",
        "-silent",
        "-include-response-header",
        "-status-code",
        "-title",
        "-tech-detect",
        "-server",
    ]

    rc, stdout, stderr = await _run(cmd, timeout_s)

    if rc == -1:
        return [_timeout_finding("httpx", "net.httpx_probe", target.normalized_url, timeout_s)]

    findings: list[Finding] = []
    lines = [l.strip() for l in stdout.splitlines() if l.strip()]

    if not lines:
        findings.append(Finding(
            test_id="net.httpx_probe",
            title="Host no responde por HTTP/HTTPS",
            category=Category.NETWORK,
            target=target.normalized_url,
            description=(
                f"httpx no obtuvo respuesta de {target.normalized_url}. "
                f"stderr: {stderr[:300]}"
            ),
            passed=False,
            evidence=Evidence(raw=stderr[:1000]),
        ))
        return findings

    for line in lines:
        try:
            data = json.loads(line)
        except json.JSONDecodeError:
            continue

        url_hit = data.get("url", target.normalized_url)
        status  = data.get("status_code", 0)
        headers: dict[str, str] = {
            k.lower(): v
            for k, v in (data.get("headers") or {}).items()
        }

        host = data.get("host") or target.base_domain
        if host and host not in target.discovered_hosts:
            target.discovered_hosts.append(host)

        raw_resp = json.dumps(data, indent=2)

        # cabeceras de seguridad obligatorias: (header, titulo, descripcion, vector_ajuste)
        SECURITY_HEADERS = [
            (
                "strict-transport-security",
                "HSTS ausente",
                "El servidor no devuelve Strict-Transport-Security. "
                "Sin HSTS los navegadores no fuerzan HTTPS y son vulnerables a SSL-strip.",
                None,  # usa el vector base de net.httpx_probe
            ),
            (
                "content-security-policy",
                "CSP ausente",
                "No se detectó Content-Security-Policy. Incrementa el riesgo de XSS.",
                "AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:L/A:N",
            ),
            (
                "x-frame-options",
                "X-Frame-Options ausente",
                "Sin X-Frame-Options (o CSP frame-ancestors) el sitio puede ser embebido "
                "en iframes para ataques de clickjacking.",
                "AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N",
            ),
            (
                "x-content-type-options",
                "X-Content-Type-Options ausente",
                "Sin 'nosniff' los navegadores pueden interpretar recursos con tipo MIME "
                "incorrecto, habilitando ataques de MIME-sniffing.",
                "AV:N/AC:H/PR:N/UI:R/S:U/C:N/I:L/A:N",
            ),
            (
                "referrer-policy",
                "Referrer-Policy ausente",
                "Sin Referrer-Policy el navegador puede filtrar URLs completas a terceros.",
                "AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N",
            ),
        ]

        csp_val = headers.get("content-security-policy", "")
        has_frame_ancestors = "frame-ancestors" in csp_val

        for hdr, title, desc, vec in SECURITY_HEADERS:
            if hdr in headers:
                continue
            if hdr == "x-frame-options" and has_frame_ancestors:
                continue
            findings.append(Finding(
                test_id="net.httpx_probe",
                title=title,
                category=Category.NETWORK,
                target=url_hit,
                description=f"{desc}\n\nURL: {url_hit} (HTTP {status})",
                passed=False,
                cvss_vector_override=vec,
                evidence=Evidence(
                    request={"url": url_hit, "header_checked": hdr},
                    response={"status": status, "headers_present": list(headers.keys())},
                    raw=raw_resp[:4000],
                ),
            ))

    if not findings:
        findings.append(Finding(
            test_id="net.httpx_probe",
            title="Cabeceras de seguridad HTTP presentes",
            category=Category.NETWORK,
            target=target.normalized_url,
            description=f"{target.normalized_url} devuelve todas las cabeceras de seguridad evaluadas.",
            passed=True,
        ))

    _ingest_to_ctx(ctx, "httpx", stdout, target.normalized_url)
    return findings


# ── net.subfinder ─────────────────────────────────────────────────────────────

@net_test(
    id="net.subfinder",
    level=1,
    name="Subdomain Enumeration (subfinder)",
    category="network",
    description=(
        "Enumera subdominios del dominio objetivo usando subfinder. "
        "Los subdominios descubiertos se añaden al contexto del scan para "
        "que los tests posteriores (nuclei, katana) los procesen también."
    ),
)
async def subfinder_enum(target: NetworkTarget, ctx: dict[str, Any]) -> list[Finding]:
    tool = find_tool("subfinder")
    if not tool:
        return [_tool_missing("subfinder", "net.subfinder", target.normalized_url)]

    timeout_s = ctx.get("timeout_s", 120)
    domain = target.base_domain

    cmd = [
        tool,
        "-d", domain,
        "-silent",
        "-json",
        "-timeout", str(min(timeout_s // 2, 60)),
    ]

    rc, stdout, stderr = await _run(cmd, timeout_s)

    if rc == -1:
        return [_timeout_finding("subfinder", "net.subfinder", target.normalized_url, timeout_s)]

    subdomains: list[str] = []
    for line in stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
            host = obj.get("host", "")
        except json.JSONDecodeError:
            host = line

        if host and target.in_scope(host):
            if host not in target.discovered_subdomains:
                target.discovered_subdomains.append(host)
            subdomains.append(host)

    if not subdomains:
        return [Finding(
            test_id="net.subfinder",
            title="Sin subdominios descubiertos",
            category=Category.NETWORK,
            target=domain,
            description=f"subfinder no encontró subdominios para '{domain}'.",
            passed=True,
        )]

    return [Finding(
        test_id="net.subfinder",
        title=f"{len(subdomains)} subdominios descubiertos",
        category=Category.NETWORK,
        target=domain,
        description=(
            f"subfinder encontró {len(subdomains)} subdominio(s) para '{domain}'. "
            "Revisa si alguno expone servicios no inventariados (shadow IT)."
        ),
        passed=True,
        evidence=Evidence(raw="\n".join(subdomains[:200])),
    )]


# ── net.nuclei_scan ───────────────────────────────────────────────────────────

_NUCLEI_CVSS_MAP: dict[str, str] = {
    "critical": "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    "high":     "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
    "medium":   "AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N",
    "low":      "AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N",
    "info":     "AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:N",
}


@net_test(
    id="net.nuclei_scan",
    level=2,
    name="Vulnerability Scan (nuclei)",
    category="network",
    description=(
        "Ejecuta nuclei contra el target y los subdominios descubiertos. "
        "Cada template hit se convierte en un Finding. "
        "Por defecto incluye severidades critical, high y medium."
    ),
)
async def nuclei_scan(target: NetworkTarget, ctx: dict[str, Any]) -> list[Finding]:
    tool = find_tool("nuclei")
    if not tool:
        return [_tool_missing("nuclei", "net.nuclei_scan", target.normalized_url)]

    timeout_s   = ctx.get("timeout_s", 240)
    severities  = ctx.get("nuclei_severity", ["critical", "high", "medium"])
    rate_limit  = ctx.get("rate_limit", 150)

    targets = [target.normalized_url]
    for sub in target.discovered_subdomains:
        sub_url = f"https://{sub}" if "://" not in sub else sub
        if target.in_scope(sub):
            targets.append(sub_url)

    with tempfile.NamedTemporaryFile(
        mode="w", suffix=".txt", delete=False, prefix="ares_nuclei_"
    ) as tf:
        tf.write("\n".join(targets))
        targets_file = tf.name

    try:
        cmd = [
            tool,
            "-l", targets_file,
            "-jsonl",
            "-silent",
            "-no-color",
            "-s", ",".join(severities),
            "-timeout", str(min(timeout_s // 2, 60)),
        ]
        if rate_limit:
            cmd += ["-rate-limit", str(rate_limit)]

        rc, stdout, stderr = await _run(cmd, timeout_s)
    finally:
        try:
            os.unlink(targets_file)
        except OSError:
            pass

    if rc == -1:
        return [_timeout_finding("nuclei", "net.nuclei_scan", target.normalized_url, timeout_s)]

    findings: list[Finding] = []
    for line in stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            hit = json.loads(line)
        except json.JSONDecodeError:
            continue

        sev_str  = str(hit.get("info", {}).get("severity", "info")).lower()
        # usa el CVSS del template si lo tiene; si no, el nuestro por severidad
        cvss_vec = (
            hit.get("info", {}).get("classification", {}).get("cvss-metrics")
            or _NUCLEI_CVSS_MAP.get(sev_str, _NUCLEI_CVSS_MAP["info"])
        )

        name     = hit.get("info", {}).get("name", hit.get("template-id", "?"))
        template = hit.get("template-id", "")
        matched  = hit.get("matched-at", "")
        desc     = hit.get("info", {}).get("description", "")
        refs     = hit.get("info", {}).get("reference", [])
        if isinstance(refs, str):
            refs = [refs]

        full_desc = desc
        if refs:
            full_desc += "\n\nReferencias:\n" + "\n".join(f"- {r}" for r in refs[:5])
        full_desc += f"\n\nTemplate: {template}"

        findings.append(Finding(
            test_id="net.nuclei_scan",
            title=f"[nuclei] {name}",
            category=Category.NETWORK,
            target=matched or target.normalized_url,
            description=full_desc,
            passed=False,
            cvss_vector_override=cvss_vec,
            evidence=Evidence(
                request={"template": template, "target": matched},
                raw=json.dumps(hit, indent=2)[:4000],
            ),
        ))

    if not findings:
        findings.append(Finding(
            test_id="net.nuclei_scan",
            title="nuclei: sin hallazgos",
            category=Category.NETWORK,
            target=target.normalized_url,
            description=(
                f"nuclei no encontró vulnerabilidades de severidad "
                f"{', '.join(severities)} en {target.normalized_url}."
            ),
            passed=True,
        ))

    _ingest_to_ctx(ctx, "nuclei", stdout, target.normalized_url)
    return findings


# ── net.katana_crawl ──────────────────────────────────────────────────────────

@net_test(
    id="net.katana_crawl",
    level=1,
    name="Web Crawl (katana)",
    category="network",
    description=(
        "Rastrea el sitio con katana para descubrir endpoints, formularios y "
        "parámetros. Los endpoints descubiertos se añaden al contexto del scan "
        "para pruebas posteriores y se reportan como superficie de ataque."
    ),
)
async def katana_crawl(target: NetworkTarget, ctx: dict[str, Any]) -> list[Finding]:
    tool = find_tool("katana")
    if not tool:
        return [_tool_missing("katana", "net.katana_crawl", target.normalized_url)]

    timeout_s  = ctx.get("timeout_s", 120)
    rate_limit = ctx.get("rate_limit", 150)

    cmd = [
        tool,
        "-u", target.normalized_url,
        "-silent",
        "-json",
        "-depth", "3",
        "-js-crawl",
        "-timeout", str(min(timeout_s // 4, 20)),
        "-no-color",
    ]
    if rate_limit:
        cmd += ["-rate-limit", str(rate_limit)]

    rc, stdout, stderr = await _run(cmd, timeout_s)

    if rc == -1:
        return [_timeout_finding("katana", "net.katana_crawl", target.normalized_url, timeout_s)]

    urls: list[str] = []
    for line in stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
            url = obj.get("request", {}).get("url") or obj.get("url", "")
        except json.JSONDecodeError:
            url = line

        if url and url not in target.crawled_urls:
            target.crawled_urls.append(url)
        if url:
            urls.append(url)

    parameterized = [u for u in urls if "?" in u]

    if not urls:
        return [Finding(
            test_id="net.katana_crawl",
            title="katana: sin URLs rastreadas",
            category=Category.NETWORK,
            target=target.normalized_url,
            description=f"katana no encontró URLs en {target.normalized_url}.",
            passed=True,
        )]

    findings = [Finding(
        test_id="net.katana_crawl",
        title=f"{len(urls)} endpoints descubiertos",
        category=Category.NETWORK,
        target=target.normalized_url,
        description=(
            f"katana rastreó {len(urls)} URL(s) en '{target.base_domain}'. "
            f"{len(parameterized)} con parámetros (candidatos para fuzzing/injection)."
        ),
        passed=True,
        evidence=Evidence(raw="\n".join(urls[:300])),
    )]

    if len(parameterized) > 50:
        findings.append(Finding(
            test_id="net.katana_crawl",
            title="Superficie de ataque amplia: >50 endpoints con parámetros",
            category=Category.NETWORK,
            target=target.normalized_url,
            description=(
                f"Se descubrieron {len(parameterized)} endpoints con parámetros. "
                "Una superficie amplia incrementa el riesgo de vulnerabilidades no auditadas "
                "(injection, IDOR, lógica de negocio)."
            ),
            passed=False,
            cvss_vector_override="AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N",
            evidence=Evidence(raw="\n".join(parameterized[:200])),
        ))

    return findings


# ── net.bbot_osint ───────────────────────────────────────────────────────────

@net_test(
    id="net.bbot_osint",
    level=1,
    name="Passive OSINT (bbot)",
    category="network",
    description=(
        "Reconocimiento pasivo con bbot: descubre subdominios, direcciones email, "
        "tecnologías y registros DNS sin enviar tráfico activo al target. "
        "Complementa a subfinder con más fuentes OSINT."
    ),
)
async def bbot_osint(target: NetworkTarget, ctx: dict[str, Any]) -> list[Finding]:
    tool = find_tool("bbot")
    if not tool:
        return [_tool_missing("bbot", "net.bbot_osint", target.normalized_url)]

    timeout_s = ctx.get("timeout_s", 300)
    domain = target.base_domain

    with tempfile.TemporaryDirectory(prefix="ares_bbot_") as tmpdir:
        cmd = [
            tool,
            "-t", domain,
            "-p", "passive",
            "-o", tmpdir,
            "-rf", "ndjson",
            "-n", "ares_scan",
            "--ignore-failed-deps",
            "-y",
            "--silent",
        ]

        rc, stdout, stderr = await _run(cmd, timeout_s)

        if rc == -1:
            return [_timeout_finding("bbot", "net.bbot_osint", target.normalized_url, timeout_s)]

        # buscar el ndjson generado por bbot
        ndjson_files = glob.glob(os.path.join(tmpdir, "scans", "ares_scan", "output.ndjson"))
        if not ndjson_files:
            # bbot a veces no produce output si no hay datos, o si la version difiere
            return [Finding(
                test_id="net.bbot_osint",
                title="bbot: sin datos OSINT encontrados",
                category=Category.NETWORK,
                target=domain,
                description=(
                    f"bbot corrió pero no produjo output para '{domain}'. "
                    f"rc={rc} stderr: {stderr[:300]}"
                ),
                passed=True,
            )]

        subdomains: list[str] = []
        emails: list[str] = []
        technologies: list[str] = []
        ips: list[str] = []
        total_events = 0

        with open(ndjson_files[0]) as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    evt = json.loads(line)
                except json.JSONDecodeError:
                    continue

                total_events += 1
                etype = evt.get("type", "")
                data = str(evt.get("data", ""))

                if etype == "DNS_NAME" and target.in_scope(data):
                    if data not in target.discovered_subdomains and data != domain:
                        target.discovered_subdomains.append(data)
                    if data not in subdomains:
                        subdomains.append(data)
                elif etype == "EMAIL_ADDRESS":
                    if data not in emails:
                        emails.append(data)
                elif etype == "TECHNOLOGY":
                    tech = data if isinstance(data, str) else json.dumps(data)
                    if tech not in technologies:
                        technologies.append(tech)
                elif etype == "IP_ADDRESS":
                    if data not in ips:
                        ips.append(data)

    if not total_events:
        return [Finding(
            test_id="net.bbot_osint",
            title="bbot: sin hallazgos OSINT",
            category=Category.NETWORK,
            target=domain,
            description=f"bbot no encontró datos OSINT para '{domain}'.",
            passed=True,
        )]

    lines = []
    if subdomains:
        lines.append(f"Subdominios: {', '.join(subdomains[:20])}" +
                     (f" (+{len(subdomains) - 20} más)" if len(subdomains) > 20 else ""))
    if emails:
        lines.append(f"Emails: {', '.join(emails[:10])}" +
                     (f" (+{len(emails) - 10} más)" if len(emails) > 10 else ""))
    if technologies:
        lines.append(f"Tecnologías: {', '.join(technologies[:10])}")
    if ips:
        lines.append(f"IPs: {', '.join(ips[:10])}")

    summary_parts = []
    if subdomains: summary_parts.append(f"{len(subdomains)} subdominios")
    if emails: summary_parts.append(f"{len(emails)} emails")
    if technologies: summary_parts.append(f"{len(technologies)} tecnologías")
    if ips: summary_parts.append(f"{len(ips)} IPs")

    findings = [Finding(
        test_id="net.bbot_osint",
        title=f"OSINT: {', '.join(summary_parts)} descubiertos",
        category=Category.NETWORK,
        target=domain,
        description=(
            f"bbot (modo pasivo) encontró {total_events} eventos OSINT para '{domain}'.\n\n"
            + "\n".join(lines)
        ),
        passed=True,
        evidence=Evidence(raw="\n".join(
            (subdomains[:50] if subdomains else []) +
            (emails[:20] if emails else []) +
            (technologies[:20] if technologies else [])
        )),
    )]

    # Email exposure es un riesgo de phishing/spear-phishing
    if emails:
        findings.append(Finding(
            test_id="net.bbot_osint",
            title=f"Exposición de {len(emails)} dirección(es) de email vía OSINT",
            category=Category.NETWORK,
            target=domain,
            description=(
                f"Se encontraron {len(emails)} dirección(es) de email asociadas a '{domain}' "
                "en fuentes públicas. Esto facilita ataques de phishing y spear-phishing "
                "dirigidos a empleados/usuarios del dominio.\n\n"
                f"Emails: {', '.join(emails[:20])}"
            ),
            passed=False,
            cvss_vector_override="AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N",
            evidence=Evidence(raw="\n".join(emails)),
        ))

    if ndjson_files:
        try:
            with open(ndjson_files[0]) as _f:
                _ingest_to_ctx(ctx, "bbot", _f.read(), domain)
        except Exception:
            pass
    return findings


# ── net.ffuf_fuzz ────────────────────────────────────────────────────────────

_FFUF_WORDLIST = [
    # admin / panel
    "admin", "administrator", "admin.php", "admin/", "admin/login",
    "panel", "dashboard", "control", "cpanel", "superadmin",
    # auth
    "login", "login.php", "signin", "auth", "logout", "register",
    "forgot", "reset", "oauth", "sso",
    # APIs y docs
    "api", "api/v1", "api/v2", "api/v3", "graphql", "graphiql",
    "swagger", "swagger-ui", "openapi.json", "api-docs", "redoc", "docs",
    # archivos sensibles
    ".env", ".git/config", ".htaccess", ".htpasswd", ".DS_Store",
    "config.php", "config.json", "config.yml", "settings.php",
    "database.php", "db.php", "wp-config.php", ".aws/credentials",
    # backups
    "backup", "backup.zip", "backup.tar.gz", "backup.sql", "db.sql",
    "dump.sql", "data.zip", "site.zip", "www.zip", "files.zip",
    # diagnóstico / debug
    "phpinfo.php", "info.php", "test.php", "debug.php", "debug",
    "console", "shell.php", "cmd.php", "command.php", "exec.php",
    "server-status", "server-info",
    # CMS comunes
    "wp-admin", "wp-login.php", "wp-cron.php", "xmlrpc.php",
    "joomla", "administrator/index.php",
    # health / metrics
    "health", "healthz", "ping", "status", "metrics",
    "actuator", "actuator/env", "actuator/beans", "actuator/health",
    "actuator/info", "actuator/loggers",
    # phpMyAdmin / db tools
    "phpmyadmin", "pma", "mysql", "adminer", "adminer.php",
    # uploads / archivos
    "upload", "uploads", "files", "file", "media", "images",
    # well-known
    ".well-known/security.txt", "robots.txt", "sitemap.xml",
    "crossdomain.xml", "clientaccesspolicy.xml",
    # misceláneo
    "log", "logs", "error.log", "access.log",
    "tmp", "temp", "cache", "bak", "old", "new", "test",
    "staging", "dev", "development",
    "version", "changelog", "readme", "README.md",
]


@net_test(
    id="net.ffuf_fuzz",
    level=2,
    name="Directory Fuzzing (ffuf)",
    category="network",
    description=(
        "Fuzzea rutas comunes (admin, backup, config, debug, etc.) en el target "
        "buscando recursos no enlazados: paneles de administración, archivos de "
        "configuración, endpoints de debug, backups. Usa una wordlist curada embebida."
    ),
)
async def ffuf_fuzz(target: NetworkTarget, ctx: dict[str, Any]) -> list[Finding]:
    tool = find_tool("ffuf")
    if not tool:
        return [_tool_missing("ffuf", "net.ffuf_fuzz", target.normalized_url)]

    timeout_s  = ctx.get("timeout_s", 120)
    rate_limit = ctx.get("rate_limit", 50)  # más conservador para fuzzing

    base_url = target.normalized_url.rstrip("/")
    targets_to_fuzz = [base_url]

    with tempfile.NamedTemporaryFile(
        mode="w", suffix=".txt", delete=False, prefix="ares_ffuf_wl_"
    ) as wl:
        wl.write("\n".join(_FFUF_WORDLIST))
        wordlist_path = wl.name

    findings: list[Finding] = []

    try:
        for fuzz_base in targets_to_fuzz[:3]:  # máximo 3 targets (base + 2 subdominios)
            with tempfile.NamedTemporaryFile(
                mode="w", suffix=".json", delete=False, prefix="ares_ffuf_out_"
            ) as out_f:
                out_path = out_f.name

            try:
                cmd = [
                    tool,
                    "-u", f"{fuzz_base}/FUZZ",
                    "-w", wordlist_path,
                    "-o", out_path,
                    "-of", "json",
                    "-silent",
                    "-mc", "200,201,204,301,302,307,401,403,405",
                    "-t", "20",
                ]
                if rate_limit:
                    cmd += ["-rate", str(rate_limit)]

                rc, stdout, stderr = await _run(cmd, timeout_s)

                if rc == -1:
                    findings.append(_timeout_finding("ffuf", "net.ffuf_fuzz", fuzz_base, timeout_s))
                    continue

                try:
                    with open(out_path) as f:
                        result_data = json.load(f)
                    hits = result_data.get("results", [])
                except (json.JSONDecodeError, FileNotFoundError, KeyError):
                    hits = []
                    result_data = {}
                _ingest_to_ctx(ctx, "ffuf", json.dumps(result_data), fuzz_base)

                # filtrar: ignorar 403 solos (pueden ser honeypots o WAF genérico)
                interesting = [
                    h for h in hits
                    if h.get("status") in (200, 201, 204, 301, 302, 307, 405)
                ]
                auth_walls = [h for h in hits if h.get("status") == 401]
                # 403 en rutas de admin/config son igualmente interesantes
                soft_403 = [
                    h for h in hits
                    if h.get("status") == 403 and any(
                        p in (h.get("input", {}).get("FUZZ", "")).lower()
                        for p in ["admin", "config", "backup", "env", "git", "htpasswd",
                                  "dashboard", "panel", "phpmyadmin"]
                    )
                ]
                interesting = interesting + auth_walls + soft_403

                if interesting:
                    rows = "\n".join(
                        f"[{h.get('status')}] {h.get('url', '')} (size:{h.get('length',0)})"
                        for h in interesting[:50]
                    )

                    _RISKY_PATHS = {
                        ".env", ".git/config", ".htaccess", ".htpasswd",
                        "config.php", "config.json", "wp-config.php",
                        "backup", "backup.sql", "dump.sql", "db.sql",
                        "phpinfo.php", "info.php", "shell.php", "cmd.php",
                        ".aws/credentials",
                    }
                    risky = [
                        h for h in interesting
                        if any(
                            r in (h.get("url", "") or "").lower()
                            for r in _RISKY_PATHS
                        )
                    ]

                    cvss_vec = (
                        "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"
                        if risky else
                        "AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"
                    )
                    title = (
                        f"[ffuf] Rutas sensibles expuestas en {fuzz_base}"
                        if risky else
                        f"[ffuf] {len(interesting)} ruta(s) accesibles en {fuzz_base}"
                    )

                    findings.append(Finding(
                        test_id="net.ffuf_fuzz",
                        title=title,
                        category=Category.NETWORK,
                        target=fuzz_base,
                        description=(
                            f"ffuf encontró {len(interesting)} ruta(s) accesibles (códigos "
                            f"2xx/3xx/401/403) en '{fuzz_base}'."
                            + (f"\n\n⚠ Rutas de alto riesgo: {', '.join(h.get('url','') for h in risky[:5])}" if risky else "")
                            + f"\n\n{rows}"
                        ),
                        passed=False,
                        cvss_vector_override=cvss_vec,
                        evidence=Evidence(
                            request={"url": f"{fuzz_base}/FUZZ", "wordlist_size": len(_FFUF_WORDLIST)},
                            response={"hits": len(interesting), "risky": len(risky)},
                            raw=rows[:4000],
                        ),
                    ))
                else:
                    findings.append(Finding(
                        test_id="net.ffuf_fuzz",
                        title=f"ffuf: sin rutas interesantes en {fuzz_base}",
                        category=Category.NETWORK,
                        target=fuzz_base,
                        description=f"ffuf no encontró rutas accesibles o sensibles en '{fuzz_base}'.",
                        passed=True,
                    ))
            finally:
                try:
                    os.unlink(out_path)
                except OSError:
                    pass
    finally:
        try:
            os.unlink(wordlist_path)
        except OSError:
            pass

    return findings or [Finding(
        test_id="net.ffuf_fuzz",
        title="ffuf: sin resultados",
        category=Category.NETWORK,
        target=target.normalized_url,
        description="ffuf no produjo resultados.",
        passed=True,
    )]


# ── net.dalfox_xss ───────────────────────────────────────────────────────────

@net_test(
    id="net.dalfox_xss",
    level=2,
    name="XSS Scan (dalfox)",
    category="network",
    description=(
        "Busca vulnerabilidades XSS (Cross-Site Scripting) en los endpoints con "
        "parámetros descubiertos por katana. Usa dalfox en modo --only-poc para "
        "identificar puntos de inyección sin ejecutar payloads destructivos."
    ),
)
async def dalfox_xss(target: NetworkTarget, ctx: dict[str, Any]) -> list[Finding]:
    tool = find_tool("dalfox")
    if not tool:
        return [_tool_missing("dalfox", "net.dalfox_xss", target.normalized_url)]

    timeout_s = ctx.get("timeout_s", 120)

    # tomar URLs con parámetros de katana; si no hay, generar una básica con param dummy
    parameterized = [u for u in target.crawled_urls if "?" in u]
    if not parameterized:
        return [Finding(
            test_id="net.dalfox_xss",
            title="dalfox: sin URLs con parámetros para escanear",
            category=Category.NETWORK,
            target=target.normalized_url,
            description=(
                "No se encontraron URLs con parámetros en el crawl previo. "
                "Ejecuta net.katana_crawl antes de net.dalfox_xss."
            ),
            passed=True,
        )]

    urls_to_scan = parameterized[:30]  # limitar para no exceder timeout

    with tempfile.NamedTemporaryFile(
        mode="w", suffix=".txt", delete=False, prefix="ares_dalfox_urls_"
    ) as uf:
        uf.write("\n".join(urls_to_scan))
        urls_file = uf.name

    try:
        cmd = [
            tool, "file", urls_file,
            "--only-poc",
            "--no-color",
            "--format", "json",
            "--silence",
            "--timeout", str(min(timeout_s // 4, 10)),
        ]

        rc, stdout, stderr = await _run(cmd, timeout_s)
    finally:
        try:
            os.unlink(urls_file)
        except OSError:
            pass

    if rc == -1:
        return [_timeout_finding("dalfox", "net.dalfox_xss", target.normalized_url, timeout_s)]

    findings: list[Finding] = []

    for line in stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            hit = json.loads(line)
        except json.JSONDecodeError:
            # dalfox a veces mezcla texto plano con JSON
            continue

        if not isinstance(hit, dict):
            continue

        vuln_url = hit.get("url") or hit.get("target") or target.normalized_url
        poc      = hit.get("poc") or hit.get("param") or ""
        param    = hit.get("param") or ""
        xss_type = hit.get("type") or hit.get("evidence") or "reflected"

        findings.append(Finding(
            test_id="net.dalfox_xss",
            title=f"[dalfox] XSS en {vuln_url[:80]}",
            category=Category.NETWORK,
            target=vuln_url,
            description=(
                f"dalfox confirmó un punto de inyección XSS en '{vuln_url}'.\n\n"
                f"Parámetro: {param}\nTipo: {xss_type}\nPoC: {poc}"
            ),
            passed=False,
            cvss_vector_override="AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
            evidence=Evidence(
                request={"url": vuln_url, "param": param},
                response={"poc": poc, "type": xss_type},
                raw=json.dumps(hit, indent=2)[:2000],
            ),
        ))

    if not findings:
        # buscar también en texto plano por si el formato no es JSON
        xss_hits = [l for l in stdout.splitlines() if "POC" in l or "XSS" in l.upper()]
        if xss_hits:
            findings.append(Finding(
                test_id="net.dalfox_xss",
                title=f"[dalfox] Posibles XSS detectados ({len(xss_hits)} hits)",
                category=Category.NETWORK,
                target=target.normalized_url,
                description=(
                    f"dalfox reportó {len(xss_hits)} posible(s) punto(s) de inyección. "
                    "Verificar manualmente.\n\n" + "\n".join(xss_hits[:20])
                ),
                passed=False,
                cvss_vector_override="AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
                evidence=Evidence(raw="\n".join(xss_hits[:100])),
            ))
        else:
            findings.append(Finding(
                test_id="net.dalfox_xss",
                title="dalfox: sin XSS detectados",
                category=Category.NETWORK,
                target=target.normalized_url,
                description=(
                    f"dalfox no encontró vulnerabilidades XSS en "
                    f"{len(urls_to_scan)} URL(s) con parámetros."
                ),
                passed=True,
            ))

    return findings


# ── net.sqlmap_sqli ──────────────────────────────────────────────────────────

@net_test(
    id="net.sqlmap_sqli",
    level=3,
    name="SQL Injection (sqlmap)",
    category="network",
    description=(
        "Prueba inyección SQL en endpoints con parámetros descubiertos por katana, "
        "con --level=1 --risk=1 (modo conservador, no destructivo). "
        "Requiere autorización explícita del propietario del sistema."
    ),
)
async def sqlmap_sqli(target: NetworkTarget, ctx: dict[str, Any]) -> list[Finding]:
    tool = find_tool("sqlmap")
    if not tool:
        return [_tool_missing("sqlmap", "net.sqlmap_sqli", target.normalized_url)]

    timeout_s = ctx.get("timeout_s", 300)

    parameterized = [u for u in target.crawled_urls if "?" in u]
    if not parameterized:
        return [Finding(
            test_id="net.sqlmap_sqli",
            title="sqlmap: sin URLs con parámetros para probar",
            category=Category.NETWORK,
            target=target.normalized_url,
            description=(
                "No se encontraron URLs con parámetros en el crawl previo. "
                "Ejecuta net.katana_crawl antes de net.sqlmap_sqli."
            ),
            passed=True,
        )]

    # máximo 5 URLs por timeout; priorizar las que tienen parámetros de ID/nombre comunes
    _PRIORITY_PARAMS = re.compile(r"[?&](id|ID|user_id|item|product|page|cat|category|q)=", re.I)
    priority = [u for u in parameterized if _PRIORITY_PARAMS.search(u)]
    urls_to_test = (priority or parameterized)[:5]

    with tempfile.NamedTemporaryFile(
        mode="w", suffix=".txt", delete=False, prefix="ares_sqlmap_urls_"
    ) as uf:
        uf.write("\n".join(urls_to_test))
        urls_file = uf.name

    with tempfile.TemporaryDirectory(prefix="ares_sqlmap_out_") as out_dir:
        cmd = [
            tool,
            "-m", urls_file,
            "--batch",
            "--level=1",
            "--risk=1",
            "--timeout=10",
            "--retries=1",
            "--threads=1",
            "--no-logging",
            "--output-dir", out_dir,
        ]

        try:
            rc, stdout, stderr = await _run(cmd, timeout_s)
        finally:
            try:
                os.unlink(urls_file)
            except OSError:
                pass

        if rc == -1:
            return [_timeout_finding("sqlmap", "net.sqlmap_sqli", target.normalized_url, timeout_s)]

        combined = stdout + "\n" + stderr
        findings: list[Finding] = []

        # patrones de confirmación de sqlmap (texto, no JSON)
        _VULN_PATTERNS = [
            r"(https?://\S+)\s+.*?is vulnerable",
            r"Parameter:\s+(\S+)\s+.*?appears to be injectable",
            r"sqlmap identified the following injection point",
        ]
        _NOTVULN_PATTERN = re.compile(
            r"does not appear to be injectable|all tested parameters do not appear to be injectable",
            re.I,
        )

        vulnerable_urls: list[str] = []
        for pat in _VULN_PATTERNS:
            for m in re.finditer(pat, combined, re.I | re.MULTILINE):
                url_or_param = m.group(1) if m.lastindex else "?"
                if url_or_param not in vulnerable_urls:
                    vulnerable_urls.append(url_or_param)

        # también buscar líneas de log claves
        key_lines = [
            line.strip() for line in combined.splitlines()
            if any(kw in line.lower() for kw in
                   ["vulnerable", "injectable", "injection point", "sqlmap identified"])
        ]

        if vulnerable_urls or key_lines:
            evidence_text = "\n".join(key_lines[:30])
            findings.append(Finding(
                test_id="net.sqlmap_sqli",
                title=f"[sqlmap] Inyección SQL confirmada en {target.base_domain}",
                category=Category.NETWORK,
                target=target.normalized_url,
                description=(
                    f"sqlmap confirmó vulnerabilidades de inyección SQL en '{target.base_domain}'.\n\n"
                    f"URLs/parámetros: {', '.join(vulnerable_urls[:5]) or '(ver evidencia)'}\n\n"
                    f"{evidence_text}"
                ),
                passed=False,
                cvss_vector_override="AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
                evidence=Evidence(
                    request={"urls_tested": urls_to_test, "level": 1, "risk": 1},
                    raw=evidence_text[:4000],
                ),
            ))
        else:
            not_vuln = bool(_NOTVULN_PATTERN.search(combined))
            findings.append(Finding(
                test_id="net.sqlmap_sqli",
                title="sqlmap: sin inyección SQL detectada" if not_vuln else "sqlmap: corrida completada",
                category=Category.NETWORK,
                target=target.normalized_url,
                description=(
                    f"sqlmap {'no encontró inyección SQL' if not_vuln else 'terminó'} "
                    f"en {len(urls_to_test)} URL(s) probadas (level=1, risk=1)."
                ),
                passed=True,
            ))

    return findings
