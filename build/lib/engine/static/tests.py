"""
Tests estáticos: analizan la definición (JSON Schema) de cada tool
sin ejecutar nada contra el servidor.
"""
from __future__ import annotations
from engine.core.models import Finding, Evidence, Category
from engine.core.registry import register_test
from engine.static.known_cves import check_known_cves
from engine.static.typosquatting import check_typosquatting


@register_test(
    id="static.schema_permissive",
    name="Detección de schemas demasiado permisivos",
    category=Category.STATIC,
    description="Marca parámetros sin tipo, sin enum/pattern, o con additionalProperties=true en tools de alto riesgo.",
)
async def schema_permissive(target, ctx) -> list[Finding]:
    tools = ctx.get("tools") or await target.list_tools()
    findings = []
    for tool in tools:
        schema = tool.get("input_schema") or {}
        props = schema.get("properties", {})
        issues = []

        if schema.get("additionalProperties", False) is True:
            issues.append("additionalProperties=true (acepta campos arbitrarios no declarados)")

        for pname, pschema in props.items():
            if not isinstance(pschema, dict):
                continue
            if "type" not in pschema:
                issues.append(f"parámetro '{pname}' sin 'type' declarado")
            if pschema.get("type") == "string" and not any(k in pschema for k in ("enum", "pattern", "maxLength", "format")):
                issues.append(f"parámetro string '{pname}' sin enum/pattern/maxLength (riesgo de injection/path traversal)")

        if issues:
            findings.append(Finding(
                test_id="static.schema_permissive",
                title=f"Schema permisivo en tool '{tool['name']}'",
                category=Category.STATIC,
                target=tool["name"],
                description="; ".join(issues),
                evidence=Evidence(response=schema),
                passed=False,
                remediation="Restringir tipos, usar enum/pattern/maxLength en parámetros string, y "
                             "additionalProperties=false salvo necesidad explícita.",
            ))
    if not findings:
        findings.append(Finding(
            test_id="static.schema_permissive",
            title="Schemas dentro de lo razonable",
            category=Category.STATIC,
            target="server",
            description="No se detectaron schemas excesivamente permisivos.",
            passed=True,
        ))
    return findings


@register_test(
    id="static.no_schema",
    name="Tools sin input_schema definido",
    category=Category.STATIC,
    description="Detecta tools que no publican ningún schema de entrada (imposible de fuzzear con guía, riesgo de inputs no validados).",
)
async def no_schema(target, ctx) -> list[Finding]:
    tools = ctx.get("tools") or await target.list_tools()
    findings = []
    for tool in tools:
        schema = tool.get("input_schema") or {}
        if not schema or not schema.get("properties"):
            findings.append(Finding(
                test_id="static.no_schema",
                title=f"Tool '{tool['name']}' sin schema de entrada útil",
                category=Category.STATIC,
                target=tool["name"],
                description="El tool no declara 'properties' en su input_schema.",
                passed=False,
                remediation="Definir JSON Schema explícito para todos los parámetros aceptados.",
            ))
    if not findings:
        findings.append(Finding(
            test_id="static.no_schema", title="Todos los tools declaran schema",
            category=Category.STATIC, target="server",
            description="OK", passed=True,
        ))
    return findings


@register_test(
    id="static.known_cve_check",
    name="CVEs conocidos de servers MCP oficiales (feed curado)",
    category=Category.STATIC,
    description="Compara el server_info.name/version que el TARGET autoreporta en 'initialize' contra un "
                 "feed curado a mano de CVEs reales publicados en servers MCP oficiales/ampliamente "
                 "desplegados (ver engine/static/known_cves.py) -- distinto de "
                 "supplychain.dependency_vulnerabilities (genérico vía OSV.dev sobre --source-path). "
                 "Heuristic: el dato lo autoreporta el propio target bajo auditoría, no una fuente "
                 "independiente.",
)
async def known_cve_check(target, ctx) -> list[Finding]:
    if target is None or not getattr(target, "server_info", None):
        return [Finding(
            test_id="static.known_cve_check", title="Sin server_info disponible",
            category=Category.STATIC, target="server",
            description="La sesión no completó 'initialize' con éxito; no hay name/version para comparar.",
            passed=True,
        )]

    name = getattr(target.server_info, "name", None)
    version = getattr(target.server_info, "version", None)
    hits = check_known_cves(name, version)

    findings = []
    for entry in hits:
        findings.append(Finding(
            test_id="static.known_cve_check",
            title=f"{entry['cve']}: {entry['title']}",
            category=Category.STATIC,
            target=f"{name} {version or '?'}",
            description=f"{entry['summary']} CVSS publicado: {entry['cvss']}. Versión reportada por el "
                         f"target: '{version or 'desconocida'}' (afecta a versiones anteriores a "
                         f"{entry['affected_before']}).",
            evidence=Evidence(response={"server_info": {"name": name, "version": version}, "cve": entry["cve"]}),
            passed=False,
            remediation=f"Actualizar a {entry['fixed_in']} o posterior.",
            references=[entry["source"], f"https://nvd.nist.gov/vuln/detail/{entry['cve']}"],
        ))

    if not findings:
        findings.append(Finding(
            test_id="static.known_cve_check",
            title=f"Sin CVEs conocidos para '{name or '?'}' {version or ''}".strip(),
            category=Category.STATIC, target="server",
            description="El nombre/versión autoreportado no matchea ningún CVE del feed curado (esto NO "
                         "es una auditoría exhaustiva de CVEs, es un feed chico mantenido a mano).",
            passed=True,
        ))
    return findings


@register_test(
    id="static.typosquatting_check",
    name="Typosquatting de paquete MCP (requiere --package-name)",
    category=Category.STATIC,
    description="Compara --package-name (el nombre de paquete que creés estar instalando) contra una lista "
                 "curada de paquetes MCP oficiales/ampliamente conocidos por similitud Jaro-Winkler (umbral "
                 "0.88) -- distinto de supplychain.tool_squatting (que compara nombres de TOOLS dentro del "
                 "mismo server). El vector real: instalar 'mcp-server-fetchh' pensando que es el oficial "
                 "'mcp-server-fetch'.",
    default_enabled=False,
)
async def typosquatting_check(target, ctx) -> list[Finding]:
    package_name = ctx.get("package_name")
    if not package_name:
        return [Finding(
            test_id="static.typosquatting_check", title="Sin --package-name dado",
            category=Category.STATIC, target="server",
            description="Pasá --package-name '<nombre-del-paquete>' para habilitar este chequeo.",
            passed=True,
        )]

    result = check_typosquatting(package_name)
    if result:
        return [Finding(
            test_id="static.typosquatting_check",
            title=f"'{package_name}' es sospechosamente parecido a '{result['matched_against']}' (posible typosquat)",
            category=Category.STATIC,
            target=package_name,
            description=f"Similitud Jaro-Winkler {result['similarity']:.3f} con el paquete legítimo conocido "
                         f"'{result['matched_against']}', sin ser un match exacto. Confirmá la fuente real "
                         f"antes de confiar en este paquete -- un nombre casi idéntico al oficial es el "
                         f"patrón clásico de typosquatting.",
            passed=False,
            remediation=f"Verificar que '{package_name}' sea intencional y no un error de tipeo de "
                         f"'{result['matched_against']}'; si es un typosquat, desinstalar inmediatamente.",
            references=["https://owasp.org/www-project-mcp-top-10/"],
        )]

    return [Finding(
        test_id="static.typosquatting_check", title=f"'{package_name}' sin indicios de typosquatting",
        category=Category.STATIC, target=package_name,
        description="No matchea exacto ni es sospechosamente parecido a ningún paquete de la lista curada "
                     "de MCPs oficiales conocidos.",
        passed=True,
    )]
