"""
Tests de reconocimiento (pasivos): no envían payloads adversariales,
solo enumeran y analizan lo que el servidor expone.
"""
from __future__ import annotations
import re
import unicodedata

from engine.core.models import Finding, Evidence, Category
from engine.core.registry import register_test
from engine.core.risk import build_vector, base_vector_for
from engine.core.limits import cap_text

# patrones sospechosos dentro de descripciones de tools (posible tool poisoning /
# instrucciones ocultas dirigidas al modelo, no al usuario)
SUSPICIOUS_PATTERNS = [
    (r"ignore (all|previous|the) (instructions|prompt)", "posible override de instrucciones"),
    (r"do not (tell|inform|mention) the user", "instrucción de ocultar info al usuario"),
    (r"system prompt", "referencia directa al system prompt"),
    (r"<\s*(system|assistant|user)\s*>", "tags de rol falsificados dentro de la descripción"),
    (r"before (calling|using) this tool", "condicionamiento de comportamiento del agente"),
    (r"always (run|call|execute)", "instrucción imperativa fuera de contexto normal de uso"),
    (r"secretly|silently|without (asking|confirmation)", "ejecución encubierta"),
]


@register_test(
    id="recon.enumerate",
    name="Enumeración de tools/resources/prompts",
    category=Category.RECON,
    description="Lista todo lo que expone el servidor MCP (tools, resources, prompts).",
)
async def enumerate_surface(target, ctx) -> list[Finding]:
    tools = await target.list_tools()
    resources = await target.list_resources()
    prompts = await target.list_prompts()
    ctx["tools"] = tools
    ctx["resources"] = resources
    ctx["prompts"] = prompts

    f = Finding(
        test_id="recon.enumerate",
        title="Superficie de ataque enumerada",
        category=Category.RECON,
        target="server",
        description=f"Se encontraron {len(tools)} tools, {len(resources)} resources y {len(prompts)} prompts.",
        evidence=Evidence(response={"tools": tools, "resources": resources, "prompts": prompts}),
        passed=True,
    )
    return [f]


def _param_descriptions(tool: dict) -> dict[str, str]:
    """Descripciones a nivel de parámetro dentro del input_schema -- el vector real de
    'Line Jumping' (ATR-2026-00579): una instrucción embebida en el campo 'description' de
    un parámetro, no en la descripción del tool, que el cliente igual carga al contexto del
    modelo apenas lista el server, antes de que la tool se invoque."""
    schema = tool.get("input_schema") or {}
    props = schema.get("properties", {}) or {}
    return {
        pname: pschema["description"]
        for pname, pschema in props.items()
        if isinstance(pschema, dict) and pschema.get("description")
    }


@register_test(
    id="recon.suspicious_descriptions",
    name="Análisis de descripciones sospechosas (tool poisoning / line jumping)",
    category=Category.RECON,
    description="Busca instrucciones ocultas o dirigidas al modelo dentro de las descripciones de tools "
                 "Y de sus parámetros (line jumping: la descripción de un parámetro en el schema es un "
                 "vector tan válido como la del tool, y suele quedar afuera de los escáneres que solo "
                 "miran tool.description).",
)
async def suspicious_descriptions(target, ctx) -> list[Finding]:
    tools = ctx.get("tools") or await target.list_tools()
    findings = []
    for tool in tools:
        # tool.description ya viene capado desde client.py; las descripciones de PARÁMETROS
        # (line jumping) vienen del input_schema crudo, sin pasar por ese cap -- hay que
        # acotarlas acá, mismo motivo que el cap en supplychain._all_text_blobs.
        blobs = {"description": tool.get("description", "") or ""}
        blobs.update({f"parámetro '{p}'": cap_text(d) for p, d in _param_descriptions(tool).items()})

        for field_label, text in blobs.items():
            hits = [label for pattern, label in SUSPICIOUS_PATTERNS if re.search(pattern, text, re.IGNORECASE)]
            invisible = [c for c in text if unicodedata.category(c) in ("Cf", "Co") or ord(c) in (0x200B, 0x200C, 0x200D, 0x2060)]
            if not (hits or invisible):
                continue

            is_line_jumping = field_label != "description"
            findings.append(Finding(
                test_id="recon.suspicious_descriptions",
                title=f"{'Line jumping' if is_line_jumping else 'Descripción sospechosa'} en '{tool['name']}' ({field_label})",
                category=Category.RECON,
                target=tool["name"],
                # unicode invisible (zero-width, bidi override) es casi imposible que sea legítimo --
                # baja la complejidad de ataque asumida (AC:H -> AC:L) vs. un simple match de keyword,
                # que sí podría ser texto de documentación legítima discutiendo el tema.
                cvss_vector_override=build_vector(base_vector_for("recon.suspicious_descriptions"),
                                                    AC="L" if invisible else "H"),
                description="Patrones detectados: " + ", ".join(hits or []) +
                            (f" | {len(invisible)} caracteres invisibles/unicode sospechosos" if invisible else "") +
                            (f" -- inyectado vía la descripción del PARÁMETRO, no del tool: se carga al "
                             f"contexto del modelo apenas se lista el server, antes de invocar nada."
                             if is_line_jumping else ""),
                evidence=Evidence(response={field_label: text, "invisible_chars": [hex(ord(c)) for c in invisible]}),
                passed=False,
                remediation="Revisar manualmente la descripción del tool Y de cada parámetro; eliminar "
                            "instrucciones dirigidas al modelo que no sean documentación legítima de uso, "
                            "y cualquier carácter Unicode invisible.",
                references=["https://embracethered.com/blog/", "https://agentthreatrule.org/en/rules/ATR-2026-00579"],
            ))
    if not findings:
        findings.append(Finding(
            test_id="recon.suspicious_descriptions",
            title="Sin patrones sospechosos en descripciones",
            category=Category.RECON,
            target="server",
            description="No se detectaron instrucciones ocultas ni caracteres invisibles en las descripciones analizadas.",
            passed=True,
        ))
    return findings


@register_test(
    id="recon.audit_logging",
    name="Soporte de audit/telemetría (logging capability)",
    category=Category.RECON,
    description="Verifica si el server declara soporte del capability 'logging' del protocolo MCP en su "
                 "respuesta de initialize -- sin esto, no hay rastro server-side de qué tools se invocaron "
                 "ni con qué argumentos, lo que dificulta detectar abuso o investigar un incidente después "
                 "(OWASP MCP08:2025 -- Lack of Audit and Telemetry).",
)
async def audit_logging(target, ctx) -> list[Finding]:
    if target is None:
        # La conexión inicial falló (ver ctx["connection_error"]) -- esto NO es evidencia
        # de que el server no declare 'logging', es que nunca se le pudo ni preguntar.
        # Confirmar "sin logging" acá sería un falso positivo: el hallazgo real en este
        # escenario es la falla de conexión misma, que connection_error ya reporta aparte.
        return [Finding(
            test_id="recon.audit_logging", title="Sin sesión viva para verificar audit logging",
            category=Category.RECON, target="server",
            description="La conexión inicial falló (ver el error de conexión reportado aparte); no se "
                         "pudo consultar si el server declara el capability 'logging' -- no es que no lo "
                         "declare, es que Ares no pudo ni preguntarle.",
            passed=True,
        )]

    caps = target.get_capabilities() if hasattr(target, "get_capabilities") else {}
    has_logging = "logging" in caps

    return [Finding(
        test_id="recon.audit_logging",
        title="Soporte de logging declarado" if has_logging else "Sin soporte de logging declarado",
        category=Category.RECON,
        target="server",
        description=(
            "El server declara el capability 'logging' en su respuesta de initialize."
            if has_logging else
            "El server NO declara el capability 'logging'. Esto no prueba que no loguee nada server-side "
            "(puede hacerlo fuera del protocolo MCP), pero sí significa que no hay un canal estándar para "
            "que el cliente reciba esos logs, y es una señal de que la telemetría no fue una prioridad de diseño."
        ),
        evidence=Evidence(response={"capabilities": caps}),
        passed=has_logging,
        remediation="Implementar el capability 'logging' del protocolo MCP y loguear cada tool call "
                     "(nombre, argumentos, resultado, identidad del cliente) server-side como mínimo, "
                     "para poder auditar e investigar incidentes después del hecho.",
        references=["https://modelcontextprotocol.io/specification"],
    )]


@register_test(
    id="recon.excessive_permissions",
    name="Detección de permisos/alcance excesivo declarado",
    category=Category.RECON,
    description="Marca tools cuyo nombre/descripción sugiere capacidades muy amplias (fs, shell, network) sin sandboxing aparente.",
)
async def excessive_permissions(target, ctx) -> list[Finding]:
    tools = ctx.get("tools") or await target.list_tools()
    risky_kw = ["exec", "shell", "eval", "run_command", "system", "subprocess", "delete", "rm ", "write_file", "sql", "admin"]
    findings = []
    for tool in tools:
        blob = (tool["name"] + " " + tool.get("description", "")).lower()
        matched = [k for k in risky_kw if k in blob]
        if matched:
            findings.append(Finding(
                test_id="recon.excessive_permissions",
                title=f"Tool con capacidad potencialmente peligrosa: '{tool['name']}'",
                category=Category.RECON,
                target=tool["name"],
                description=f"Palabras clave de alto riesgo detectadas: {matched}. Validar sandboxing, límites y "
                             f"confirmación humana antes de ejecutar.",
                evidence=Evidence(response=tool),
                passed=False,
                remediation="Asegurar sandboxing estricto, allowlist de comandos/paths, y human-in-the-loop "
                             "para operaciones destructivas o de ejecución arbitraria.",
            ))
    if not findings:
        findings.append(Finding(
            test_id="recon.excessive_permissions",
            title="Sin tools de alto riesgo evidente",
            category=Category.RECON,
            target="server",
            description="Ningún tool coincide con palabras clave de alto riesgo (heurística de nombre/descripción).",
            passed=True,
        ))
    return findings
