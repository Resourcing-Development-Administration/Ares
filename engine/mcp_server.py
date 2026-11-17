"""
MCP Server mode — expone Ares como servidor MCP.

Permite que cualquier cliente MCP (Claude Desktop, agentes externos)
use las capacidades de Ares como herramientas MCP nativas.

Herramientas expuestas:
  - ares_netrecon        — reconocimiento de red activo
  - ares_agent_scan      — scan autónomo dirigido por LLM
  - ares_scan            — scan MCP completo (server stdio/HTTP/SSE)
  - ares_tools_status    — estado de herramientas instaladas
  - ares_list_reports    — lista reportes recientes
  - ares_get_report      — obtiene un reporte por scan_id

Arrancar: python -m engine.mcp_server
  o desde cli: ares serve --mcp-mode
"""
from __future__ import annotations
import asyncio
import json
import os
import sys

from mcp.server.fastmcp import FastMCP

mcp = FastMCP(
    "ares-redteam",
    instructions=(
        "Ares es una plataforma de red-team para servidores MCP y aplicaciones web. "
        "Sus herramientas ejecutan tests de seguridad reales contra el target especificado. "
        "IMPORTANTE: solo usar sobre targets con autorización explícita."
    ),
)

# ─── herramientas ────────────────────────────────────────────────────────────

@mcp.tool()
async def ares_netrecon(
    target_url: str,
    scope: str = "",
    tests: str = "",
    nuclei_severity: str = "critical,high,medium",
    timeout_s: int = 180,
    environment: str = "production",
) -> str:
    """Ejecuta reconocimiento de red activo contra target_url.

    Args:
        target_url: URL o dominio del objetivo (ej: https://example.com)
        scope: Dominios en scope separados por coma. Recomendado siempre.
        tests: IDs de tests a correr separados por coma. Vacío = todos.
        nuclei_severity: Severidades nuclei (critical,high,medium,low,info)
        timeout_s: Timeout por test en segundos (default 180)
        environment: production|staging|development

    Returns:
        JSON con resumen del scan: score, findings, política.
    """
    from engine.netrecon.runner import run_netrecon_scan

    scope_list = [s.strip() for s in scope.split(",") if s.strip()] if scope else None
    selected = [s.strip() for s in tests.split(",") if s.strip()] if tests else None
    severities = [s.strip() for s in nuclei_severity.split(",") if s.strip()]

    events: list[dict] = []

    def cb(event: dict) -> None:
        events.append(event)

    report = await run_netrecon_scan(
        target_url=target_url,
        scope=scope_list,
        selected_tests=selected,
        nuclei_severity=severities,
        timeout_s=timeout_s,
        environment=environment,
        progress_cb=cb,
    )

    confirmed = [f for f in report.findings if not f.passed]
    return json.dumps({
        "scan_id": report.scan_id,
        "target": target_url,
        "confirmed_findings": len(confirmed),
        "score": report.score,
        "policy_verdict": report.policy_verdict,
        "findings": [
            {
                "test_id": f.test_id,
                "title": f.title,
                "severity": f.severity.value if hasattr(f.severity, "value") else str(f.severity),
                "description": (f.description or "")[:500],
            }
            for f in confirmed[:20]
        ],
    }, ensure_ascii=False, indent=2)


@mcp.tool()
async def ares_agent_scan(
    target_url: str,
    scope: str = "",
    goal: str = "",
    provider: str = "auto",
    model: str = "",
    max_rounds: int = 8,
    allow_level3: bool = False,
) -> str:
    """Scan autónomo dirigido por LLM. El agente decide qué tests correr.

    Args:
        target_url: URL o dominio del objetivo
        scope: Dominios en scope separados por coma
        goal: Instrucción al agente (ej: 'Encontrar SQLi y paneles admin')
        provider: Provider LLM: auto|anthropic|openai|deepseek|nvidia|mistral|groq|
                  together|openrouter|gemini|xai|ollama|custom. 'auto' detecta
                  automáticamente las API keys configuradas en el entorno.
        model: Nombre del modelo (vacío = default del provider)
        max_rounds: Rondas máximas de llamadas al LLM
        allow_level3: Permitir tests nivel 3 (sqlmap — intrusivo)

    Returns:
        JSON con resumen del scan y análisis final del agente.
    """
    from engine.agent.orchestrator import run_agent_scan

    scope_list = [s.strip() for s in scope.split(",") if s.strip()] if scope else None

    events: list[dict] = []

    def cb(event: dict) -> None:
        events.append(event)

    report = await run_agent_scan(
        target_url=target_url,
        scope=scope_list,
        goal=goal or None,
        provider=provider,
        model=model or None,
        max_rounds=max_rounds,
        allow_level3=allow_level3,
        progress_cb=cb,
    )

    confirmed = [f for f in report.findings if not f.passed]
    agent_notes = [f for f in report.findings
                   if f.test_id in ("agent.analyst_note", "agent.final_analysis")]
    return json.dumps({
        "scan_id": report.scan_id,
        "target": target_url,
        "confirmed_findings": len(confirmed),
        "score": report.score,
        "policy_verdict": report.policy_verdict,
        "agent_analysis": [
            {"title": f.title, "content": (f.description or "")[:800]}
            for f in agent_notes
        ],
        "findings": [
            {
                "test_id": f.test_id,
                "title": f.title,
                "severity": f.severity.value if hasattr(f.severity, "value") else str(f.severity),
            }
            for f in confirmed[:20]
        ],
    }, ensure_ascii=False, indent=2)


@mcp.tool()
async def ares_tools_status() -> str:
    """Estado de las herramientas de red instaladas (nuclei, httpx, subfinder, etc.).

    Returns:
        JSON con nombre, versión, disponibilidad y fuente de cada herramienta.
    """
    from engine.tools.paths import tools_status
    status = tools_status()
    return json.dumps(status, ensure_ascii=False, indent=2)


@mcp.tool()
async def ares_list_reports(limit: int = 20, mode: str = "") -> str:
    """Lista los reportes de scans recientes.

    Args:
        limit: Máximo de reportes a retornar (default 20)
        mode: Filtrar por modo (scan, api-scan, netrecon, agent-scan). Vacío = todos.

    Returns:
        JSON con lista de reportes ordenados por fecha descendente.
    """
    import os
    reports_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), "reports")
    index_path = os.path.join(reports_dir, "index.json")
    if not os.path.exists(index_path):
        return json.dumps([])
    try:
        with open(index_path, encoding="utf-8") as fh:
            entries = json.load(fh)
        if mode:
            entries = [e for e in entries if e.get("mode") == mode]
        entries = entries[:limit]
        return json.dumps(entries, ensure_ascii=False, indent=2)
    except Exception as e:
        return json.dumps({"error": str(e)})


@mcp.tool()
async def ares_get_report(scan_id: str) -> str:
    """Obtiene el reporte completo de un scan por su scan_id.

    Args:
        scan_id: ID del scan (ej: 'abc12345')

    Returns:
        JSON con el reporte completo incluyendo todos los findings.
    """
    import os
    reports_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), "reports")
    report_path = os.path.join(reports_dir, scan_id, "report.json")
    if not os.path.exists(report_path):
        return json.dumps({"error": f"scan_id '{scan_id}' no encontrado"})
    try:
        with open(report_path, encoding="utf-8") as fh:
            return fh.read()
    except Exception as e:
        return json.dumps({"error": str(e)})


# ─── resources ───────────────────────────────────────────────────────────────

@mcp.resource("ares://tests/netrecon")
async def resource_netrecon_tests() -> str:
    """Lista todos los tests de reconocimiento de red disponibles."""
    from engine.netrecon.registry import all_net_tests
    tests = all_net_tests()
    return json.dumps([
        {"id": t["id"], "name": t["name"], "level": t.get("level", 1),
         "description": t.get("description", "")}
        for t in tests
    ], ensure_ascii=False, indent=2)


@mcp.resource("ares://status")
async def resource_status() -> str:
    """Estado general de Ares: versión, tools, providers LLM disponibles."""
    from engine import __version__
    from engine.agent.llmpool import _OAI_COMPAT
    provider_keys = {
        "anthropic": bool(os.environ.get("ANTHROPIC_API_KEY")),
        "ollama":    bool(os.environ.get("OLLAMA_BASE_URL") or True),  # siempre intenta
        "custom":    bool(os.environ.get("CUSTOM_LLM_URL")),
        **{name: bool(os.environ.get(key_env))
           for name, (_, key_env, _) in _OAI_COMPAT.items()},
    }
    configured = [k for k, v in provider_keys.items() if v]
    return json.dumps({
        "version": __version__,
        "mcp_server_mode": True,
        "configured_providers": configured,
        "postgres_configured": bool(os.environ.get("ARES_POSTGRES_DSN")),
        "notifications_configured": bool(
            os.environ.get("ARES_NOTIFY_WEBHOOK_URL")
            or os.environ.get("ARES_NOTIFY_SLACK_URL")
            or os.environ.get("ARES_NOTIFY_FEISHU_URL")
        ),
    }, indent=2)


if __name__ == "__main__":
    mcp.run()
