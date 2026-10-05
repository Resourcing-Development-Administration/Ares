"""
Descubre servidores MCP configurados localmente (Claude Desktop, Cursor,
VSCode, etc.) parseando sus archivos de config conocidos. Concepto portado de
agent-scan/src/agent_scan/agents/{base,claude_desktop}.py: leer JSON, extraer
"mcpServers", y devolver una lista plana lista para alimentar un ScanConfig.
"""
from __future__ import annotations
import json

from engine.discovery.well_known import known_config_paths


def discover_mcp_servers() -> list[dict]:
    """Devuelve [{client, config_path, server_name, command, args, env, url}, ...]
    para cada server declarado en cada config conocida encontrada en esta máquina."""
    found = []
    for entry in known_config_paths():
        try:
            with open(entry["path"], "r", encoding="utf-8") as f:
                data = json.load(f)
        except Exception:
            continue

        servers = data.get("mcpServers") or data.get("mcp_servers") or {}
        for name, cfg in servers.items():
            if not isinstance(cfg, dict):
                continue
            found.append({
                "client": entry["client"],
                "config_path": entry["path"],
                "server_name": name,
                "command": cfg.get("command"),
                "args": cfg.get("args", []),
                "env": cfg.get("env"),
                "url": cfg.get("url") or cfg.get("serverUrl"),
                "headers": cfg.get("headers"),
            })
    return found
