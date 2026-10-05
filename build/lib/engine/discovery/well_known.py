"""
Rutas conocidas de configs de clientes MCP por sistema operativo, portadas
del concepto de agent-scan/src/agent_scan/agents/well_known_clients.py
(tabla de rutas por cliente/SO), simplificado a lo que necesitamos: encontrar
el JSON y su clave "mcpServers".
"""
from __future__ import annotations
import os
import platform


def _expand(path: str) -> str:
    return os.path.expanduser(os.path.expandvars(path))


def known_config_paths() -> list[dict]:
    system = platform.system()  # "Linux" | "Darwin" | "Windows"
    home = os.path.expanduser("~")

    candidates = [
        {"client": "claude-desktop", "path": os.path.join(home, ".config/Claude/claude_desktop_config.json")},
        {"client": "claude-desktop", "path": os.path.join(home, "Library/Application Support/Claude/claude_desktop_config.json")},
        {"client": "claude-desktop", "path": _expand(os.path.join("%APPDATA%", "Claude", "claude_desktop_config.json"))},
        {"client": "claude-code", "path": os.path.join(home, ".claude.json")},
        {"client": "claude-code", "path": os.path.join(home, ".claude", "claude.json")},
        {"client": "cursor", "path": os.path.join(home, ".cursor", "mcp.json")},
        {"client": "vscode", "path": os.path.join(home, ".vscode", "mcp.json")},
        {"client": "windsurf", "path": os.path.join(home, ".codeium", "windsurf", "mcp_config.json")},
        {"client": "codex", "path": os.path.join(home, ".codex", "config.json")},
    ]
    return [c for c in candidates if os.path.isfile(c["path"])]
