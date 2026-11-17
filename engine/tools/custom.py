"""
Custom user-defined tools — puerto de ARTEX custom tools (tipo http/command/bash).
Los tools definidos aquí se exponen al agente LLM como herramientas adicionales.
"""
from __future__ import annotations

import asyncio
import json
import os
import re
import shlex
import subprocess
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Optional
import uuid

try:
    import httpx as _httpx
    _HAS_HTTPX = True
except ImportError:
    _HAS_HTTPX = False


class CustomToolType(str, Enum):
    HTTP = "http"
    COMMAND = "command"
    BASH = "bash"


@dataclass
class CustomTool:
    id: str = field(default_factory=lambda: uuid.uuid4().hex[:8])
    name: str = ""
    description: str = ""
    tool_type: CustomToolType = CustomToolType.COMMAND
    # HTTP fields
    url_template: str = ""
    method: str = "GET"
    headers_template: dict = field(default_factory=dict)
    body_template: str = ""
    # COMMAND/BASH fields
    command_template: str = ""
    timeout_s: int = 60
    # LLM params schema
    params: list[dict] = field(default_factory=list)
    # Control
    enabled: bool = True
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def to_dict(self) -> dict:
        d = asdict(self)
        d["tool_type"] = self.tool_type.value
        return d

    @classmethod
    def from_dict(cls, d: dict) -> "CustomTool":
        d = dict(d)
        if "tool_type" in d:
            d["tool_type"] = CustomToolType(d["tool_type"])
        return cls(**d)


_SECRET_PATTERNS = [
    re.compile(r'(?i)(password|passwd|secret|token|api[_-]?key|auth)["\s:=]+\S+'),
    re.compile(r'Bearer\s+\S+'),
    re.compile(r'Basic\s+[A-Za-z0-9+/=]{8,}'),
]


def _redact_secrets(text: str) -> str:
    for pat in _SECRET_PATTERNS:
        text = pat.sub(lambda m: m.group(0)[:m.start(1) - m.start(0) + len(m.group(1))] + " [REDACTED]", text)
    return text


class CustomToolStore:
    """Persistence en JSON + ejecución de custom tools."""

    def __init__(self, store_path: str = "reports/custom_tools.json") -> None:
        self._path = store_path
        self._tools: dict[str, CustomTool] = {}
        self._load()

    # ── CRUD ──────────────────────────────────────────────────────────────────

    def add(self, tool: CustomTool) -> CustomTool:
        if not tool.name:
            raise ValueError("custom tool name is required")
        for existing in self._tools.values():
            if existing.name == tool.name and existing.id != tool.id:
                raise ValueError(f"tool name '{tool.name}' already exists")
        self._tools[tool.id] = tool
        self._save()
        return tool

    def update(self, id: str, **kwargs) -> Optional[CustomTool]:
        t = self._tools.get(id)
        if t is None:
            return None
        d = t.to_dict()
        for k, v in kwargs.items():
            if k in d:
                d[k] = v
        self._tools[id] = CustomTool.from_dict(d)
        self._save()
        return self._tools[id]

    def delete(self, id: str) -> bool:
        if id not in self._tools:
            return False
        del self._tools[id]
        self._save()
        return True

    def get(self, id: str) -> Optional[CustomTool]:
        return self._tools.get(id)

    def list_all(self, enabled_only: bool = False) -> list[CustomTool]:
        tools = list(self._tools.values())
        if enabled_only:
            tools = [t for t in tools if t.enabled]
        return sorted(tools, key=lambda t: t.created_at)

    def as_tool_definitions(self) -> list[dict]:
        """Convierte CustomTools al formato de tool definitions del LLM pool."""
        defs = []
        for t in self.list_all(enabled_only=True):
            props: dict[str, Any] = {}
            required: list[str] = []
            for p in t.params:
                props[p["name"]] = {
                    "type": p.get("type", "string"),
                    "description": p.get("description", ""),
                }
                if p.get("required", False):
                    required.append(p["name"])
            defs.append({
                "name": t.name,
                "description": t.description,
                "input_schema": {
                    "type": "object",
                    "properties": props,
                    "required": required,
                },
            })
        return defs

    # ── Execution ─────────────────────────────────────────────────────────────

    async def execute(self, tool_id: str, params: dict, gate: Any = None) -> str:
        t = self._tools.get(tool_id)
        if t is None:
            return f"[custom-tool error] tool '{tool_id}' not found"
        if not t.enabled:
            return f"[custom-tool error] tool '{t.name}' is disabled"

        try:
            if t.tool_type == CustomToolType.HTTP:
                return await self._execute_http(t, params, gate)
            elif t.tool_type in (CustomToolType.COMMAND, CustomToolType.BASH):
                return await self._execute_command(t, params)
            else:
                return f"[custom-tool error] unknown type '{t.tool_type}'"
        except Exception as e:
            return f"[custom-tool error] {e}"

    async def _execute_http(self, t: CustomTool, params: dict, gate: Any) -> str:
        if not _HAS_HTTPX:
            return "[custom-tool error] httpx not installed"
        url = self._render_template(t.url_template, params)
        body = self._render_template(t.body_template, params) if t.body_template else None
        headers = {k: self._render_template(v, params) for k, v in t.headers_template.items()}

        # Gate check
        if gate is not None:
            from urllib.parse import urlparse
            host = urlparse(url).hostname or ""
            decision = gate.check(host, test_id=f"custom.{t.name}", level=1)
            if decision.action == "deny":
                return f"[gate denied] {decision.reason}"

        async with _httpx.AsyncClient(timeout=t.timeout_s, follow_redirects=True) as client:
            resp = await client.request(
                method=t.method,
                url=url,
                headers=headers,
                content=body.encode() if body else None,
            )
        output = f"HTTP {resp.status_code}\n{dict(resp.headers)}\n\n{resp.text[:4096]}"
        return _redact_secrets(output)

    async def _execute_command(self, t: CustomTool, params: dict) -> str:
        cmd_str = self._render_template(t.command_template, params)
        if t.tool_type == CustomToolType.BASH:
            cmd = ["bash", "-c", cmd_str]
        else:
            try:
                cmd = shlex.split(cmd_str)
            except ValueError:
                cmd = ["bash", "-c", cmd_str]

        loop = asyncio.get_event_loop()
        try:
            proc = await asyncio.wait_for(
                loop.run_in_executor(
                    None,
                    lambda: subprocess.run(
                        cmd, capture_output=True, text=True, timeout=t.timeout_s,
                        env={**os.environ},
                    ),
                ),
                timeout=t.timeout_s + 5,
            )
            output = (proc.stdout or "") + (proc.stderr or "")
            return _redact_secrets(output[:8192])
        except asyncio.TimeoutError:
            return f"[custom-tool timeout after {t.timeout_s}s]"

    def _render_template(self, template: str, params: dict) -> str:
        """Reemplaza {{param_name}} con params.get(param_name, '')."""
        def replace(m: re.Match) -> str:
            key = m.group(1).strip()
            return str(params.get(key, ""))
        return re.sub(r"\{\{([^}]+)\}\}", replace, template)

    # ── Persistence ───────────────────────────────────────────────────────────

    def _load(self) -> None:
        if not os.path.exists(self._path):
            return
        try:
            with open(self._path, encoding="utf-8") as fh:
                data = json.load(fh)
            for item in data:
                t = CustomTool.from_dict(item)
                self._tools[t.id] = t
        except Exception:
            pass

    def _save(self) -> None:
        os.makedirs(os.path.dirname(self._path) if os.path.dirname(self._path) else ".", exist_ok=True)
        try:
            with open(self._path, "w", encoding="utf-8") as fh:
                json.dump([t.to_dict() for t in self._tools.values()], fh, indent=2, ensure_ascii=False)
        except Exception:
            pass


# ARTEX-port: custom user-defined tools (http/command/bash types)
