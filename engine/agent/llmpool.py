"""
LLM Pool multi-proveedor con health checks y fallback automático.

Proveedores soportados:
  Nativos:
    - anthropic     → Claude (Sonnet, Opus, Haiku) vía SDK oficial
    - ollama        → modelos locales (llama3, mistral, qwen, etc.)

  OpenAI-compatible (misma API, distinto base_url + key):
    - openai        → GPT-4o, GPT-4o-mini, o1, etc.
    - deepseek      → DeepSeek-V3, DeepSeek-R1 (DEEPSEEK_API_KEY)
    - nvidia        → NVIDIA NIM (llama3, mistral, etc.) (NVIDIA_API_KEY)
    - mistral       → Mistral-Large, Codestral, etc. (MISTRAL_API_KEY)
    - groq          → Llama3, Mixtral vía Groq (GROQ_API_KEY)
    - together      → Llama3, Qwen, etc. vía Together AI (TOGETHER_API_KEY)
    - azure         → Azure OpenAI (AZURE_OPENAI_KEY + AZURE_OPENAI_ENDPOINT)
    - openrouter    → cualquier modelo vía OpenRouter (OPENROUTER_API_KEY)
    - gemini        → Gemini Pro vía OpenAI-compat endpoint (GEMINI_API_KEY)
    - xai           → Grok (XAI_API_KEY)
    - custom        → cualquier endpoint OpenAI-compatible (CUSTOM_LLM_URL + CUSTOM_LLM_KEY)

Auto-detección (from_env):
  Detecta qué keys están configuradas y construye el pool con los disponibles.
  Orden de prioridad: anthropic > openai > deepseek > nvidia > mistral > groq > together > openrouter > gemini > xai > ollama > custom

Configuración:
  ARES_LLM_PROVIDER   = "auto" | "anthropic" | "openai" | "deepseek" | ...
  ARES_LLM_MODEL      = modelo por defecto para el provider principal
  <PROVIDER>_API_KEY  = clave de API del provider
  ANTHROPIC_API_KEY, OPENAI_API_KEY, DEEPSEEK_API_KEY, NVIDIA_API_KEY,
  MISTRAL_API_KEY, GROQ_API_KEY, TOGETHER_API_KEY, OPENROUTER_API_KEY,
  GEMINI_API_KEY, XAI_API_KEY, OLLAMA_BASE_URL, AZURE_OPENAI_KEY,
  AZURE_OPENAI_ENDPOINT, CUSTOM_LLM_URL, CUSTOM_LLM_KEY
"""
from __future__ import annotations
import asyncio
import json
import os
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Literal


Provider = Literal[
    "anthropic", "openai", "deepseek", "nvidia", "mistral",
    "groq", "together", "azure", "openrouter", "gemini",
    "xai", "ollama", "custom",
]

# Tabla de proveedores OpenAI-compatible: (base_url, env_key, default_model)
_OAI_COMPAT: dict[str, tuple[str, str, str]] = {
    "openai":     ("https://api.openai.com/v1",                       "OPENAI_API_KEY",     "gpt-4o-mini"),
    "deepseek":   ("https://api.deepseek.com/v1",                     "DEEPSEEK_API_KEY",   "deepseek-chat"),
    "nvidia":     ("https://integrate.api.nvidia.com/v1",             "NVIDIA_API_KEY",     "meta/llama-3.1-70b-instruct"),
    "mistral":    ("https://api.mistral.ai/v1",                       "MISTRAL_API_KEY",    "mistral-large-latest"),
    "groq":       ("https://api.groq.com/openai/v1",                  "GROQ_API_KEY",       "llama-3.1-70b-versatile"),
    "together":   ("https://api.together.xyz/v1",                     "TOGETHER_API_KEY",   "meta-llama/Meta-Llama-3.1-70B-Instruct-Turbo"),
    "openrouter": ("https://openrouter.ai/api/v1",                    "OPENROUTER_API_KEY", "meta-llama/llama-3.1-70b-instruct"),
    "gemini":     ("https://generativelanguage.googleapis.com/v1beta/openai", "GEMINI_API_KEY", "gemini-1.5-flash"),
    "xai":        ("https://api.x.ai/v1",                             "XAI_API_KEY",        "grok-beta"),
}


# Cooldown ladder: cada vez que el breaker se abre, el cooldown crece
# 1er fallo → 60s; 2do → 300s; 3ro+ → 1800s
_COOLDOWN_LADDER = [60, 300, 1800]


@dataclass
class ProviderHealth:
    provider: str
    model: str
    healthy: bool = True
    last_error: str | None = None
    last_check: float = field(default_factory=time.time)
    consecutive_failures: int = 0
    total_requests: int = 0
    total_errors: int = 0
    trip_count: int = 0       # cuántas veces se ha abierto el breaker
    _cooldown_until: float = field(default=0.0, repr=False)

    def mark_success(self) -> None:
        self.healthy = True
        self.consecutive_failures = 0
        self.total_requests += 1
        self._cooldown_until = 0.0

    def mark_failure(self, error: str, is_hard: bool = False) -> None:
        """Registra un fallo. is_hard=True para errores 401/402/403/404."""
        self.last_error = error
        self.consecutive_failures += 1
        self.total_requests += 1
        self.total_errors += 1
        self.last_check = time.time()
        if is_hard or self.consecutive_failures >= 3:
            # Abrir el breaker con ladder de cooldown
            cooldown_idx = min(self.trip_count, len(_COOLDOWN_LADDER) - 1)
            self._cooldown_until = time.time() + _COOLDOWN_LADDER[cooldown_idx]
            self.trip_count += 1
            self.healthy = False

    @property
    def in_cooldown(self) -> bool:
        return time.time() < self._cooldown_until

    @property
    def cooldown_remaining(self) -> float:
        return max(0.0, self._cooldown_until - time.time())

    def should_retry(self, cooldown_s: int = 60) -> bool:
        """Retorna True si el provider está en cooldown expirado y se puede reintentar."""
        if self.healthy:
            return False
        return not self.in_cooldown


# ---------------------------------------------------------------------------
# Provider adapters
# Protocolo interno normalizado: chat() → {content, content_normalized, stop_reason, provider, model}
# content_normalized: lista de {type:"text",text:...} o {type:"tool_use",id,name,input}
# ---------------------------------------------------------------------------

class _AnthropicAdapter:
    """Claude — usa el SDK oficial de Anthropic."""

    def __init__(self, model: str) -> None:
        try:
            import anthropic as _a
            self._lib = _a
        except ImportError:
            raise ImportError("pip install anthropic")
        self.model = model
        self._client: Any = None

    def _get_client(self) -> Any:
        if self._client is None:
            self._client = self._lib.AsyncAnthropic()
        return self._client

    async def chat(self, messages: list[dict], *, system: str,
                   tools: list[dict] | None = None, max_tokens: int = 4096,
                   stream_cb: Callable[[str], None] | None = None) -> dict:
        kwargs: dict[str, Any] = dict(
            model=self.model, max_tokens=max_tokens,
            system=system, messages=messages,
        )
        if tools:
            kwargs["tools"] = tools
        if stream_cb:
            async with self._get_client().messages.stream(**kwargs) as stream:
                async for text in stream.text_stream:
                    stream_cb(text)
                response = await stream.get_final_message()
        else:
            response = await self._get_client().messages.create(**kwargs)
        content_norm = []
        for block in response.content:
            if hasattr(block, "text"):
                content_norm.append({"type": "text", "text": block.text})
            elif getattr(block, "type", None) == "tool_use":
                content_norm.append({
                    "type": "tool_use", "id": block.id,
                    "name": block.name, "input": block.input,
                })
        return {
            "content": response.content,          # nativo — se agrega a messages[]
            "content_normalized": content_norm,
            "stop_reason": response.stop_reason,
            "provider": "anthropic", "model": self.model,
        }


class _OpenAICompatAdapter:
    """Adaptador genérico para cualquier API OpenAI-compatible.

    Funciona con OpenAI, DeepSeek, NVIDIA NIM, Mistral, Groq, Together,
    OpenRouter, Gemini (OpenAI-compat), xAI Grok, Azure OpenAI y endpoints custom.
    """

    def __init__(
        self,
        model: str,
        base_url: str,
        api_key: str,
        provider_name: str = "openai_compat",
        extra_headers: dict | None = None,
    ) -> None:
        self.model = model
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key
        self.provider_name = provider_name
        self.extra_headers = extra_headers or {}

    def _oai_messages(self, messages: list[dict], system: str) -> list[dict]:
        """Convierte mensajes del formato interno al formato OpenAI."""
        result = [{"role": "system", "content": system}]
        for m in messages:
            role = m["role"]
            content = m["content"]
            if isinstance(content, list):
                # puede ser native Anthropic content blocks o normalized dicts
                tool_calls = []
                tool_results = []
                text_parts = []
                for block in content:
                    # normalizado
                    if isinstance(block, dict):
                        t = block.get("type", "")
                        if t == "tool_use":
                            tool_calls.append({
                                "id": block["id"], "type": "function",
                                "function": {
                                    "name": block["name"],
                                    "arguments": json.dumps(block.get("input", {})),
                                },
                            })
                        elif t == "tool_result":
                            tool_results.append({
                                "role": "tool",
                                "tool_call_id": block["tool_use_id"],
                                "content": block.get("content", ""),
                            })
                        elif t == "text":
                            text_parts.append(block.get("text", ""))
                    # nativo Anthropic (objetos con .type)
                    elif hasattr(block, "type"):
                        if block.type == "tool_use":
                            tool_calls.append({
                                "id": block.id, "type": "function",
                                "function": {
                                    "name": block.name,
                                    "arguments": json.dumps(block.input),
                                },
                            })
                        elif block.type == "text":
                            text_parts.append(block.text)
                        elif block.type == "tool_result":
                            tool_results.append({
                                "role": "tool",
                                "tool_call_id": block.tool_use_id,
                                "content": block.content or "",
                            })
                if tool_results:
                    result.extend(tool_results)
                elif tool_calls:
                    result.append({
                        "role": "assistant",
                        "content": " ".join(text_parts) or None,
                        "tool_calls": tool_calls,
                    })
                elif text_parts:
                    result.append({"role": role, "content": " ".join(text_parts)})
            else:
                result.append({"role": role, "content": content})
        return result

    async def chat(self, messages: list[dict], *, system: str,
                   tools: list[dict] | None = None, max_tokens: int = 4096) -> dict:
        import httpx

        oai_messages = self._oai_messages(messages, system)
        payload: dict[str, Any] = {
            "model": self.model,
            "messages": oai_messages,
            "max_tokens": max_tokens,
        }
        if tools:
            payload["tools"] = [
                {"type": "function", "function": {
                    "name": t["name"],
                    "description": t.get("description", ""),
                    "parameters": t.get("input_schema", {}),
                }}
                for t in tools
            ]
            payload["tool_choice"] = "auto"

        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
            **self.extra_headers,
        }

        async with httpx.AsyncClient(timeout=120) as client:
            resp = await client.post(
                f"{self.base_url}/chat/completions",
                headers=headers, json=payload,
            )
            resp.raise_for_status()
            data = resp.json()

        choice = data["choices"][0]
        msg = choice["message"]
        content_norm = []
        txt = msg.get("content") or ""
        if txt:
            content_norm.append({"type": "text", "text": txt})
        for tc in (msg.get("tool_calls") or []):
            fn = tc["function"]
            try:
                args = json.loads(fn["arguments"])
            except Exception:
                args = {}
            content_norm.append({
                "type": "tool_use",
                "id": tc["id"],
                "name": fn["name"],
                "input": args,
            })

        stop = "end_turn"
        if msg.get("tool_calls"):
            stop = "tool_use"
        elif choice.get("finish_reason") == "length":
            stop = "max_tokens"

        return {
            "content": content_norm,       # normalizado — funciona con append a messages
            "content_normalized": content_norm,
            "stop_reason": stop,
            "provider": self.provider_name, "model": self.model,
        }


class _OllamaAdapter:
    """Modelos locales vía Ollama (llama3, mistral, qwen2, gemma, phi, etc.)."""

    def __init__(self, model: str, base_url: str | None = None) -> None:
        self.model = model
        self.base_url = (base_url or "http://localhost:11434").rstrip("/")

    async def chat(self, messages: list[dict], *, system: str,
                   tools: list[dict] | None = None, max_tokens: int = 4096) -> dict:
        import httpx

        ollama_msgs = [{"role": "system", "content": system}]
        for m in messages:
            content = m["content"]
            if isinstance(content, list):
                parts = []
                for b in content:
                    txt = ""
                    if isinstance(b, dict) and b.get("type") == "text":
                        txt = b.get("text", "")
                    elif hasattr(b, "type") and b.type == "text":
                        txt = b.text
                    elif isinstance(b, dict) and b.get("type") == "tool_result":
                        ollama_msgs.append({"role": "tool", "content": b.get("content", "")})
                        continue
                    if txt:
                        parts.append(txt)
                if parts:
                    ollama_msgs.append({"role": m["role"], "content": " ".join(parts)})
            else:
                ollama_msgs.append({"role": m["role"], "content": content})

        payload: dict[str, Any] = {
            "model": self.model, "messages": ollama_msgs,
            "stream": False, "options": {"num_predict": max_tokens},
        }
        if tools:
            payload["tools"] = [
                {"type": "function", "function": {
                    "name": t["name"],
                    "description": t.get("description", ""),
                    "parameters": t.get("input_schema", {}),
                }}
                for t in tools
            ]

        async with httpx.AsyncClient(timeout=180) as client:
            resp = await client.post(f"{self.base_url}/api/chat", json=payload)
            resp.raise_for_status()
            data = resp.json()

        msg = data.get("message", {})
        content_norm = []
        txt = msg.get("content", "")
        if txt:
            content_norm.append({"type": "text", "text": txt})
        for tc in (msg.get("tool_calls") or []):
            fn = tc.get("function", {})
            args = fn.get("arguments", {})
            if isinstance(args, str):
                try:
                    args = json.loads(args)
                except Exception:
                    args = {}
            content_norm.append({
                "type": "tool_use",
                "id": f"ollama_{fn.get('name','')}_{id(tc)}",
                "name": fn.get("name", ""),
                "input": args,
            })

        stop = "tool_use" if msg.get("tool_calls") else "end_turn"
        return {
            "content": content_norm,
            "content_normalized": content_norm,
            "stop_reason": stop,
            "provider": "ollama", "model": self.model,
        }


# ---------------------------------------------------------------------------
# Pool
# ---------------------------------------------------------------------------

class LLMPool:
    """Pool multi-proveedor con health checks y fallback automático.

    El primer provider saludable de la lista atiende cada request.
    Si falla 3 veces seguidas pasa a unhealthy (cooldown 60s).
    """

    def __init__(self, providers: list[tuple[str, Any]]) -> None:
        self._providers = providers
        # usar índice para evitar colisión si hay dos adapters con el mismo nombre
        self._health: dict[str, ProviderHealth] = {}
        for i, (name, adapter) in enumerate(providers):
            key = name if name not in self._health else f"{name}_{i}"
            self._health[key] = ProviderHealth(
                provider=name,
                model=getattr(adapter, "model", "unknown"),
            )
        self._health_keys = list(self._health.keys())

    # ─── factory methods ─────────────────────────────────────────────────────

    @classmethod
    def from_env(
        cls,
        preferred: str = "auto",
        model_override: str | None = None,
    ) -> "LLMPool":
        """Auto-detecta providers disponibles según env vars configuradas."""
        providers: list[tuple[str, Any]] = []

        pref = (os.environ.get("ARES_LLM_PROVIDER") or preferred).lower()
        env_model = model_override or os.environ.get("ARES_LLM_MODEL")

        def _add_oai_compat(name: str) -> None:
            base_url, key_env, default_model = _OAI_COMPAT[name]
            api_key = os.environ.get(key_env, "")
            if not api_key:
                return
            model = env_model if (pref == name and env_model) else default_model
            # Azure tiene endpoint custom
            if name == "azure":
                endpoint = os.environ.get("AZURE_OPENAI_ENDPOINT", "").rstrip("/")
                if not endpoint:
                    return
                api_version = os.environ.get("AZURE_OPENAI_API_VERSION", "2024-02-01")
                base_url = f"{endpoint}/openai"
                extra = {"api-version": api_version}
                providers.append((name, _OpenAICompatAdapter(
                    model or "gpt-4o", base_url, api_key, name, extra,
                )))
                return
            providers.append((name, _OpenAICompatAdapter(model, base_url, api_key, name)))

        # Anthropic (siempre intentar si hay key)
        if pref in ("auto", "anthropic") or (pref not in _OAI_COMPAT and pref not in ("ollama", "custom")):
            if os.environ.get("ANTHROPIC_API_KEY"):
                default_claude = "claude-sonnet-5-5"
                m = env_model if pref == "anthropic" and env_model else default_claude
                try:
                    providers.append(("anthropic", _AnthropicAdapter(m)))
                except ImportError:
                    pass

        # OpenAI-compatible providers
        order = ["openai", "deepseek", "nvidia", "mistral", "groq", "together",
                 "openrouter", "gemini", "xai", "azure"]
        if pref == "auto":
            for name in order:
                _add_oai_compat(name)
        elif pref in _OAI_COMPAT:
            _add_oai_compat(pref)
            # fallback: resto de providers
            for name in order:
                if name != pref:
                    _add_oai_compat(name)

        # Custom endpoint
        if os.environ.get("CUSTOM_LLM_URL"):
            custom_url = os.environ["CUSTOM_LLM_URL"]
            custom_key = os.environ.get("CUSTOM_LLM_KEY", "none")
            custom_model = env_model or os.environ.get("CUSTOM_LLM_MODEL", "default")
            providers.append(("custom", _OpenAICompatAdapter(
                custom_model, custom_url, custom_key, "custom",
            )))

        # Ollama (siempre al final como fallback local)
        if pref in ("auto", "ollama") or not providers:
            ollama_url = os.environ.get("OLLAMA_BASE_URL", "http://localhost:11434")
            ollama_model = env_model if pref == "ollama" and env_model else "llama3.2"
            providers.append(("ollama", _OllamaAdapter(ollama_model, ollama_url)))

        if not providers:
            raise RuntimeError(
                "No hay providers LLM disponibles. Configurá al menos una de estas variables:\n"
                "  ANTHROPIC_API_KEY (Claude) | OPENAI_API_KEY (GPT) | DEEPSEEK_API_KEY\n"
                "  NVIDIA_API_KEY | MISTRAL_API_KEY | GROQ_API_KEY | TOGETHER_API_KEY\n"
                "  OPENROUTER_API_KEY | GEMINI_API_KEY | XAI_API_KEY\n"
                "  CUSTOM_LLM_URL + CUSTOM_LLM_KEY | Ollama local en localhost:11434"
            )
        return cls(providers)

    @classmethod
    def single(
        cls,
        provider: str,
        model: str,
        base_url: str | None = None,
        api_key: str | None = None,
    ) -> "LLMPool":
        """Crea un pool con un solo provider explícito."""
        if provider == "anthropic":
            adapter: Any = _AnthropicAdapter(model)
        elif provider == "ollama":
            adapter = _OllamaAdapter(model, base_url)
        elif provider in _OAI_COMPAT:
            _, key_env, _ = _OAI_COMPAT[provider]
            key = api_key or os.environ.get(key_env, "")
            url = base_url or _OAI_COMPAT[provider][0]
            adapter = _OpenAICompatAdapter(model, url, key, provider)
        elif provider == "custom":
            if not base_url:
                raise ValueError("custom provider requiere base_url")
            adapter = _OpenAICompatAdapter(model, base_url, api_key or "none", "custom")
        else:
            raise ValueError(
                f"provider '{provider}' desconocido. Válidos: "
                f"anthropic, ollama, custom, {', '.join(_OAI_COMPAT)}"
            )
        return cls([(provider, adapter)])

    # ─── main API ────────────────────────────────────────────────────────────

    async def chat(
        self,
        messages: list[dict],
        *,
        system: str,
        tools: list[dict] | None = None,
        max_tokens: int = 4096,
    ) -> dict:
        """Envía request al primer provider saludable. Fallback automático."""
        last_error: Exception | None = None
        for key, (name, adapter) in zip(self._health_keys, self._providers):
            health = self._health[key]
            # Saltar si está en cooldown activo (breaker abierto y no expirado)
            if health.in_cooldown:
                continue
            if not health.healthy and not health.should_retry():
                continue
            try:
                result = await adapter.chat(
                    messages, system=system, tools=tools, max_tokens=max_tokens,
                )
                health.mark_success()
                return result
            except Exception as e:
                err_str = str(e)
                # Detectar errores hard (autenticación/permisos): abrir breaker inmediatamente
                is_hard = any(code in err_str for code in ("401", "402", "403", "404"))
                health.mark_failure(err_str, is_hard=is_hard)
                last_error = e
                continue
        raise RuntimeError(
            f"Todos los providers LLM fallaron. Último error: {last_error}"
        )

    def active_provider(self) -> str | None:
        """Retorna el nombre del primer provider saludable."""
        for key, (name, _) in zip(self._health_keys, self._providers):
            h = self._health[key]
            if h.healthy or h.should_retry():
                return name
        return None

    def health_summary(self) -> list[dict]:
        return [
            {
                "provider": h.provider, "model": h.model,
                "healthy": h.healthy, "total_requests": h.total_requests,
                "total_errors": h.total_errors,
                "consecutive_failures": h.consecutive_failures,
                "last_error": h.last_error,
            }
            for h in self._health.values()
        ]

    def health_status(self) -> dict:
        """Retorna estado de salud de todos los providers (incluye cooldown ladder)."""
        result = {}
        for name, health in self._health.items():
            result[name] = {
                "healthy": health.healthy,
                "consecutive_failures": health.consecutive_failures,
                "trip_count": health.trip_count,
                "cooldown_remaining_s": round(health.cooldown_remaining, 1),
                "in_cooldown": health.in_cooldown,
                "last_error": health.last_error,
                "total_requests": health.total_requests,
                "total_errors": health.total_errors,
            }
        return result

    def __repr__(self) -> str:
        providers = [f"{n}({getattr(a,'model','?')})" for n, a in self._providers]
        return f"LLMPool([{', '.join(providers)}])"
