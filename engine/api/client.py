"""
Cliente HTTP del módulo de APIs. Todo pasa por acá: credenciales A/B, retardo entre requests, tope de
tamaño de respuesta (el target es hostil por definición), log de evidencia. NUNCA sigue redirects
solo: un 302 a otro host no debe sacar las credenciales del scope auditado.
"""
from __future__ import annotations
import asyncio
import json
import time
from urllib.parse import urlparse

import httpx

from engine.core.limits import cap_text, MAX_RESPONSE_CONTENT


class ApiTarget:
    def __init__(self, base_url: str, *, headers: dict | None = None, auth_a: dict | None = None,
                 auth_b: dict | None = None, verify=True, delay_ms: int = 0, timeout: float = 15.0,
                 max_body: int = MAX_RESPONSE_CONTENT):
        self.base_url = base_url.rstrip("/")
        self.origin = f"{urlparse(base_url).scheme}://{urlparse(base_url).netloc}"
        self.headers = dict(headers or {})
        self.auth = {"a": dict(auth_a or {}), "b": dict(auth_b or {})}
        self.delay_ms, self.max_body = delay_ms, max_body
        self.client = httpx.AsyncClient(verify=verify, timeout=timeout, follow_redirects=False)
        self.call_log: list[dict] = []
        self.request_count = 0

    async def close(self):
        await self.client.aclose()

    def has_auth(self, who: str = "a") -> bool:
        return bool(self.auth.get(who))

    def url(self, path: str) -> str:
        """Path relativo al base_url: si el base trae un prefijo (/api/v1) y el path del spec no lo
        incluye, se antepone; un URL completo se respeta tal cual."""
        if path.startswith(("http://", "https://")):
            return path
        bp = urlparse(self.base_url).path.rstrip("/")
        p = "/" + path.lstrip("/")
        if bp and p != bp and not p.startswith(bp + "/"):
            p = bp + p
        return self.origin + p

    async def request(self, method: str, path: str, *, params=None, json_body=None, data=None, content=None,
                      headers: dict | None = None, auth: str | None = "a", raw_url: bool = False) -> dict:
        """auth: 'a' | 'b' | None (sin credenciales). Devuelve SIEMPRE un dict, nunca levanta:
        {status, headers, text, json, elapsed_ms, error, url}."""
        if self.delay_ms:
            await asyncio.sleep(self.delay_ms / 1000)
        h = dict(self.headers)
        if auth:
            h.update(self.auth.get(auth, {}))
        else:
            for k in list(h):  # "sin credenciales" también quita lo que venga en --header
                if k.lower() in ("authorization", "cookie", "x-api-key"):
                    h.pop(k)
        if headers:
            h.update(headers)
        url = path if raw_url else self.url(path)
        t0 = time.monotonic()
        self.request_count += 1
        out = {"status": None, "headers": {}, "text": "", "json": None, "elapsed_ms": 0.0, "error": None, "url": url}
        try:
            r = await self.client.request(method.upper(), url, params=params, json=json_body, data=data,
                                          content=content, headers=h)
            out["status"] = r.status_code
            out["headers"] = {k.lower(): v for k, v in r.headers.items()}
            out["text"] = cap_text(r.text, self.max_body)
            if "json" in out["headers"].get("content-type", "") or out["text"][:1] in ("{", "["):
                try:
                    out["json"] = json.loads(out["text"])
                except Exception:
                    pass
        except Exception as e:
            out["error"] = f"{type(e).__name__}: {e}"
        out["elapsed_ms"] = (time.monotonic() - t0) * 1000
        self.call_log.append({"method": method.upper(), "url": url, "status": out["status"], "error": out["error"]})
        return out
