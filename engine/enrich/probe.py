"""
Enrich engine — DNS + HTTP probing para dominios y URLs.
Puerto de ARTEX enrich/probe con noise governor y gate HTTP.
"""
from __future__ import annotations

import asyncio
import socket
import time
from dataclasses import dataclass, field
from typing import Any, Optional
from urllib.parse import urlparse

try:
    import httpx as _httpx
    _HAS_HTTPX = True
except ImportError:
    _HAS_HTTPX = False


@dataclass
class EnrichResult:
    target: str
    # DNS
    a_records: list[str] = field(default_factory=list)
    aaaa_records: list[str] = field(default_factory=list)
    cname: Optional[str] = None
    # HTTP (only for URL enrichment)
    status_code: Optional[int] = None
    final_url: Optional[str] = None
    server: Optional[str] = None
    content_type: Optional[str] = None
    title: Optional[str] = None
    response_time_ms: Optional[float] = None
    # Misc
    errors: list[str] = field(default_factory=list)
    enriched_at: float = field(default_factory=time.time)

    def to_dict(self) -> dict:
        return {
            "target": self.target,
            "a_records": self.a_records,
            "aaaa_records": self.aaaa_records,
            "cname": self.cname,
            "status_code": self.status_code,
            "final_url": self.final_url,
            "server": self.server,
            "content_type": self.content_type,
            "title": self.title,
            "response_time_ms": self.response_time_ms,
            "errors": self.errors,
            "enriched_at": self.enriched_at,
        }


def _extract_title(html: str) -> Optional[str]:
    import re
    m = re.search(r"<title[^>]*>(.*?)</title>", html, re.I | re.S)
    if m:
        return m.group(1).strip()[:256]
    return None


class EnrichEngine:
    """DNS y HTTP enrichment con cooldown entre requests."""

    def __init__(
        self,
        gate: Any = None,
        http_timeout_s: float = 10.0,
        cooldown_s: float = 0.5,
        max_concurrent: int = 5,
        kg: Any = None,
    ) -> None:
        self.gate = gate
        self.http_timeout_s = http_timeout_s
        self.cooldown_s = cooldown_s
        self._sem = asyncio.Semaphore(max_concurrent)
        self._kg = kg  # engine.persistence.knowledge_graph.KnowledgeGraph | None

    async def enrich_domain(self, domain: str) -> EnrichResult:
        """DNS-only enrichment (sin gate — no emite tráfico HTTP)."""
        result = EnrichResult(target=domain)
        loop = asyncio.get_event_loop()

        # IPv4
        try:
            infos = await loop.getaddrinfo(domain, None, family=socket.AF_INET)
            result.a_records = list({i[4][0] for i in infos})
        except Exception as e:
            result.errors.append(f"DNS A: {e}")

        # IPv6
        try:
            infos6 = await loop.getaddrinfo(domain, None, family=socket.AF_INET6)
            result.aaaa_records = list({i[4][0] for i in infos6})
        except Exception:
            pass

        # CNAME (best-effort via socket)
        try:
            canon = socket.getfqdn(domain)
            if canon and canon != domain:
                result.cname = canon
        except Exception:
            pass

        await self._push_to_kg_domain(result)
        return result

    async def enrich_url(self, url: str) -> EnrichResult:
        """DNS + HTTP enrichment. Pasa por gate si está configurado."""
        result = EnrichResult(target=url)

        parsed = urlparse(url)
        host = parsed.hostname or ""
        loop = asyncio.get_event_loop()

        # DNS
        try:
            infos = await loop.getaddrinfo(host, None, family=socket.AF_INET)
            result.a_records = list({i[4][0] for i in infos})
        except Exception as e:
            result.errors.append(f"DNS A: {e}")

        # Gate check
        if self.gate is not None:
            decision = self.gate.check(host, test_id="enrich.probe", level=1)
            if decision.action == "deny":
                result.errors.append(f"gate denied: {decision.reason}")
                return result

        if not _HAS_HTTPX:
            result.errors.append("httpx not installed — HTTP enrichment skipped")
            return result

        # HTTP probe
        async with self._sem:
            try:
                t0 = time.monotonic()
                async with _httpx.AsyncClient(
                    timeout=self.http_timeout_s,
                    follow_redirects=True,
                    verify=False,
                ) as client:
                    resp = await client.get(url, headers={"User-Agent": "Ares/1.0 enrich"})
                elapsed_ms = (time.monotonic() - t0) * 1000
                result.status_code = resp.status_code
                result.final_url = str(resp.url)
                result.server = resp.headers.get("server", "")
                result.content_type = resp.headers.get("content-type", "")
                result.response_time_ms = round(elapsed_ms, 1)
                ct = result.content_type or ""
                if "html" in ct:
                    result.title = _extract_title(resp.text)
            except Exception as e:
                result.errors.append(f"HTTP: {e}")

            await asyncio.sleep(self.cooldown_s)

        await self._push_to_kg_url(result, url)
        return result

    async def _push_to_kg_domain(self, result: EnrichResult) -> None:
        if self._kg is None or not self._kg.available:
            return
        try:
            await self._kg.add_domain(result.target, {
                "a_records": result.a_records,
                "aaaa_records": result.aaaa_records,
                "cname": result.cname,
                "enriched_at": result.enriched_at,
            })
            for ip in result.a_records:
                await self._kg.upsert_edge("domain", result.target, "resolves_to", "ip", ip)
        except Exception:
            pass

    async def _push_to_kg_url(self, result: EnrichResult, url: str) -> None:
        if self._kg is None or not self._kg.available:
            return
        try:
            parsed = urlparse(url)
            domain = parsed.netloc.split(":")[0]
            if domain:
                await self._kg.add_domain(domain, {
                    "a_records": result.a_records,
                    "enriched_at": result.enriched_at,
                })
                await self._kg.add_url(domain, url, {
                    "status_code": result.status_code,
                    "server": result.server,
                    "title": result.title,
                    "response_time_ms": result.response_time_ms,
                })
                for ip in result.a_records:
                    await self._kg.upsert_edge("domain", domain, "resolves_to", "ip", ip)
        except Exception:
            pass

    async def enrich_batch(
        self,
        targets: list[str],
        mode: str = "url",  # "url" or "domain"
    ) -> list[EnrichResult]:
        """Enriquece una lista de targets en paralelo con cooldown."""
        async def _do(t: str) -> EnrichResult:
            if mode == "domain":
                return await self.enrich_domain(t)
            return await self.enrich_url(t)

        tasks = [asyncio.create_task(_do(t)) for t in targets]
        return list(await asyncio.gather(*tasks, return_exceptions=False))


# ARTEX-port: enrich/probe — DNS + HTTP enrichment con gate + noise governor
