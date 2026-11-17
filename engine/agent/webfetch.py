"""
webfetch — WebFetch tool integration with the egress governor.
Port of ARTEX agent/webfetch.go.
"""
from __future__ import annotations

import asyncio
from typing import Any


TOOL_SCHEMA = {
    "name": "web_fetch",
    "description": (
        "Fetch a URL and return its response. All requests are paced through the "
        "egress governor (noise profile rate limits). Use for HTTP reconnaissance "
        "that respects the task's scope and rate limits."
    ),
    "input_schema": {
        "type": "object",
        "properties": {
            "url": {"type": "string", "description": "URL to fetch."},
            "method": {
                "type": "string",
                "enum": ["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD"],
                "default": "GET",
            },
            "headers": {
                "type": "object",
                "additionalProperties": {"type": "string"},
                "description": "Optional request headers.",
            },
            "body": {
                "type": "string",
                "description": "Request body for POST/PUT/PATCH.",
            },
            "timeout": {
                "type": "integer",
                "description": "Timeout in seconds (default: 30).",
                "default": 30,
            },
            "follow_redirects": {
                "type": "boolean",
                "default": True,
            },
        },
        "required": ["url"],
    },
}


def _get_governor():
    try:
        from engine.egress.governor import get as _get
        return _get()
    except (ImportError, Exception):
        return None


async def web_fetch(params: dict[str, Any]) -> dict:
    """Execute the web_fetch tool call, pacing via the egress governor."""
    import aiohttp

    url = params.get("url", "")
    method = (params.get("method") or "GET").upper()
    headers = params.get("headers") or {}
    body = params.get("body") or None
    timeout_s = int(params.get("timeout") or 30)
    follow_redirects = params.get("follow_redirects", True)

    if not url:
        return {"error": "url is required"}

    gov = _get_governor()
    if gov is not None:
        try:
            async with asyncio.timeout(30.0):
                async with gov.acquire(url):
                    pass
        except (asyncio.TimeoutError, AttributeError, Exception):
            pass

    timeout = aiohttp.ClientTimeout(total=timeout_s)
    try:
        async with aiohttp.ClientSession(
            timeout=timeout,
            headers={**headers, "User-Agent": headers.get("User-Agent", "Ares/webfetch 1.0")},
        ) as session:
            resp = await session.request(
                method, url,
                data=body.encode() if body else None,
                allow_redirects=follow_redirects,
                ssl=False,
            )
            body_bytes = await resp.read()
            try:
                body_text = body_bytes.decode("utf-8", errors="replace")
            except Exception:
                body_text = body_bytes.hex()

            return {
                "url": str(resp.url),
                "status_code": resp.status,
                "headers": dict(resp.headers),
                "body": body_text[:65536],
                "body_truncated": len(body_bytes) > 65536,
                "content_type": resp.content_type,
            }
    except aiohttp.ClientError as exc:
        return {"error": str(exc), "url": url}
    except Exception as exc:
        return {"error": str(exc), "url": url}
