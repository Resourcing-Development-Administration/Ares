"""
RecordExternal — ingests captured exchanges from the browser extension CDP path.
Equivalent to ARTEX traffic/external.go.
"""
from __future__ import annotations

import time
from urllib.parse import urlparse

from .traffic import Traffic, _template_path


def _header_lines(headers: dict) -> str:
    return "\n".join(f"{k}: {v}" for k, v in headers.items())


def _to_header_map(raw: dict | None) -> dict:
    if not raw:
        return {}
    return {str(k).lower(): str(v) for k, v in raw.items()}


def record_external(t: Traffic, event: dict) -> None:
    """
    Ingest one browser-extension CDP event (request or response).
    Request/response pairs are joined by requestId stored in t._pending_ext.
    """
    if t is None:
        return
    etype = event.get("type")
    if etype not in ("request", "response"):
        return

    request_id = event.get("requestId") or event.get("networkId") or ""
    url = event.get("url", "")
    if not url:
        return

    try:
        parsed = urlparse(url)
    except Exception:
        return
    if not parsed.netloc:
        return

    if etype == "request":
        t._pending_ext[request_id] = {
            "method": (event.get("method") or "GET").upper(),
            "url": url,
            "host": parsed.hostname or "",
            "url_template": _template_path(parsed.path),
            "req_headers": _to_header_map(event.get("headers")),
            "req_body": (event.get("body") or "").encode("utf-8", errors="replace"),
            "ts": int(event.get("timestamp", time.time() * 1000)) // 1000,
        }

    elif etype == "response":
        pending = t._pending_ext.pop(request_id, None)
        ts = int(event.get("timestamp", time.time() * 1000)) // 1000
        url_template = _template_path(parsed.path)
        method = "GET"
        req_head = ""
        req_body = b""
        host = parsed.hostname or ""
        req_headers: dict = {}

        if pending:
            method = pending["method"]
            host = pending["host"] or host
            url_template = pending["url_template"] or url_template
            ts = pending["ts"]
            req_headers = pending["req_headers"]
            req_body = pending["req_body"]
            req_head = f"{method} {parsed.path or '/'} HTTP/1.1\n{_header_lines(req_headers)}"

        resp_headers = _to_header_map(event.get("headers") or event.get("responseHeaders"))
        resp_body_raw = (event.get("body") or "").encode("utf-8", errors="replace")
        content_type = resp_headers.get("content-type", "")
        status = int(event.get("statusCode") or 200)
        resp_head = f"HTTP {status}\n{_header_lines(resp_headers)}"

        with t._wlock:
            req_b = t._spill(req_body, req_headers.get("content-type", ""))
            resp_b = t._spill(resp_body_raw, content_type)
            id_ = t._next_id(ts)
            t._insert_exchange(
                id_, ts, host, method, url_template, url, status,
                content_type, len(req_body), len(resp_body_raw),
                req_head, req_b, resp_head, resp_b,
            )
