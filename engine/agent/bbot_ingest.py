"""
bbot_ingest — Typed, injection-safe bbot output.json parser.
Port of ARTEX agent/bbot_ingest.go.
"""
from __future__ import annotations

import json
import re
import urllib.parse
from dataclasses import dataclass, field
from typing import Any

_TYPED_TYPES = frozenset([
    "DNS_NAME", "IP_ADDRESS", "OPEN_TCP_PORT", "URL", "HTTP_RESPONSE",
    "FINDING", "VULNERABILITY", "TECHNOLOGY", "EMAIL_ADDRESS",
    "SOCIAL", "AZURE_TENANT", "SUBDOMAIN",
])

_SCOPE_IN = 0


@dataclass
class BbotEvent:
    type: str
    scope_distance: int
    host: str
    url: str
    port: int
    module: str
    source: str
    quoted: str


@dataclass
class BbotIngest:
    in_scope: list[BbotEvent] = field(default_factory=list)
    intel: list[BbotEvent] = field(default_factory=list)
    skipped: int = 0


_IP_RE = re.compile(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$")
_HOST_RE = re.compile(r"^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z]{2,})+$")


def _validate_host(h: str) -> str:
    if not h:
        return ""
    h = h.strip().lower()
    if _IP_RE.match(h) or _HOST_RE.match(h):
        return h
    return ""


def _validate_url(u: str) -> str:
    if not u:
        return ""
    try:
        parsed = urllib.parse.urlparse(u)
        if parsed.scheme in ("http", "https") and parsed.netloc:
            return u
    except Exception:
        pass
    return ""


def _quote_free(raw: Any) -> str:
    if raw is None:
        return ""
    return repr(str(raw)[:2000])


def parse_bbot_jsonl(content: str) -> BbotIngest:
    """
    Parse bbot output.json (one JSON object per line).
    Only typed fields are extracted; free text is kept inert.
    """
    result = BbotIngest()
    for line in content.splitlines():
        line = line.strip()
        if not line or not line.startswith("{"):
            result.skipped += 1
            continue
        try:
            raw = json.loads(line)
        except json.JSONDecodeError:
            result.skipped += 1
            continue

        etype = str(raw.get("type", "")).upper()
        if etype not in _TYPED_TYPES:
            result.skipped += 1
            continue

        scope_dist = raw.get("scope_distance")
        try:
            scope_int = int(scope_dist) if scope_dist is not None else 1
        except (ValueError, TypeError):
            scope_int = 1

        host = _validate_host(str(raw.get("host") or ""))
        url = _validate_url(str(raw.get("url") or ""))
        port = 0
        try:
            port = int(raw.get("port") or 0)
        except (ValueError, TypeError):
            pass
        module = str(raw.get("module") or "")[:64]

        data = raw.get("data") or raw.get("data_json") or ""
        quoted = _quote_free(data) if data else ""

        source = "tool_output" if scope_int == _SCOPE_IN else "third_party_intel"

        ev = BbotEvent(
            type=etype,
            scope_distance=scope_int,
            host=host,
            url=url,
            port=port,
            module=module,
            source=source,
            quoted=quoted,
        )

        if scope_int == _SCOPE_IN:
            result.in_scope.append(ev)
        else:
            result.intel.append(ev)

    return result


def to_assets_and_facts(ingest: BbotIngest) -> tuple[list[dict], list[dict]]:
    assets: list[dict] = []
    facts: list[dict] = []
    seen_assets: set[str] = set()

    for ev in ingest.in_scope:
        if ev.host and ev.host not in seen_assets:
            seen_assets.add(ev.host)
            assets.append({"type": "Host", "value": ev.host, "props": {"module": ev.module}})
        if ev.url and ev.url not in seen_assets:
            seen_assets.add(ev.url)
            assets.append({"type": "URL", "value": ev.url, "props": {"module": ev.module}})
        if ev.port and ev.host:
            key = f"{ev.host}:{ev.port}"
            if key not in seen_assets:
                seen_assets.add(key)
                assets.append({"type": "Port", "value": key, "props": {"module": ev.module}})
        if ev.quoted:
            facts.append({
                "subject": ev.host or ev.url or "unknown",
                "predicate": f"bbot_{ev.type.lower()}",
                "object": ev.quoted,
                "source": ev.source,
                "confidence": 0.8,
            })

    for ev in ingest.intel:
        if (ev.host or ev.url) and ev.quoted:
            facts.append({
                "subject": ev.host or ev.url,
                "predicate": f"bbot_{ev.type.lower()}",
                "object": ev.quoted,
                "source": "third_party_intel",
                "confidence": 0.6,
            })

    return assets, facts
