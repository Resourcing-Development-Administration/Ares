"""Parse bbot JSONL output → assets and facts (scope_distance=0 only)."""
from __future__ import annotations
import json
from .models import Asset, IngestFact, IngestResult

# ARTEX-port: bbot JSONL ingestion — mirrors agent/bbot_ingest.go
# Only scope_distance == 0 events are ingested; others become intel only.

_TYPE_KIND: dict[str, str] = {
    "DNS_NAME": "domain",
    "IP_ADDRESS": "ip",
    "OPEN_TCP_PORT": "port",
    "URL": "url",
    "URL_UNVERIFIED": "url",
}


def parse_bbot_jsonl(jsonl_content: str, target: str = "") -> IngestResult:
    assets: list[Asset] = []
    facts: list[IngestFact] = []
    errors: list[str] = []

    for lineno, line in enumerate(jsonl_content.splitlines(), 1):
        line = line.strip()
        if not line:
            continue
        try:
            row = json.loads(line)
        except json.JSONDecodeError as e:
            errors.append(f"bbot line {lineno}: {e}")
            continue

        scope_distance = row.get("scope_distance", 1)
        if scope_distance != 0:
            continue

        event_type = row.get("type", "")
        data = row.get("data", "")
        tags: list = row.get("tags") or []
        source = row.get("source", "")

        if event_type in _TYPE_KIND and data:
            kind = _TYPE_KIND[event_type]
            value = data if isinstance(data, str) else str(data)
            assets.append(Asset(kind=kind, value=value,
                                attrs={"tags": tags, "source": source}))

            if event_type == "DNS_NAME" and source:
                facts.append(IngestFact(subject=source, predicate="has_subdomain",
                                        object=value, raw={"tags": tags}))
            elif event_type == "OPEN_TCP_PORT" and isinstance(data, str) and ":" in data:
                host, port = data.rsplit(":", 1)
                facts.append(IngestFact(subject=host, predicate="has_open_port",
                                        object=port, raw={"tags": tags}))
            elif event_type in ("URL", "URL_UNVERIFIED") and source:
                facts.append(IngestFact(subject=source, predicate="has_url",
                                        object=value, raw={"tags": tags}))

        elif event_type == "VULNERABILITY":
            vuln_data = data if isinstance(data, dict) else {}
            host = vuln_data.get("host", target)
            vuln_name = vuln_data.get("name", "")
            severity = vuln_data.get("severity", "unknown")
            if host and vuln_name:
                facts.append(IngestFact(subject=host, predicate="has_vulnerability",
                                        object=vuln_name,
                                        raw={"severity": severity, "tags": tags}))

        elif event_type == "FINDING":
            find_data = data if isinstance(data, dict) else {}
            host = find_data.get("host", target)
            description = find_data.get("description", "")
            if host and description:
                facts.append(IngestFact(subject=host, predicate="has_finding",
                                        object=description[:200],
                                        raw={"tags": tags}))

        elif event_type == "HTTP_RESPONSE":
            resp_data = data if isinstance(data, dict) else {}
            url = resp_data.get("url", "")
            status = resp_data.get("status_code", "")
            if url:
                assets.append(Asset(kind="url", value=url,
                                    attrs={"status_code": status}))
                facts.append(IngestFact(subject=url, predicate="has_http_response",
                                        object=str(status),
                                        raw={"tags": tags}))

    return IngestResult(assets=assets, facts=facts, source_tool="bbot",
                        target=target, errors=errors)
