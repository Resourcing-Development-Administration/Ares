"""Parse httpx JSONL output → assets and facts."""
from __future__ import annotations
import json
from .models import Asset, IngestFact, IngestResult

# ARTEX-port: httpx JSONL ingestion


def parse_httpx_jsonl(jsonl_content: str, target: str = "") -> IngestResult:
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
            errors.append(f"httpx line {lineno}: {e}")
            continue

        url = row.get("url") or row.get("input", "")
        host = row.get("host") or row.get("input", "")
        status_code = row.get("status-code") or row.get("status_code")
        webserver = row.get("webserver") or row.get("web-server", "")
        title = row.get("title", "")
        techs: list = row.get("tech") or row.get("technologies") or []
        tls = row.get("tls") or {}

        if url:
            attrs: dict = {}
            if status_code is not None:
                attrs["status_code"] = status_code
            if title:
                attrs["title"] = title
            assets.append(Asset(kind="url", value=url, attrs=attrs))

        if host and status_code is not None:
            facts.append(IngestFact(subject=host, predicate="has_status",
                                    object=str(status_code),
                                    raw={"url": url, "title": title}))

        if host and webserver:
            facts.append(IngestFact(subject=host, predicate="runs_webserver",
                                    object=webserver))

        for tech in techs:
            tech_name = tech if isinstance(tech, str) else tech.get("name", str(tech))
            if tech_name:
                facts.append(IngestFact(subject=host or url, predicate="uses_tech",
                                        object=tech_name))

        if tls:
            tls_subject = (tls.get("subject") or {}).get("common_name", "") or \
                          tls.get("subject_cn", "")
            if tls_subject:
                facts.append(IngestFact(subject=host or url, predicate="has_tls_cert",
                                        object=tls_subject,
                                        raw={"expiry": tls.get("not_after", "")}))

    return IngestResult(assets=assets, facts=facts, source_tool="httpx",
                        target=target, errors=errors)
