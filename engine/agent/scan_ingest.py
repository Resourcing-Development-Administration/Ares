"""
scan_ingest — Parse scanner output files for structured asset/fact extraction.
Supports nmap XML, nuclei JSONL, httpx JSON, ffuf JSON.
Port of ARTEX agent/scan_ingest.go.
"""
from __future__ import annotations

import json
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from typing import Any

SCAN_NOTABLE_MAX = 20
SCAN_MAX_ITEMS = 50_000


@dataclass
class ScanIngest:
    events: int = 0
    ports: int = 0
    skipped: int = 0
    oversized: int = 0
    over_cap: int = 0
    truncated: bool = False
    assets: list[dict] = field(default_factory=list)
    facts: list[dict] = field(default_factory=list)
    notable: dict[str, list[str]] = field(default_factory=dict)

    def _note(self, kind: str, item: str) -> None:
        lst = self.notable.setdefault(kind, [])
        if len(lst) < SCAN_NOTABLE_MAX:
            lst.append(item)

    def _full(self) -> bool:
        return len(self.assets) + len(self.facts) >= SCAN_MAX_ITEMS


def _safe_text(s: str) -> str:
    return repr(s)


def parse_nmap_xml(content: str) -> ScanIngest:
    result = ScanIngest()
    try:
        root = ET.fromstring(content)
    except ET.ParseError:
        result.skipped += 1
        return result

    for host in root.findall("host"):
        state_el = host.find("status")
        if state_el is None or state_el.get("state") != "up":
            continue
        addr = host.find("address[@addrtype='ipv4']")
        ip = addr.get("addr", "") if addr is not None else ""
        if not ip:
            continue

        hostname_el = host.find("hostnames/hostname[@type='A']")
        hostname = hostname_el.get("name", "") if hostname_el is not None else ""

        result.events += 1
        if not result._full():
            result.assets.append({"type": "Host", "value": ip, "props": {"hostname": hostname}})
        else:
            result.over_cap += 1
            result.truncated = True

        for port in host.findall("ports/port"):
            state = port.find("state")
            if state is None or state.get("state") != "open":
                continue
            portnum = port.get("portid", "")
            proto = port.get("protocol", "tcp")
            service_el = port.find("service")
            service = service_el.get("name", "") if service_el is not None else ""
            banner = service_el.get("product", "") if service_el is not None else ""

            result.ports += 1
            if not result._full():
                result.assets.append({
                    "type": "Port",
                    "value": f"{ip}:{portnum}/{proto}",
                    "props": {"service": service, "banner": _safe_text(banner)},
                })
                if service:
                    result._note("open_ports", f"{ip}:{portnum} {service}")
            else:
                result.over_cap += 1
                result.truncated = True

    return result


def parse_nuclei_jsonl(content: str) -> ScanIngest:
    result = ScanIngest()
    for line in content.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            ev = json.loads(line)
        except json.JSONDecodeError:
            result.skipped += 1
            continue

        result.events += 1
        matched_at = ev.get("matched-at") or ev.get("host") or ""
        template_id = ev.get("template-id") or ev.get("templateID") or ""
        info = ev.get("info", {})
        severity = info.get("severity", "info") if isinstance(info, dict) else "info"

        if not result._full():
            result.facts.append({
                "subject": matched_at,
                "predicate": "nuclei_finding",
                "object": _safe_text(template_id),
                "source": "tool_output",
                "confidence": 0.9,
                "detail": _safe_text(json.dumps({"severity": severity, "id": template_id})),
            })
            result._note("nuclei_findings", f"{matched_at} → {template_id} ({severity})")
        else:
            result.over_cap += 1
            result.truncated = True

    return result


def parse_httpx_json(content: str) -> ScanIngest:
    result = ScanIngest()
    for line in content.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            ev = json.loads(line)
        except json.JSONDecodeError:
            result.skipped += 1
            continue

        result.events += 1
        url = ev.get("url") or ev.get("input") or ""
        status = ev.get("status_code") or ev.get("status") or 0
        title = ev.get("title") or ""
        tech = ev.get("tech") or ev.get("technologies") or []

        if not result._full() and url:
            result.assets.append({
                "type": "URL",
                "value": url,
                "props": {
                    "status_code": status,
                    "title": _safe_text(title),
                    "technologies": tech,
                },
            })
            if status and status < 400:
                result._note("live_urls", f"{url} ({status})")
        else:
            result.over_cap += 1
            result.truncated = True

    return result


def parse_ffuf_json(content: str) -> ScanIngest:
    result = ScanIngest()
    try:
        data = json.loads(content)
    except json.JSONDecodeError:
        result.skipped += 1
        return result

    results = data.get("results") or []
    for item in results:
        result.events += 1
        url = item.get("url") or ""
        status = item.get("status") or 0
        length = item.get("length") or 0

        if not result._full() and url:
            result.assets.append({
                "type": "URL",
                "value": url,
                "props": {"status_code": status, "content_length": length},
            })
            if status and status < 400:
                result._note("ffuf_hits", f"{url} ({status}, {length}b)")
        else:
            result.over_cap += 1
            result.truncated = True

    return result


def ingest_file(content: str, hint: str = "") -> ScanIngest:
    """Auto-detect scanner format and parse."""
    h = hint.lower()
    stripped = content.lstrip()

    if "nmap" in h or stripped.startswith("<?xml") or "<nmaprun" in stripped[:200]:
        return parse_nmap_xml(content)
    if "nuclei" in h or (stripped.startswith("{") and '"template-id"' in content[:500]):
        return parse_nuclei_jsonl(content)
    if "ffuf" in h or (stripped.startswith("{") and '"results"' in content[:200]):
        return parse_ffuf_json(content)
    if "httpx" in h or '"status_code"' in content[:500]:
        return parse_httpx_json(content)
    return parse_nuclei_jsonl(content)
