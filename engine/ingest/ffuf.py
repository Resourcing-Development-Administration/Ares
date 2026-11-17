"""Parse ffuf JSON output → assets and facts."""
from __future__ import annotations
import json
from urllib.parse import urlparse
from .models import Asset, IngestFact, IngestResult

# ARTEX-port: ffuf JSON ingestion

_INTERESTING_STATUSES = {200, 201, 204, 301, 302, 307, 308, 403, 401}


def parse_ffuf_json(json_content: str, target: str = "") -> IngestResult:
    assets: list[Asset] = []
    facts: list[IngestFact] = []
    errors: list[str] = []

    try:
        data = json.loads(json_content.strip())
    except json.JSONDecodeError as e:
        return IngestResult(assets=[], facts=[], source_tool="ffuf", target=target,
                            errors=[f"ffuf JSON parse error: {e}"])

    results = data.get("results") or []

    for item in results:
        url = item.get("url", "")
        status = item.get("status", 0)
        length = item.get("length", 0)
        content_type = item.get("content-type", "")

        if not url or status not in _INTERESTING_STATUSES:
            continue

        assets.append(Asset(kind="url", value=url,
                            attrs={"status": status, "length": length,
                                   "content_type": content_type}))

        try:
            parsed = urlparse(url)
            path = parsed.path.rstrip("/") or "/"
            facts.append(IngestFact(
                subject=f"{parsed.scheme}://{parsed.netloc}",
                predicate="found_path",
                object=path,
                raw={"status": status, "length": length},
            ))
        except Exception:
            pass

        facts.append(IngestFact(
            subject=url, predicate="has_status", object=str(status),
            raw={"length": length},
        ))

    return IngestResult(assets=assets, facts=facts, source_tool="ffuf",
                        target=target, errors=errors)
