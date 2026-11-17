"""Parse nuclei JSONL output → assets and facts."""
from __future__ import annotations
import json
from .models import Asset, IngestFact, IngestResult

# ARTEX-port: nuclei JSONL ingestion


def parse_nuclei_jsonl(jsonl_content: str, target: str = "") -> IngestResult:
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
            errors.append(f"nuclei line {lineno}: {e}")
            continue

        template_id = row.get("template-id") or row.get("templateID") or ""
        host = row.get("host", "")
        matched_at = row.get("matched-at") or row.get("matched") or host
        info = row.get("info", {})
        severity = info.get("severity", "info")
        name = info.get("name", template_id)
        classification = info.get("classification", {})
        cve_ids: list = classification.get("cve-id") or []
        if isinstance(cve_ids, str):
            cve_ids = [cve_ids]

        if matched_at:
            assets.append(Asset(kind="url", value=matched_at,
                                attrs={"severity": severity, "template": template_id}))

        if host and template_id:
            facts.append(IngestFact(
                subject=host, predicate="has_vulnerability", object=template_id,
                raw={"severity": severity, "name": name, "matched_at": matched_at},
            ))

        for cve in cve_ids:
            if cve:
                facts.append(IngestFact(
                    subject=host or matched_at, predicate="has_cve", object=cve.upper(),
                    raw={"template": template_id, "severity": severity},
                ))

        for extracted in (row.get("extracted-results") or []):
            if extracted:
                facts.append(IngestFact(
                    subject=matched_at or host, predicate="extracted_value",
                    object=str(extracted)[:500],
                    raw={"template": template_id},
                ))

    return IngestResult(assets=assets, facts=facts, source_tool="nuclei",
                        target=target, errors=errors)
