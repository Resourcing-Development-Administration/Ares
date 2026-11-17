"""Router principal del pipeline de ingesta de scanner output."""
from __future__ import annotations
from .models import IngestResult
from .nmap import parse_nmap_xml
from .nuclei import parse_nuclei_jsonl
from .httpx import parse_httpx_jsonl
from .ffuf import parse_ffuf_json
from .bbot import parse_bbot_jsonl

# ARTEX-port: dispatch scanner output to typed parsers


def ingest_scanner_output(
    tool: str,
    content: str,
    target: str = "",
) -> IngestResult:
    """Parsea el output de un scanner y retorna assets y facts tipados."""
    tool = tool.lower().strip()
    if tool == "nmap":
        return parse_nmap_xml(content, target)
    elif tool == "nuclei":
        return parse_nuclei_jsonl(content, target)
    elif tool in ("httpx", "httpx_probe"):
        return parse_httpx_jsonl(content, target)
    elif tool == "ffuf":
        return parse_ffuf_json(content, target)
    elif tool == "bbot":
        return parse_bbot_jsonl(content, target)
    else:
        return IngestResult(assets=[], facts=[], source_tool=tool, target=target,
                            errors=[f"ingest: unknown tool '{tool}'"])


async def ingest_and_persist(
    tool: str,
    content: str,
    target: str,
    kg: object,  # engine.persistence.knowledge_graph.KnowledgeGraph
) -> IngestResult:
    """Ingesta + persiste assets en el knowledge graph."""
    result = ingest_scanner_output(tool, content, target)
    if not result.assets:
        return result

    try:
        from urllib.parse import urlparse
        for asset in result.assets:
            if asset.kind == "domain":
                await kg.add_domain(asset.value)
            elif asset.kind == "url":
                parsed = urlparse(asset.value)
                domain = parsed.netloc.split(":")[0]
                if domain:
                    await kg.add_url(domain, asset.value)
            elif asset.kind in ("ip", "port"):
                # ip/port: agregar como nodo genérico
                await kg.upsert_node(asset.value, asset.kind, asset.attrs)
    except Exception:
        pass

    return result
