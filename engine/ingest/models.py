"""Modelos compartidos del pipeline de ingesta de scanner output."""
from __future__ import annotations
from dataclasses import dataclass, field

# ARTEX-port: typed asset/fact models for scanner ingestion


@dataclass
class Asset:
    kind: str                               # domain / ip / url / port / service
    value: str
    attrs: dict = field(default_factory=dict)
    source: str = "scanner"                 # scanner / inference / observed


@dataclass
class IngestFact:
    subject: str                            # asset value que originó el hecho
    predicate: str                          # has_port / runs_service / has_cve / has_subdomain / has_url / ...
    object: str
    confidence: str = "observed"            # observed / inferred
    source: str = "scanner"
    raw: dict = field(default_factory=dict) # fila original del scanner


@dataclass
class IngestResult:
    assets: list[Asset]
    facts: list[IngestFact]
    source_tool: str
    target: str
    errors: list[str] = field(default_factory=list)

    def all_asset_values(self) -> list[str]:
        return [a.value for a in self.assets]
