"""FactStore: in-memory typed facts with provenance. ARTEX-port."""
from __future__ import annotations
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Optional
import uuid


class FactSource(str, Enum):
    OBSERVED = "observed"   # directly witnessed (HTTP response, banner grab)
    INFERRED = "inferred"   # derived from observed facts (e.g. port → service guess)
    SCANNER = "scanner"     # scanner tool output (nmap, nuclei, httpx …)
    OPERATOR = "operator"   # analyst/operator manually asserted


@dataclass
class Fact:
    id: str
    subject: str
    predicate: str
    object: str
    source: FactSource
    tool: str                                   # originating scanner or "" if manual
    confidence: float = 1.0                     # 0.0–1.0
    created_at: str = ""
    raw: dict = field(default_factory=dict)     # original scanner row

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "subject": self.subject,
            "predicate": self.predicate,
            "object": self.object,
            "source": self.source.value,
            "tool": self.tool,
            "confidence": self.confidence,
            "created_at": self.created_at,
        }


class FactStore:
    """In-memory fact store. All writes go through add_fact(); query via by_subject/by_predicate."""

    def __init__(self) -> None:
        self._facts: list[Fact] = []
        self._by_subject: dict[str, list[Fact]] = {}
        self._by_predicate: dict[str, list[Fact]] = {}

    def add_fact(
        self,
        subject: str,
        predicate: str,
        object_: str,
        source: FactSource = FactSource.SCANNER,
        tool: str = "",
        confidence: float = 1.0,
        raw: Optional[dict] = None,
    ) -> Fact:
        fact = Fact(
            id=str(uuid.uuid4()),
            subject=subject,
            predicate=predicate,
            object=object_,
            source=source,
            tool=tool,
            confidence=confidence,
            created_at=datetime.now(timezone.utc).isoformat(),
            raw=raw or {},
        )
        self._facts.append(fact)
        self._by_subject.setdefault(subject, []).append(fact)
        self._by_predicate.setdefault(predicate, []).append(fact)
        return fact

    def add_from_ingest(self, ingest_facts: list, tool: str = "") -> list[Fact]:
        """Bulk-import IngestFact list from engine.ingest."""
        added: list[Fact] = []
        for inf in ingest_facts:
            source = FactSource.OBSERVED if inf.confidence == "observed" else FactSource.INFERRED
            added.append(self.add_fact(
                subject=inf.subject,
                predicate=inf.predicate,
                object_=inf.object,
                source=source,
                tool=tool or inf.source,
                raw=inf.raw,
            ))
        return added

    def by_subject(self, subject: str) -> list[Fact]:
        return self._by_subject.get(subject, [])

    def by_predicate(self, predicate: str) -> list[Fact]:
        return self._by_predicate.get(predicate, [])

    def all_facts(self) -> list[Fact]:
        return list(self._facts)

    def all_subjects(self) -> list[str]:
        return list(self._by_subject.keys())

    def __len__(self) -> int:
        return len(self._facts)
