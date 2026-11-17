"""
Coverage ledger — rastrea la superficie ya cubierta por el agente.

Evita que el agente repita trabajo entre rondas y permite tomar decisiones
informadas sobre qué zonas de la superficie atacar a continuación.
Inspirado en ARTEX agent/coverage_ledger.go.
"""
from __future__ import annotations
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Literal


@dataclass
class CoverageEntry:
    test_id: str
    target: str
    started_at: str
    finished_at: str | None = None
    findings_count: int = 0
    confirmed_count: int = 0
    outcome: Literal["ok", "error", "gate_denied", "skipped"] = "ok"
    error: str | None = None


class CoverageLedger:
    """Libro mayor de cobertura — qué tests corrieron, cuándo, con qué resultado.

    Permite:
    - Saber qué tests quedan sin correr
    - Priorizar tests por zonas no exploradas
    - Generar un resumen de cobertura para el reporte final
    """

    def __init__(self) -> None:
        self._entries: list[CoverageEntry] = []
        self._started: dict[str, str] = {}  # test_id → started_at

    # ─── recording ───────────────────────────────────────────────────────────

    def record_started(self, test_id: str, target: str) -> None:
        ts = datetime.now(timezone.utc).isoformat()
        self._started[test_id] = ts
        self._entries.append(CoverageEntry(
            test_id=test_id, target=target, started_at=ts,
        ))

    def record_finished(
        self,
        test_id: str,
        findings_count: int = 0,
        confirmed_count: int = 0,
        outcome: Literal["ok", "error", "gate_denied", "skipped"] = "ok",
        error: str | None = None,
    ) -> None:
        ts = datetime.now(timezone.utc).isoformat()
        for e in reversed(self._entries):
            if e.test_id == test_id and e.finished_at is None:
                e.finished_at = ts
                e.findings_count = findings_count
                e.confirmed_count = confirmed_count
                e.outcome = outcome
                e.error = error
                break

    def record_gate_denied(self, test_id: str, target: str, reason: str) -> None:
        ts = datetime.now(timezone.utc).isoformat()
        self._entries.append(CoverageEntry(
            test_id=test_id, target=target,
            started_at=ts, finished_at=ts,
            outcome="gate_denied", error=reason,
        ))

    # ─── queries ─────────────────────────────────────────────────────────────

    @property
    def tested_ids(self) -> set[str]:
        return {e.test_id for e in self._entries
                if e.outcome in ("ok", "error")}

    @property
    def denied_ids(self) -> set[str]:
        return {e.test_id for e in self._entries if e.outcome == "gate_denied"}

    def was_tested(self, test_id: str) -> bool:
        return test_id in self.tested_ids

    def was_denied(self, test_id: str) -> bool:
        return test_id in self.denied_ids

    def untested(self, all_test_ids: list[str]) -> list[str]:
        done = self.tested_ids | self.denied_ids
        return [t for t in all_test_ids if t not in done]

    # ─── summary ─────────────────────────────────────────────────────────────

    def summary(self) -> dict:
        tested = [e for e in self._entries if e.outcome == "ok"]
        errors = [e for e in self._entries if e.outcome == "error"]
        denied = [e for e in self._entries if e.outcome == "gate_denied"]
        total_findings = sum(e.findings_count for e in tested)
        total_confirmed = sum(e.confirmed_count for e in tested)
        return {
            "tests_run": len(tested),
            "tests_errors": len(errors),
            "tests_gate_denied": len(denied),
            "total_findings": total_findings,
            "total_confirmed": total_confirmed,
            "coverage_pct": None,  # calculado externamente si se conoce el total
            "entries": [
                {
                    "test_id": e.test_id,
                    "outcome": e.outcome,
                    "findings": e.findings_count,
                    "confirmed": e.confirmed_count,
                    "started_at": e.started_at,
                    "finished_at": e.finished_at,
                    "error": e.error,
                }
                for e in self._entries
            ],
        }
