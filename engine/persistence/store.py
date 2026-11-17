"""
Persistence layer opcional — PostgreSQL async (asyncpg) con fallback JSON.

Si asyncpg está disponible Y ARES_POSTGRES_DSN está configurado, usa Postgres.
Si no, usa el sistema JSON existente en reports/ (sin cambios de comportamiento).

Schema mínimo (auto-creado en connect()):
    ares_scans(id, scan_id, target_name, started_at, finished_at, score, policy_verdict,
               mode, findings_json, report_json, created_at)
    ares_findings(id, scan_id, fingerprint, test_id, title, severity, category,
                  target, passed, confidence, created_at)
    ares_schedules(id, entry_id, config_json, created_at, updated_at)

Uso:
    store = await PersistenceStore.connect()
    await store.save_report(report, mode="netrecon")
    rows = await store.list_reports(limit=50)
    await store.close()
"""
from __future__ import annotations
import json
import os
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from engine.core.models import ScanReport

POSTGRES_DSN = os.environ.get("ARES_POSTGRES_DSN", "")


def _has_asyncpg() -> bool:
    try:
        import asyncpg  # noqa
        return True
    except ImportError:
        return False


_CREATE_TABLES_SQL = """
CREATE TABLE IF NOT EXISTS ares_scans (
    id          BIGSERIAL PRIMARY KEY,
    scan_id     TEXT NOT NULL UNIQUE,
    target_name TEXT NOT NULL,
    started_at  TIMESTAMPTZ,
    finished_at TIMESTAMPTZ,
    score       JSONB,
    policy_verdict JSONB,
    mode        TEXT DEFAULT 'scan',
    findings_json JSONB DEFAULT '[]',
    report_json JSONB DEFAULT '{}',
    created_at  TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS ares_findings (
    id          BIGSERIAL PRIMARY KEY,
    scan_id     TEXT NOT NULL REFERENCES ares_scans(scan_id) ON DELETE CASCADE,
    fingerprint TEXT NOT NULL,
    test_id     TEXT NOT NULL,
    title       TEXT NOT NULL,
    severity    TEXT NOT NULL,
    category    TEXT NOT NULL,
    target      TEXT,
    passed      BOOLEAN NOT NULL DEFAULT FALSE,
    confidence  TEXT,
    created_at  TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS ares_findings_scan_id ON ares_findings(scan_id);
CREATE INDEX IF NOT EXISTS ares_findings_fingerprint ON ares_findings(fingerprint);

CREATE TABLE IF NOT EXISTS ares_schedules (
    id          BIGSERIAL PRIMARY KEY,
    entry_id    TEXT NOT NULL UNIQUE,
    config_json JSONB NOT NULL,
    created_at  TIMESTAMPTZ DEFAULT NOW(),
    updated_at  TIMESTAMPTZ DEFAULT NOW()
);
"""


class PersistenceStore:
    """Abstrae el backend de persistencia (Postgres o JSON noop)."""

    def __init__(self, pool: Any | None = None) -> None:
        self._pool = pool  # asyncpg Pool o None
        self._backend: str = "postgres" if pool else "json"

    @classmethod
    async def connect(cls) -> "PersistenceStore":
        if not POSTGRES_DSN or not _has_asyncpg():
            return cls(pool=None)
        import asyncpg
        try:
            pool = await asyncpg.create_pool(POSTGRES_DSN, min_size=1, max_size=5)
            # run versioned migrations (creates tables + ares_schema_migrations)
            try:
                from engine.persistence.migrations import MigrationManager
                mm = MigrationManager(pool)
                await mm.migrate()
            except Exception:
                # fallback: legacy inline DDL (keeps backward compat if sql/ dir missing)
                async with pool.acquire() as conn:
                    await conn.execute(_CREATE_TABLES_SQL)
            return cls(pool=pool)
        except Exception:
            return cls(pool=None)

    @classmethod
    async def connect_or_noop(cls) -> "PersistenceStore":
        """Siempre retorna un store (puede ser noop si Postgres no está disponible)."""
        return await cls.connect()

    @property
    def backend(self) -> str:
        return self._backend

    @property
    def available(self) -> bool:
        return self._pool is not None

    async def close(self) -> None:
        if self._pool:
            await self._pool.close()

    # ─── scans ───────────────────────────────────────────────────────────────

    async def save_report(self, report: "ScanReport", mode: str = "scan") -> bool:
        if not self._pool:
            return False
        from engine.reporting.dedup import fingerprint as fp_fn

        findings_json = []
        for f in report.findings:
            findings_json.append({
                "test_id": f.test_id,
                "title": f.title,
                "severity": f.severity.value if hasattr(f.severity, "value") else str(f.severity),
                "category": f.category.value if hasattr(f.category, "value") else str(f.category),
                "target": f.target,
                "passed": f.passed,
                "confidence": f.confidence,
                "fingerprint": fp_fn(f),
            })

        score_j = report.score if isinstance(report.score, dict) else None
        policy_j = report.policy_verdict if isinstance(report.policy_verdict, dict) else None

        try:
            async with self._pool.acquire() as conn:
                await conn.execute(
                    """
                    INSERT INTO ares_scans
                        (scan_id, target_name, started_at, finished_at, score,
                         policy_verdict, mode, findings_json)
                    VALUES ($1,$2,$3,$4,$5,$6,$7,$8)
                    ON CONFLICT (scan_id) DO UPDATE SET
                        finished_at = EXCLUDED.finished_at,
                        score = EXCLUDED.score,
                        policy_verdict = EXCLUDED.policy_verdict,
                        findings_json = EXCLUDED.findings_json
                    """,
                    report.scan_id,
                    report.target_name,
                    _parse_ts(report.started_at),
                    _parse_ts(report.finished_at),
                    json.dumps(score_j),
                    json.dumps(policy_j),
                    mode,
                    json.dumps(findings_json),
                )
                # upsert individual findings
                for f_data in findings_json:
                    await conn.execute(
                        """
                        INSERT INTO ares_findings
                            (scan_id, fingerprint, test_id, title, severity,
                             category, target, passed, confidence)
                        VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)
                        ON CONFLICT DO NOTHING
                        """,
                        report.scan_id,
                        f_data["fingerprint"],
                        f_data["test_id"],
                        f_data["title"],
                        f_data["severity"],
                        f_data["category"],
                        f_data.get("target"),
                        f_data["passed"],
                        f_data.get("confidence"),
                    )
            return True
        except Exception:
            return False

    async def list_reports(
        self,
        limit: int = 50,
        mode: str | None = None,
    ) -> list[dict]:
        if not self._pool:
            return []
        q = "SELECT scan_id, target_name, started_at, finished_at, score, policy_verdict, mode, created_at FROM ares_scans"
        args: list[Any] = []
        if mode:
            q += " WHERE mode = $1"
            args.append(mode)
        q += " ORDER BY created_at DESC LIMIT $" + str(len(args) + 1)
        args.append(limit)
        async with self._pool.acquire() as conn:
            rows = await conn.fetch(q, *args)
        return [dict(r) for r in rows]

    async def get_findings_by_fingerprint(self, fingerprint: str) -> list[dict]:
        if not self._pool:
            return []
        async with self._pool.acquire() as conn:
            rows = await conn.fetch(
                "SELECT * FROM ares_findings WHERE fingerprint = $1 ORDER BY created_at DESC",
                fingerprint,
            )
        return [dict(r) for r in rows]

    async def get_recurring_findings(
        self,
        target_name: str,
        min_occurrences: int = 2,
    ) -> list[dict]:
        """Findings que aparecen en múltiples scans del mismo target."""
        if not self._pool:
            return []
        async with self._pool.acquire() as conn:
            rows = await conn.fetch(
                """
                SELECT af.fingerprint, af.test_id, af.title, af.severity,
                       COUNT(DISTINCT af.scan_id) as occurrences
                FROM ares_findings af
                JOIN ares_scans s ON s.scan_id = af.scan_id
                WHERE s.target_name = $1 AND af.passed = FALSE
                GROUP BY af.fingerprint, af.test_id, af.title, af.severity
                HAVING COUNT(DISTINCT af.scan_id) >= $2
                ORDER BY occurrences DESC, af.severity DESC
                """,
                target_name, min_occurrences,
            )
        return [dict(r) for r in rows]


def _parse_ts(ts: str | None) -> datetime | None:
    if not ts:
        return None
    try:
        return datetime.fromisoformat(ts.replace("Z", "+00:00"))
    except Exception:
        return None
