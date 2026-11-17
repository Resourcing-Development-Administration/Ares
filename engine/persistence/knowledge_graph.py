"""
Knowledge Graph — grafo de exploración sobre PostgreSQL.
Modela relaciones entre subdominios, URLs, findings y scans.
Inspirado en ARTEX que usa un grafo de conocimiento Postgres.

Si Postgres no está disponible, todas las operaciones son noop.
"""
from __future__ import annotations
import json
import os
from typing import Any

POSTGRES_DSN = os.environ.get("ARES_POSTGRES_DSN", "")

_GRAPH_SCHEMA = """
CREATE TABLE IF NOT EXISTS kg_nodes (
    id          BIGSERIAL PRIMARY KEY,
    node_type   TEXT NOT NULL,   -- 'domain', 'url', 'ip', 'finding', 'scan'
    value       TEXT NOT NULL,
    metadata    JSONB DEFAULT '{}',
    created_at  TIMESTAMPTZ DEFAULT NOW(),
    UNIQUE(node_type, value)
);

CREATE TABLE IF NOT EXISTS kg_edges (
    id          BIGSERIAL PRIMARY KEY,
    src_id      BIGINT REFERENCES kg_nodes(id) ON DELETE CASCADE,
    dst_id      BIGINT REFERENCES kg_nodes(id) ON DELETE CASCADE,
    rel_type    TEXT NOT NULL,  -- 'has_subdomain', 'has_url', 'has_finding',
                                --  'resolves_to', 'scanned_by'
    metadata    JSONB DEFAULT '{}',
    created_at  TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS kg_edges_src ON kg_edges(src_id);
CREATE INDEX IF NOT EXISTS kg_edges_dst ON kg_edges(dst_id);
CREATE INDEX IF NOT EXISTS kg_nodes_type_value ON kg_nodes(node_type, value);
"""


class KnowledgeGraph:
    """Grafo de exploración: nodos (dominio/URL/finding) + aristas (relaciones)."""

    def __init__(self, pool: Any | None = None) -> None:
        self._pool = pool

    @classmethod
    async def connect(cls) -> "KnowledgeGraph":
        if not POSTGRES_DSN:
            return cls(pool=None)
        try:
            import asyncpg
            pool = await asyncpg.create_pool(POSTGRES_DSN, min_size=1, max_size=3)
            async with pool.acquire() as conn:
                await conn.execute(_GRAPH_SCHEMA)
            return cls(pool=pool)
        except Exception:
            return cls(pool=None)

    @property
    def available(self) -> bool:
        return self._pool is not None

    async def close(self) -> None:
        if self._pool:
            await self._pool.close()

    # ─── node upsert ─────────────────────────────────────────────────────────

    async def upsert_node(
        self,
        node_type: str,
        value: str,
        metadata: dict | None = None,
    ) -> int | None:
        if not self._pool:
            return None
        async with self._pool.acquire() as conn:
            row = await conn.fetchrow(
                """
                INSERT INTO kg_nodes (node_type, value, metadata)
                VALUES ($1, $2, $3)
                ON CONFLICT (node_type, value) DO UPDATE
                SET metadata = kg_nodes.metadata || EXCLUDED.metadata
                RETURNING id
                """,
                node_type, value, json.dumps(metadata or {}),
            )
            return row["id"] if row else None

    async def upsert_edge(
        self,
        src_type: str, src_value: str,
        rel_type: str,
        dst_type: str, dst_value: str,
        metadata: dict | None = None,
    ) -> None:
        if not self._pool:
            return
        src_id = await self.upsert_node(src_type, src_value)
        dst_id = await self.upsert_node(dst_type, dst_value)
        if src_id is None or dst_id is None:
            return
        async with self._pool.acquire() as conn:
            await conn.execute(
                """
                INSERT INTO kg_edges (src_id, dst_id, rel_type, metadata)
                VALUES ($1, $2, $3, $4)
                ON CONFLICT DO NOTHING
                """,
                src_id, dst_id, rel_type, json.dumps(metadata or {}),
            )

    # ─── domain / subdomain ──────────────────────────────────────────────────

    async def add_domain(self, domain: str, metadata: dict | None = None) -> None:
        await self.upsert_node("domain", domain, metadata)

    async def add_subdomain(self, parent: str, subdomain: str) -> None:
        await self.upsert_edge("domain", parent, "has_subdomain", "domain", subdomain)

    async def add_url(self, domain: str, url: str, metadata: dict | None = None) -> None:
        await self.upsert_edge("domain", domain, "has_url", "url", url, metadata)

    async def add_finding_to_domain(
        self, domain: str, fingerprint: str, title: str, severity: str
    ) -> None:
        await self.upsert_node("finding", fingerprint, {"title": title, "severity": severity})
        await self.upsert_edge("domain", domain, "has_finding", "finding", fingerprint)

    # ─── queries ─────────────────────────────────────────────────────────────

    async def get_subdomains(self, domain: str) -> list[str]:
        if not self._pool:
            return []
        async with self._pool.acquire() as conn:
            rows = await conn.fetch(
                """
                SELECT n2.value FROM kg_nodes n1
                JOIN kg_edges e ON e.src_id = n1.id
                JOIN kg_nodes n2 ON n2.id = e.dst_id
                WHERE n1.node_type = 'domain' AND n1.value = $1
                  AND e.rel_type = 'has_subdomain'
                """,
                domain,
            )
        return [r["value"] for r in rows]

    async def get_findings_for_domain(self, domain: str) -> list[dict]:
        if not self._pool:
            return []
        async with self._pool.acquire() as conn:
            rows = await conn.fetch(
                """
                SELECT n2.value as fingerprint, n2.metadata
                FROM kg_nodes n1
                JOIN kg_edges e ON e.src_id = n1.id
                JOIN kg_nodes n2 ON n2.id = e.dst_id
                WHERE n1.node_type = 'domain' AND n1.value = $1
                  AND e.rel_type = 'has_finding'
                ORDER BY n2.created_at DESC
                """,
                domain,
            )
        result = []
        for r in rows:
            meta = r["metadata"] or {}
            if isinstance(meta, str):
                try:
                    meta = json.loads(meta)
                except Exception:
                    meta = {}
            result.append({"fingerprint": r["fingerprint"], **meta})
        return result

    async def domain_summary(self, domain: str) -> dict:
        if not self._pool:
            return {"domain": domain, "available": False}
        subdomains = await self.get_subdomains(domain)
        findings = await self.get_findings_for_domain(domain)
        async with self._pool.acquire() as conn:
            url_count = await conn.fetchval(
                """
                SELECT COUNT(*) FROM kg_nodes n1
                JOIN kg_edges e ON e.src_id = n1.id
                WHERE n1.node_type = 'domain' AND n1.value = $1 AND e.rel_type = 'has_url'
                """,
                domain,
            )
        return {
            "domain": domain,
            "subdomains_count": len(subdomains),
            "subdomains": subdomains[:20],
            "urls_count": url_count or 0,
            "findings_count": len(findings),
            "findings": findings[:10],
        }

    async def populate_from_report(
        self,
        report: "Any",
        domain: str | None = None,
    ) -> None:
        """Popula el grafo con datos de un ScanReport."""
        if not self._pool:
            return
        from engine.reporting.dedup import fingerprint as fp_fn
        try:
            from urllib.parse import urlparse
            base_domain = domain or urlparse(report.target_name).netloc or report.target_name
        except Exception:
            base_domain = report.target_name

        await self.add_domain(base_domain)

        # subdominios del target
        if hasattr(report, "_netrecon_target") and report._netrecon_target:
            for sub in report._netrecon_target.discovered_subdomains:
                await self.add_subdomain(base_domain, sub)
            for url in list(report._netrecon_target.crawled_urls)[:500]:
                await self.add_url(base_domain, url)

        # findings confirmados
        for f in report.findings:
            if not f.passed:
                fp = fp_fn(f)
                sev = f.severity.value if hasattr(f.severity, "value") else str(f.severity)
                await self.add_finding_to_domain(base_domain, fp, f.title, sev)
