"""
asset_intercept — Per-asset intercept rules for traffic capture and analysis.
Port of ARTEX db/asset_intercept.go.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

_INTERCEPT_DDL = """
CREATE TABLE IF NOT EXISTS asset_intercept_rules (
    id          SERIAL PRIMARY KEY,
    asset_id    INTEGER NOT NULL,
    kind        TEXT NOT NULL,       -- 'url_pattern', 'header_match', 'method_match'
    pattern     TEXT NOT NULL,
    action      TEXT NOT NULL,       -- 'capture', 'drop', 'flag'
    priority    INTEGER DEFAULT 0,
    enabled     BOOLEAN DEFAULT TRUE,
    created_at  TIMESTAMPTZ DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS asset_intercept_rules_asset_id ON asset_intercept_rules(asset_id);
"""


@dataclass
class InterceptRule:
    id: int
    asset_id: int
    kind: str
    pattern: str
    action: str
    priority: int
    enabled: bool
    _compiled: re.Pattern | None = field(default=None, repr=False)

    def matches(self, url: str, method: str = "", headers: dict | None = None) -> bool:
        if not self.enabled:
            return False
        if self.kind == "url_pattern":
            if self._compiled is None:
                try:
                    object.__setattr__(self, '_compiled', re.compile(self.pattern, re.IGNORECASE))
                except re.error:
                    return False
            return bool(self._compiled.search(url))
        if self.kind == "method_match":
            return method.upper() == self.pattern.upper()
        if self.kind == "header_match" and headers:
            k, _, v = self.pattern.partition(":")
            return headers.get(k.strip(), "").lower() == v.strip().lower()
        return False


class AssetInterceptStore:
    def __init__(self, pool: Any):
        self._pool = pool

    async def setup(self) -> None:
        async with self._pool.acquire() as conn:
            await conn.execute(_INTERCEPT_DDL)

    async def add_rule(
        self,
        asset_id: int,
        kind: str,
        pattern: str,
        action: str,
        priority: int = 0,
    ) -> int:
        async with self._pool.acquire() as conn:
            row = await conn.fetchrow(
                """
                INSERT INTO asset_intercept_rules (asset_id, kind, pattern, action, priority)
                VALUES ($1, $2, $3, $4, $5) RETURNING id
                """,
                asset_id, kind, pattern, action, priority,
            )
            return row["id"]

    async def list_rules(self, asset_id: int) -> list[InterceptRule]:
        async with self._pool.acquire() as conn:
            rows = await conn.fetch(
                "SELECT * FROM asset_intercept_rules WHERE asset_id=$1 ORDER BY priority DESC",
                asset_id,
            )
        return [
            InterceptRule(
                id=r["id"],
                asset_id=r["asset_id"],
                kind=r["kind"],
                pattern=r["pattern"],
                action=r["action"],
                priority=r["priority"],
                enabled=r["enabled"],
            )
            for r in rows
        ]

    async def delete_rule(self, rule_id: int) -> None:
        async with self._pool.acquire() as conn:
            await conn.execute("DELETE FROM asset_intercept_rules WHERE id=$1", rule_id)

    async def set_enabled(self, rule_id: int, enabled: bool) -> None:
        async with self._pool.acquire() as conn:
            await conn.execute(
                "UPDATE asset_intercept_rules SET enabled=$1 WHERE id=$2",
                enabled, rule_id,
            )
