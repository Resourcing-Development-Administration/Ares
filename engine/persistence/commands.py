"""
commands — Custom slash commands DB layer.
Port of ARTEX db/commands.go.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

_COMMANDS_DDL = """
CREATE TABLE IF NOT EXISTS custom_commands (
    id          SERIAL PRIMARY KEY,
    name        TEXT NOT NULL UNIQUE,   -- slash command name (without /)
    description TEXT NOT NULL DEFAULT '',
    body        TEXT NOT NULL,          -- command body / template
    agent_key   TEXT NOT NULL DEFAULT 'auto',
    enabled     BOOLEAN DEFAULT TRUE,
    created_at  TIMESTAMPTZ DEFAULT NOW(),
    updated_at  TIMESTAMPTZ DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS custom_commands_name ON custom_commands(name);
"""


@dataclass
class CustomCommand:
    id: int
    name: str
    description: str
    body: str
    agent_key: str
    enabled: bool


class CommandStore:
    def __init__(self, pool: Any):
        self._pool = pool

    async def setup(self) -> None:
        async with self._pool.acquire() as conn:
            await conn.execute(_COMMANDS_DDL)

    async def create(
        self,
        name: str,
        body: str,
        description: str = "",
        agent_key: str = "auto",
    ) -> CustomCommand:
        async with self._pool.acquire() as conn:
            row = await conn.fetchrow(
                """
                INSERT INTO custom_commands (name, description, body, agent_key)
                VALUES ($1, $2, $3, $4)
                ON CONFLICT (name) DO UPDATE
                  SET body=$3, description=$2, agent_key=$4, updated_at=NOW()
                RETURNING *
                """,
                name, description, body, agent_key,
            )
        return _row_to_cmd(row)

    async def get(self, name: str) -> CustomCommand | None:
        async with self._pool.acquire() as conn:
            row = await conn.fetchrow(
                "SELECT * FROM custom_commands WHERE name=$1 AND enabled=TRUE",
                name,
            )
        return _row_to_cmd(row) if row else None

    async def list_all(self) -> list[CustomCommand]:
        async with self._pool.acquire() as conn:
            rows = await conn.fetch(
                "SELECT * FROM custom_commands WHERE enabled=TRUE ORDER BY name"
            )
        return [_row_to_cmd(r) for r in rows]

    async def delete(self, name: str) -> None:
        async with self._pool.acquire() as conn:
            await conn.execute("DELETE FROM custom_commands WHERE name=$1", name)

    async def set_enabled(self, name: str, enabled: bool) -> None:
        async with self._pool.acquire() as conn:
            await conn.execute(
                "UPDATE custom_commands SET enabled=$1, updated_at=NOW() WHERE name=$2",
                enabled, name,
            )


def _row_to_cmd(row: Any) -> CustomCommand:
    return CustomCommand(
        id=row["id"],
        name=row["name"],
        description=row["description"],
        body=row["body"],
        agent_key=row["agent_key"],
        enabled=row["enabled"],
    )
