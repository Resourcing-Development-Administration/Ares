"""
Conversation history persistence — PostgreSQL-backed chat thread store.
Port of ARTEX db/conversation.go.
"""
from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Any


@dataclass
class Conversation:
    id: int
    agent_key: str
    title: str
    llm_profile_id: int | None
    pinned: bool
    pinned_at: float | None
    created_at: float
    updated_at: float
    target_gate: bool = False


@dataclass
class ConversationActivity:
    id: int
    conversation_id: int
    kind: str          # "request" | "result" | "tool"
    role: str
    content: str
    input_tokens: int
    output_tokens: int
    cache_read_tokens: int
    cache_write_tokens: int
    created_at: float


CONVERSATIONS_DDL = """
CREATE TABLE IF NOT EXISTS conversations (
    id              BIGSERIAL PRIMARY KEY,
    agent_key       TEXT NOT NULL DEFAULT 'mainagent',
    title           TEXT NOT NULL DEFAULT '',
    llm_profile_id  BIGINT,
    pinned_at       TIMESTAMPTZ,
    target_gate     BOOLEAN NOT NULL DEFAULT FALSE,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS conversation_activities (
    id                 BIGSERIAL PRIMARY KEY,
    conversation_id    BIGINT NOT NULL REFERENCES conversations(id) ON DELETE CASCADE,
    kind               TEXT NOT NULL,
    role               TEXT NOT NULL DEFAULT '',
    content            TEXT NOT NULL DEFAULT '',
    input_tokens       INTEGER NOT NULL DEFAULT 0,
    output_tokens      INTEGER NOT NULL DEFAULT 0,
    cache_read_tokens  INTEGER NOT NULL DEFAULT 0,
    cache_write_tokens INTEGER NOT NULL DEFAULT 0,
    created_at         TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_ca_conv ON conversation_activities(conversation_id);
CREATE INDEX IF NOT EXISTS idx_ca_kind ON conversation_activities(kind);
"""


class ConversationStore:
    """PostgreSQL-backed conversation store."""

    def __init__(self, pool: Any):
        self._pool = pool

    async def create(
        self,
        agent_key: str = "mainagent",
        title: str = "",
        llm_profile_id: int | None = None,
        target_gate: bool = False,
    ) -> Conversation:
        async with self._pool.acquire() as conn:
            row = await conn.fetchrow(
                """INSERT INTO conversations(agent_key, title, llm_profile_id, target_gate)
                   VALUES($1, $2, $3, $4)
                   RETURNING id, agent_key, title, llm_profile_id, pinned_at,
                             created_at, updated_at, target_gate""",
                agent_key, title, llm_profile_id, target_gate,
            )
            return _row_to_conv(row)

    async def get(self, id_: int) -> Conversation | None:
        async with self._pool.acquire() as conn:
            row = await conn.fetchrow(
                """SELECT id, agent_key, title, llm_profile_id, pinned_at,
                          created_at, updated_at, target_gate
                   FROM conversations WHERE id=$1""",
                id_,
            )
            return _row_to_conv(row) if row else None

    async def list(
        self,
        agent_key: str | None = None,
        pinned_only: bool = False,
        limit: int = 50,
        offset: int = 0,
    ) -> list[Conversation]:
        where: list[str] = []
        args: list[Any] = []
        i = 1
        if agent_key:
            where.append(f"agent_key=${i}"); args.append(agent_key); i += 1
        if pinned_only:
            where.append("pinned_at IS NOT NULL")
        clause = ("WHERE " + " AND ".join(where)) if where else ""
        args += [limit, offset]
        async with self._pool.acquire() as conn:
            rows = await conn.fetch(
                f"""SELECT id, agent_key, title, llm_profile_id, pinned_at,
                           created_at, updated_at, target_gate
                    FROM conversations {clause}
                    ORDER BY COALESCE(pinned_at, '1970-01-01') DESC, updated_at DESC
                    LIMIT ${i} OFFSET ${i+1}""",
                *args,
            )
            return [_row_to_conv(r) for r in rows]

    async def update(
        self,
        id_: int,
        title: str | None = None,
        pinned: bool | None = None,
        target_gate: bool | None = None,
    ) -> Conversation | None:
        sets: list[str] = ["updated_at=now()"]
        args: list[Any] = []
        i = 1
        if title is not None:
            sets.append(f"title=${i}"); args.append(title); i += 1
        if pinned is not None:
            if pinned:
                sets.append("pinned_at=now()")
            else:
                sets.append("pinned_at=NULL")
        if target_gate is not None:
            sets.append(f"target_gate=${i}"); args.append(target_gate); i += 1
        args.append(id_)
        async with self._pool.acquire() as conn:
            row = await conn.fetchrow(
                f"""UPDATE conversations SET {', '.join(sets)} WHERE id=${i}
                    RETURNING id, agent_key, title, llm_profile_id, pinned_at,
                              created_at, updated_at, target_gate""",
                *args,
            )
            return _row_to_conv(row) if row else None

    async def delete(self, id_: int) -> bool:
        async with self._pool.acquire() as conn:
            result = await conn.execute(
                "DELETE FROM conversations WHERE id=$1", id_
            )
            return result.split()[-1] == "1"

    async def add_activity(
        self,
        conversation_id: int,
        kind: str,
        role: str,
        content: str,
        input_tokens: int = 0,
        output_tokens: int = 0,
        cache_read_tokens: int = 0,
        cache_write_tokens: int = 0,
    ) -> int:
        async with self._pool.acquire() as conn:
            row = await conn.fetchrow(
                """INSERT INTO conversation_activities
                   (conversation_id, kind, role, content,
                    input_tokens, output_tokens, cache_read_tokens, cache_write_tokens)
                   VALUES($1,$2,$3,$4,$5,$6,$7,$8)
                   RETURNING id""",
                conversation_id, kind, role, _utf8_clean(content),
                input_tokens, output_tokens, cache_read_tokens, cache_write_tokens,
            )
            return row["id"]

    async def get_activities(
        self,
        conversation_id: int,
        limit: int = 200,
    ) -> list[dict]:
        async with self._pool.acquire() as conn:
            rows = await conn.fetch(
                """SELECT id, conversation_id, kind, role, content,
                          input_tokens, output_tokens, cache_read_tokens, cache_write_tokens,
                          created_at
                   FROM conversation_activities
                   WHERE conversation_id=$1
                   ORDER BY id ASC LIMIT $2""",
                conversation_id, limit,
            )
            return [dict(r) for r in rows]

    async def token_summaries(self) -> list[dict]:
        """Return token usage per conversation (for dashboard stats)."""
        async with self._pool.acquire() as conn:
            rows = await conn.fetch(
                """SELECT c.llm_profile_id, c.created_at::text,
                          COALESCE(sum(ca.input_tokens),0),
                          COALESCE(sum(ca.output_tokens),0),
                          COALESCE(sum(ca.cache_read_tokens),0),
                          COALESCE(sum(ca.cache_write_tokens),0)
                   FROM conversations c
                   LEFT JOIN conversation_activities ca
                     ON ca.conversation_id = c.id AND ca.kind = 'result'
                   GROUP BY c.id""",
            )
            return [
                {
                    "llm_profile_id": r[0],
                    "created_at": r[1],
                    "input_tokens": r[2],
                    "output_tokens": r[3],
                    "cache_read_tokens": r[4],
                    "cache_write_tokens": r[5],
                }
                for r in rows
            ]


def _row_to_conv(row: Any) -> Conversation:
    pinned_at = row["pinned_at"]
    return Conversation(
        id=row["id"],
        agent_key=row["agent_key"],
        title=row["title"],
        llm_profile_id=row["llm_profile_id"],
        pinned=pinned_at is not None,
        pinned_at=pinned_at.timestamp() if pinned_at else None,
        created_at=row["created_at"].timestamp(),
        updated_at=row["updated_at"].timestamp(),
        target_gate=row["target_gate"],
    )


def _utf8_clean(s: str) -> str:
    return s.encode("utf-8", errors="replace").decode("utf-8").replace("\x00", "")
