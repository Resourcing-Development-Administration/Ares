"""
Persistent exploration graph — PostgreSQL-backed intent/node graph.
Port of ARTEX db/exploration.go (selected core operations).
"""
from __future__ import annotations

import json
import time
import uuid
from dataclasses import dataclass
from typing import Any

EXPLORATION_DDL = """
CREATE TABLE IF NOT EXISTS exploration_nodes (
    id          TEXT PRIMARY KEY,
    task_id     TEXT NOT NULL,
    parent_id   TEXT,
    intent      TEXT NOT NULL DEFAULT '',
    state       TEXT NOT NULL DEFAULT 'pending',
    agent_key   TEXT NOT NULL DEFAULT 'worker',
    worker_id   TEXT,
    result      TEXT,
    error       TEXT,
    hot         BOOLEAN NOT NULL DEFAULT TRUE,
    depth       INTEGER NOT NULL DEFAULT 0,
    claim_token TEXT,
    last_heartbeat_at TIMESTAMPTZ,
    started_at  TIMESTAMPTZ,
    finished_at TIMESTAMPTZ,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_en_task  ON exploration_nodes(task_id);
CREATE INDEX IF NOT EXISTS idx_en_state ON exploration_nodes(task_id, state);
CREATE INDEX IF NOT EXISTS idx_en_hot   ON exploration_nodes(task_id, hot);

CREATE TABLE IF NOT EXISTS exploration_facts (
    id          BIGSERIAL PRIMARY KEY,
    task_id     TEXT NOT NULL,
    node_id     TEXT,
    subject     TEXT NOT NULL,
    predicate   TEXT NOT NULL,
    object      TEXT NOT NULL,
    source      TEXT NOT NULL DEFAULT '',
    confidence  REAL NOT NULL DEFAULT 1.0,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_ef_task ON exploration_facts(task_id);
CREATE INDEX IF NOT EXISTS idx_ef_subj ON exploration_facts(task_id, subject);
"""

INTENT_CLAIM_TTL = 90.0  # seconds
HEARTBEAT_INTERVAL = 15.0  # seconds


@dataclass
class ExplorationNode:
    id: str
    task_id: str
    parent_id: str | None
    intent: str
    state: str
    agent_key: str
    worker_id: str | None
    result: str | None
    error: str | None
    hot: bool
    depth: int
    created_at: float
    updated_at: float


@dataclass
class ExplorationFact:
    id: int
    task_id: str
    node_id: str | None
    subject: str
    predicate: str
    object: str
    source: str
    confidence: float
    created_at: float


class ExplorationStore:
    """PostgreSQL-backed exploration graph store."""

    def __init__(self, pool: Any):
        self._pool = pool

    async def create_node(
        self,
        task_id: str,
        intent: str,
        parent_id: str | None = None,
        agent_key: str = "worker",
        depth: int = 0,
    ) -> ExplorationNode:
        id_ = str(uuid.uuid4())
        async with self._pool.acquire() as conn:
            row = await conn.fetchrow(
                """INSERT INTO exploration_nodes(id, task_id, parent_id, intent, agent_key, depth)
                   VALUES($1,$2,$3,$4,$5,$6)
                   RETURNING id,task_id,parent_id,intent,state,agent_key,
                             worker_id,result,error,hot,depth,created_at,updated_at""",
                id_, task_id, parent_id, intent, agent_key, depth,
            )
            return _row_to_node(row)

    async def get_node(self, id_: str) -> ExplorationNode | None:
        async with self._pool.acquire() as conn:
            row = await conn.fetchrow(
                """SELECT id,task_id,parent_id,intent,state,agent_key,
                          worker_id,result,error,hot,depth,created_at,updated_at
                   FROM exploration_nodes WHERE id=$1""",
                id_,
            )
            return _row_to_node(row) if row else None

    async def list_nodes(
        self,
        task_id: str,
        state: str | None = None,
        hot_only: bool = False,
        limit: int = 100,
    ) -> list[ExplorationNode]:
        where = ["task_id=$1"]
        args: list[Any] = [task_id]
        i = 2
        if state:
            where.append(f"state=${i}"); args.append(state); i += 1
        if hot_only:
            where.append("hot=TRUE")
        args.append(limit)
        async with self._pool.acquire() as conn:
            rows = await conn.fetch(
                f"""SELECT id,task_id,parent_id,intent,state,agent_key,
                           worker_id,result,error,hot,depth,created_at,updated_at
                    FROM exploration_nodes
                    WHERE {' AND '.join(where)}
                    ORDER BY created_at ASC LIMIT ${i}""",
                *args,
            )
            return [_row_to_node(r) for r in rows]

    async def update_state(
        self,
        id_: str,
        state: str,
        result: str | None = None,
        error: str | None = None,
    ) -> bool:
        sets = ["state=$2", "updated_at=now()"]
        args: list[Any] = [id_, state]
        i = 3
        if result is not None:
            sets.append(f"result=${i}"); args.append(result); i += 1
        if error is not None:
            sets.append(f"error=${i}"); args.append(error); i += 1
        if state in ("done", "failed", "exhausted"):
            sets.append("finished_at=now()")
        elif state == "running":
            sets.append("started_at=now()")
        async with self._pool.acquire() as conn:
            res = await conn.execute(
                f"UPDATE exploration_nodes SET {', '.join(sets)} WHERE id=$1", *args
            )
            return res.split()[-1] == "1"

    async def mark_cold(self, task_id: str, node_ids: list[str]) -> int:
        if not node_ids:
            return 0
        async with self._pool.acquire() as conn:
            res = await conn.execute(
                "UPDATE exploration_nodes SET hot=FALSE, updated_at=now()"
                f" WHERE task_id=$1 AND id=ANY($2)",
                task_id, node_ids,
            )
            return int(res.split()[-1])

    async def add_fact(
        self,
        task_id: str,
        subject: str,
        predicate: str,
        object_: str,
        source: str = "",
        confidence: float = 1.0,
        node_id: str | None = None,
    ) -> ExplorationFact:
        async with self._pool.acquire() as conn:
            row = await conn.fetchrow(
                """INSERT INTO exploration_facts
                   (task_id, node_id, subject, predicate, object, source, confidence)
                   VALUES($1,$2,$3,$4,$5,$6,$7)
                   RETURNING id,task_id,node_id,subject,predicate,object,source,confidence,created_at""",
                task_id, node_id, subject, predicate, _utf8(object_), source, confidence,
            )
            return _row_to_fact(row)

    async def list_facts(
        self,
        task_id: str,
        subject: str | None = None,
        limit: int = 500,
    ) -> list[ExplorationFact]:
        where = ["task_id=$1"]
        args: list[Any] = [task_id]
        i = 2
        if subject:
            where.append(f"subject=${i}"); args.append(subject); i += 1
        args.append(limit)
        async with self._pool.acquire() as conn:
            rows = await conn.fetch(
                f"""SELECT id,task_id,node_id,subject,predicate,object,source,confidence,created_at
                    FROM exploration_facts
                    WHERE {' AND '.join(where)}
                    ORDER BY created_at ASC LIMIT ${i}""",
                *args,
            )
            return [_row_to_fact(r) for r in rows]

    async def task_progress(self, task_id: str) -> dict:
        """Return counts by state for a task."""
        async with self._pool.acquire() as conn:
            rows = await conn.fetch(
                "SELECT state, COUNT(*) FROM exploration_nodes WHERE task_id=$1 GROUP BY state",
                task_id,
            )
            counts = {r[0]: r[1] for r in rows}
            total = sum(counts.values())
            return {"total": total, "by_state": counts, "task_id": task_id}


def _row_to_node(row: Any) -> ExplorationNode:
    return ExplorationNode(
        id=row["id"], task_id=row["task_id"],
        parent_id=row["parent_id"],
        intent=row["intent"], state=row["state"],
        agent_key=row["agent_key"], worker_id=row["worker_id"],
        result=row["result"], error=row["error"],
        hot=row["hot"], depth=row["depth"],
        created_at=row["created_at"].timestamp(),
        updated_at=row["updated_at"].timestamp(),
    )


def _row_to_fact(row: Any) -> ExplorationFact:
    return ExplorationFact(
        id=row["id"], task_id=row["task_id"],
        node_id=row["node_id"],
        subject=row["subject"], predicate=row["predicate"],
        object=row["object"], source=row["source"],
        confidence=float(row["confidence"]),
        created_at=row["created_at"].timestamp(),
    )


def _utf8(s: str) -> str:
    return s.encode("utf-8", errors="replace").decode("utf-8").replace("\x00", "")
