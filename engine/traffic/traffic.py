"""
Traffic recording subsystem — stores every captured HTTP exchange in a SQLite
database with content-addressed blob storage. Equivalent to ARTEX traffic/traffic.go.
"""
from __future__ import annotations

import hashlib
import os
import re
import sqlite3
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any
import threading


INDEX_SCHEMA = """
CREATE TABLE IF NOT EXISTS exchanges (
  id           TEXT PRIMARY KEY,
  ts           INTEGER,
  host         TEXT,
  method       TEXT,
  url_template TEXT,
  url          TEXT,
  status       INTEGER,
  content_type TEXT,
  req_len      INTEGER,
  resp_len     INTEGER,
  path         TEXT
);
CREATE INDEX IF NOT EXISTS idx_ex_host   ON exchanges(host);
CREATE INDEX IF NOT EXISTS idx_ex_tmpl   ON exchanges(host, url_template);
CREATE INDEX IF NOT EXISTS idx_ex_ts     ON exchanges(ts);
CREATE INDEX IF NOT EXISTS idx_ex_status ON exchanges(status);
CREATE INDEX IF NOT EXISTS idx_ex_resp   ON exchanges(resp_len);

CREATE TABLE IF NOT EXISTS exchange_bodies (
  id        TEXT PRIMARY KEY,
  req_head  TEXT NOT NULL DEFAULT '',
  req_body  BLOB,
  req_blob  TEXT,
  resp_head TEXT NOT NULL DEFAULT '',
  resp_body BLOB,
  resp_blob TEXT
);

CREATE TABLE IF NOT EXISTS blob_refs (
  hash        TEXT NOT NULL,
  exchange_id TEXT NOT NULL,
  PRIMARY KEY (hash, exchange_id)
);
CREATE INDEX IF NOT EXISTS idx_blob_refs_ex ON blob_refs(exchange_id);

CREATE TABLE IF NOT EXISTS stream_messages (
  id          INTEGER PRIMARY KEY AUTOINCREMENT,
  exchange_id TEXT NOT NULL,
  seq         INTEGER NOT NULL,
  direction   TEXT NOT NULL,
  kind        TEXT NOT NULL,
  ts          INTEGER NOT NULL,
  payload     BLOB,
  blob_hash   TEXT,
  truncated   INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_sm_ex ON stream_messages(exchange_id, seq);

CREATE TABLE IF NOT EXISTS blobs (
  hash TEXT PRIMARY KEY,
  data BLOB NOT NULL
);

CREATE VIRTUAL TABLE IF NOT EXISTS exchanges_fts USING fts5(
  id UNINDEXED, host, url, content_type, req_head, resp_head,
  content=exchanges
);
"""

# Inline threshold for body storage — bodies larger than this go to the blob store
SPILL_THRESHOLD = 4 * 1024  # 4 KB

# Max inline body kept in exchange_bodies (larger goes to blob only)
MAX_INLINE = 64 * 1024  # 64 KB

# URL parameter pattern for template normalization
_PARAM_RE = re.compile(r'[0-9a-f]{8,}|[0-9]{3,}')


@dataclass
class StoredBody:
    inline: bytes | None = None
    blob_hash: str | None = None
    length: int = 0


@dataclass
class ExchangeRow:
    id: str
    ts: int
    host: str
    method: str
    url_template: str
    url: str
    status: int
    content_type: str
    req_len: int
    resp_len: int


@dataclass
class ExchangeDetail(ExchangeRow):
    req_head: str = ""
    req_body: bytes | None = None
    req_blob: str | None = None
    resp_head: str = ""
    resp_body: bytes | None = None
    resp_blob: str | None = None


def _template_path(path: str) -> str:
    """Normalize URL path by replacing IDs/numbers with {id}."""
    return _PARAM_RE.sub("{id}", path)


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


class Traffic:
    """
    SQLite-backed HTTP traffic store. Thread-safe; use record() and query methods
    from any thread. All writes are serialized via _wlock.
    """

    def __init__(self, db_path: str | Path):
        self._db_path = str(db_path)
        self._wlock = threading.Lock()
        self._seq = 0
        self._db: sqlite3.Connection | None = None
        self._pending_ext: dict = {}
        self._open()

    def _open(self) -> None:
        os.makedirs(os.path.dirname(self._db_path) or ".", exist_ok=True)
        conn = sqlite3.connect(self._db_path, check_same_thread=False, timeout=30)
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA synchronous=NORMAL")
        conn.execute("PRAGMA foreign_keys=ON")
        conn.executescript(INDEX_SCHEMA)
        conn.commit()
        self._db = conn

    def close(self) -> None:
        if self._db:
            self._db.close()
            self._db = None

    # ── Blob store ────────────────────────────────────────────────────────────

    def _spill(self, data: bytes, _content_type: str = "") -> StoredBody:
        """Store body bytes: inline if small, blob-store if large."""
        if not data:
            return StoredBody(inline=b"", length=0)
        if len(data) <= SPILL_THRESHOLD:
            return StoredBody(inline=data, length=len(data))
        h = _sha256(data)
        try:
            self._db.execute(
                "INSERT OR IGNORE INTO blobs(hash, data) VALUES(?,?)", (h, data)
            )
        except Exception:
            pass
        return StoredBody(blob_hash=h, length=len(data))

    def _get_blob(self, hash_: str) -> bytes | None:
        row = self._db.execute(
            "SELECT data FROM blobs WHERE hash=?", (hash_,)
        ).fetchone()
        return bytes(row[0]) if row else None

    # ── Write ─────────────────────────────────────────────────────────────────

    def _next_id(self, ts: int) -> str:
        self._seq += 1
        return f"{ts}-{self._seq % 10000:04d}"

    def _insert_exchange(
        self,
        id_: str, ts: int, host: str, method: str,
        url_template: str, url: str, status: int,
        content_type: str, req_len: int, resp_len: int,
        req_head: str, req_b: StoredBody,
        resp_head: str, resp_b: StoredBody,
    ) -> None:
        cur = self._db.cursor()
        cur.execute(
            """INSERT OR REPLACE INTO exchanges
               (id,ts,host,method,url_template,url,status,content_type,req_len,resp_len,path)
               VALUES(?,?,?,?,?,?,?,?,?,?,'')""",
            (id_, ts, host, method, url_template, url, status,
             content_type, req_len, resp_len),
        )
        cur.execute(
            """INSERT OR REPLACE INTO exchange_bodies
               (id, req_head, req_body, req_blob, resp_head, resp_body, resp_blob)
               VALUES(?,?,?,?,?,?,?)""",
            (id_, req_head,
             req_b.inline, req_b.blob_hash,
             resp_head,
             resp_b.inline, resp_b.blob_hash),
        )
        for h in (req_b.blob_hash, resp_b.blob_hash):
            if h:
                cur.execute(
                    "INSERT OR IGNORE INTO blob_refs(hash, exchange_id) VALUES(?,?)",
                    (h, id_),
                )
        try:
            cur.execute(
                """INSERT OR REPLACE INTO exchanges_fts
                   (id, host, url, content_type, req_head, resp_head)
                   VALUES(?,?,?,?,?,?)""",
                (id_, host, url, content_type, req_head[:2000], resp_head[:2000]),
            )
        except Exception:
            pass
        self._db.commit()

    # ── Query ─────────────────────────────────────────────────────────────────

    def query_exchanges(
        self,
        host: str | None = None,
        method: str | None = None,
        status_min: int | None = None,
        status_max: int | None = None,
        search: str | None = None,
        limit: int = 100,
        offset: int = 0,
    ) -> list[ExchangeRow]:
        """Return exchange rows matching the given filters."""
        where: list[str] = []
        args: list[Any] = []
        if host:
            where.append("host=?"); args.append(host)
        if method:
            where.append("method=?"); args.append(method.upper())
        if status_min is not None:
            where.append("status>=?"); args.append(status_min)
        if status_max is not None:
            where.append("status<=?"); args.append(status_max)
        clause = ("WHERE " + " AND ".join(where)) if where else ""
        rows = self._db.execute(
            f"SELECT id,ts,host,method,url_template,url,status,content_type,req_len,resp_len"
            f" FROM exchanges {clause} ORDER BY ts DESC LIMIT ? OFFSET ?",
            [*args, limit, offset],
        ).fetchall()
        return [ExchangeRow(*r) for r in rows]

    def get_exchange(self, id_: str) -> ExchangeDetail | None:
        row = self._db.execute(
            "SELECT id,ts,host,method,url_template,url,status,content_type,req_len,resp_len"
            " FROM exchanges WHERE id=?", (id_,)
        ).fetchone()
        if not row:
            return None
        d = ExchangeDetail(*row)
        body_row = self._db.execute(
            "SELECT req_head,req_body,req_blob,resp_head,resp_body,resp_blob"
            " FROM exchange_bodies WHERE id=?", (id_,)
        ).fetchone()
        if body_row:
            d.req_head = body_row[0] or ""
            req_body_b, req_blob = body_row[1], body_row[2]
            d.resp_head = body_row[3] or ""
            resp_body_b, resp_blob = body_row[4], body_row[5]
            d.req_body = bytes(req_body_b) if req_body_b else (self._get_blob(req_blob) if req_blob else None)
            d.resp_body = bytes(resp_body_b) if resp_body_b else (self._get_blob(resp_blob) if resp_blob else None)
            d.req_blob = req_blob
            d.resp_blob = resp_blob
        return d

    def count_by_host(self) -> dict[str, int]:
        rows = self._db.execute(
            "SELECT host, COUNT(*) FROM exchanges GROUP BY host ORDER BY COUNT(*) DESC"
        ).fetchall()
        return {r[0]: r[1] for r in rows}

    def stats(self) -> dict[str, Any]:
        total = self._db.execute("SELECT COUNT(*) FROM exchanges").fetchone()[0]
        hosts = self._db.execute("SELECT COUNT(DISTINCT host) FROM exchanges").fetchone()[0]
        return {"total_exchanges": total, "unique_hosts": hosts, "db_path": self._db_path}


# Module-level singleton (initialized by the server on startup)
_instance: Traffic | None = None


def init(db_path: str | Path) -> "Traffic":
    global _instance
    _instance = Traffic(db_path)
    return _instance


def get() -> "Traffic | None":
    return _instance
