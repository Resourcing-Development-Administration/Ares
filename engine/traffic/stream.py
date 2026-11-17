"""
WebSocket/SSE stream message recording and query.
Equivalent to ARTEX traffic/stream.go.
"""
from __future__ import annotations

import asyncio
import json
import time
from typing import Any

from .traffic import Traffic, _sha256

STREAM_PREVIEW = 4 * 1024    # bytes kept inline; larger payloads go to blob
TOOL_STREAM_PREVIEW = 1024    # max preview in tool responses


def record_stream_message(
    t: Traffic,
    exchange_id: str,
    seq: int,
    direction: str,
    kind: str,
    payload: bytes,
) -> None:
    """Record one WebSocket message or SSE event for an exchange."""
    if t is None or not exchange_id:
        return
    ts = int(time.time())
    blob_hash = None
    inline = payload

    if len(payload) > STREAM_PREVIEW:
        blob_hash = _sha256(payload)
        inline = payload[:STREAM_PREVIEW]
        with t._wlock:
            t._db.execute(
                "INSERT OR IGNORE INTO blobs(hash, data) VALUES(?,?)",
                (blob_hash, payload),
            )
            t._db.execute(
                "INSERT OR IGNORE INTO blob_refs(hash, exchange_id) VALUES(?,?)",
                (blob_hash, exchange_id),
            )

    with t._wlock:
        t._db.execute(
            """INSERT INTO stream_messages
               (exchange_id, seq, direction, kind, ts, payload, blob_hash, truncated)
               VALUES(?,?,?,?,?,?,?,?)""",
            (exchange_id, seq, direction, kind, ts, inline,
             blob_hash, int(blob_hash is not None)),
        )
        t._db.commit()


def get_stream_messages(
    t: Traffic,
    exchange_id: str,
    limit: int = 200,
    offset: int = 0,
) -> list[dict]:
    """Return stream messages for an exchange, with preview payloads."""
    if t is None:
        return []
    rows = t._db.execute(
        """SELECT id, exchange_id, seq, direction, kind, ts,
                  SUBSTR(payload, 1, ?), blob_hash, truncated
           FROM stream_messages
           WHERE exchange_id=?
           ORDER BY seq ASC LIMIT ? OFFSET ?""",
        (TOOL_STREAM_PREVIEW, exchange_id, limit, offset),
    ).fetchall()
    result = []
    for r in rows:
        payload_bytes = bytes(r[6]) if r[6] else b""
        try:
            payload_text = payload_bytes.decode("utf-8", errors="replace")
        except Exception:
            payload_text = payload_bytes.hex()
        result.append({
            "id": r[0],
            "exchange_id": r[1],
            "seq": r[2],
            "direction": r[3],
            "kind": r[4],
            "ts": r[5],
            "payload_preview": payload_text,
            "blob_hash": r[7],
            "truncated": bool(r[8]),
        })
    return result


async def stream_traffic_ws(
    t: Traffic,
    websocket: Any,
    host_filter: str | None = None,
    poll_interval: float = 0.5,
) -> None:
    """
    Stream new traffic exchanges to a WebSocket client in real time.
    Polls every poll_interval seconds and pushes new rows as JSON.
    """
    if t is None:
        return
    last_ts = int(time.time())
    while True:
        try:
            where = "ts > ?"
            args: list[Any] = [last_ts]
            if host_filter:
                where += " AND host=?"
                args.append(host_filter)
            rows = t._db.execute(
                f"SELECT id,ts,host,method,url,status,content_type,req_len,resp_len"
                f" FROM exchanges WHERE {where} ORDER BY ts ASC LIMIT 50",
                args,
            ).fetchall()
            for row in rows:
                last_ts = max(last_ts, row[1])
                await websocket.send_text(json.dumps({
                    "type": "traffic",
                    "id": row[0], "ts": row[1], "host": row[2],
                    "method": row[3], "url": row[4], "status": row[5],
                    "content_type": row[6], "req_len": row[7], "resp_len": row[8],
                }))
        except Exception:
            break
        await asyncio.sleep(poll_interval)
