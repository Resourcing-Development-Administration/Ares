"""
Traffic archive export — creates portable snapshots of captured exchanges.
Equivalent to ARTEX traffic/archive.go.
"""
from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

from .traffic import Traffic


@dataclass
class ArchiveExchange:
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
    req_head: str = ""
    req_body: bytes | None = None
    resp_head: str = ""
    resp_body: bytes | None = None


def export_hosts(t: Traffic, hosts: list[str], out_dir: str) -> int:
    """
    Export all exchanges matching the given hosts to out_dir.
    Writes a manifest.json and copies blobs to out_dir/blobs/.
    Returns the number of exchanges exported, 0 if t is None or hosts empty.
    """
    if t is None or not hosts:
        return 0

    out_path = Path(out_dir)
    (out_path / "blobs").mkdir(parents=True, exist_ok=True)

    host_set = set(h.lower() for h in hosts)

    with t._wlock:
        rows = t._db.execute(
            "SELECT id,ts,host,method,url_template,url,status,content_type,req_len,resp_len"
            " FROM exchanges WHERE lower(host) IN ({})".format(
                ",".join("?" * len(host_set))
            ),
            list(host_set),
        ).fetchall()

        exchanges: list[ArchiveExchange] = []
        blob_hashes: set[str] = set()

        for row in rows:
            ex = ArchiveExchange(*row)
            body_row = t._db.execute(
                "SELECT req_head, req_body, req_blob, resp_head, resp_body, resp_blob"
                " FROM exchange_bodies WHERE id=?",
                (ex.id,),
            ).fetchone()
            if body_row:
                ex.req_head = body_row[0] or ""
                ex.resp_head = body_row[3] or ""
                if body_row[1]:
                    ex.req_body = bytes(body_row[1])
                elif body_row[2]:
                    blob_hashes.add(body_row[2])
                if body_row[4]:
                    ex.resp_body = bytes(body_row[4])
                elif body_row[5]:
                    blob_hashes.add(body_row[5])
            exchanges.append(ex)

        for h in blob_hashes:
            blob_row = t._db.execute(
                "SELECT data FROM blobs WHERE hash=?", (h,)
            ).fetchone()
            if blob_row:
                (out_path / "blobs" / h).write_bytes(bytes(blob_row[0]))

    snapshot = {
        "version": 1,
        "exchanges": [
            {
                "id": ex.id, "ts": ex.ts, "host": ex.host,
                "method": ex.method, "url_template": ex.url_template,
                "url": ex.url, "status": ex.status,
                "content_type": ex.content_type,
                "req_len": ex.req_len, "resp_len": ex.resp_len,
                "req_head": ex.req_head,
                "req_body": ex.req_body.hex() if ex.req_body else None,
                "resp_head": ex.resp_head,
                "resp_body": ex.resp_body.hex() if ex.resp_body else None,
            }
            for ex in exchanges
        ],
        "blobs": list(blob_hashes),
    }
    (out_path / "manifest.json").write_text(json.dumps(snapshot, indent=2))
    return len(exchanges)
