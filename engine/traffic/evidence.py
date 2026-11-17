"""
Traffic evidence access — exposes full request/response bodies for findings.
Equivalent to ARTEX traffic/evidence.go.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Callable

from .traffic import Traffic


@dataclass
class EvidenceExchange:
    id: str
    url: str
    method: str
    content_type: str
    ts: int
    status: int
    req_head: str
    resp_head: str
    req_len: int
    resp_len: int
    req_body: bytes | None
    resp_body: bytes | None


def read_evidence(
    t: Traffic,
    ids: list[str],
    consume: Callable[[EvidenceExchange], None],
) -> list[str]:
    """
    Read full bodies for the given exchange IDs and call consume() for each.
    Returns list of IDs that were not found.
    Thread-safe: holds the write lock during reads so bodies and index rows
    come from one consistent snapshot.
    """
    if t is None:
        raise RuntimeError("traffic store unavailable")

    missing: list[str] = []

    with t._wlock:
        for id_ in ids:
            row = t._db.execute(
                "SELECT ts,url,method,status,content_type,req_len,resp_len"
                " FROM exchanges WHERE id=?", (id_,)
            ).fetchone()
            if not row:
                missing.append(id_)
                continue

            ts, url, method, status, content_type, req_len, resp_len = row
            body_row = t._db.execute(
                "SELECT req_head, req_body, req_blob, resp_head, resp_body, resp_blob"
                " FROM exchange_bodies WHERE id=?", (id_,)
            ).fetchone()

            req_head = resp_head = ""
            req_body = resp_body = None

            if body_row:
                req_head = body_row[0] or ""
                resp_head = body_row[3] or ""
                if body_row[1]:
                    req_body = bytes(body_row[1])
                elif body_row[2]:
                    req_body = t._get_blob(body_row[2])
                if body_row[4]:
                    resp_body = bytes(body_row[4])
                elif body_row[5]:
                    resp_body = t._get_blob(body_row[5])

            consume(EvidenceExchange(
                id=id_, url=url, method=method, content_type=content_type,
                ts=ts, status=status,
                req_head=req_head, resp_head=resp_head,
                req_len=req_len, resp_len=resp_len,
                req_body=req_body, resp_body=resp_body,
            ))

    return missing
