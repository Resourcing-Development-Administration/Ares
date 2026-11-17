"""
LogSink — tees the backend log into an in-memory ring buffer and fans new
lines to SSE subscribers. Port of ARTEX server/logsink.go.
"""
from __future__ import annotations

import asyncio
import logging
import re
import time
from collections import deque
from dataclasses import dataclass


@dataclass
class LogLine:
    seq: int
    ts: str
    level: str    # "info" | "warn" | "error"
    tag: str      # leading [tag] token if present
    text: str


_TAG_RE = re.compile(r"^\[([^\]]{1,32})\]\s*")

RING_CAP = 3000


class LogSink(logging.Handler):
    """
    Python logging.Handler that:
    - Keeps up to RING_CAP lines in memory.
    - Fans each new line to async subscribers (asyncio.Queue).
    """

    def __init__(self, cap: int = RING_CAP):
        super().__init__()
        self._cap = cap
        self._ring: deque[LogLine] = deque(maxlen=cap)
        self._seq = 0
        self._subs: set[asyncio.Queue] = set()
        self._loop: asyncio.AbstractEventLoop | None = None

    def emit(self, record: logging.LogRecord) -> None:
        try:
            msg = self.format(record)
            level = record.levelname.lower()
            if level not in ("info", "warn", "warning", "error"):
                level = "info"
            if level == "warning":
                level = "warn"

            tag = ""
            m = _TAG_RE.match(msg)
            if m:
                tag = m.group(1)
                text = msg[m.end():]
            else:
                text = msg

            self._seq += 1
            ll = LogLine(
                seq=self._seq,
                ts=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                level=level,
                tag=tag,
                text=text,
            )
            self._ring.append(ll)
            self._fan_out(ll)
        except Exception:
            pass

    def _fan_out(self, ll: LogLine) -> None:
        if not self._subs:
            return
        loop = self._loop
        if loop is None or not loop.is_running():
            return
        dead = set()
        for q in list(self._subs):
            try:
                q.put_nowait(ll)
            except asyncio.QueueFull:
                pass
            except Exception:
                dead.add(q)
        self._subs -= dead

    def set_loop(self, loop: asyncio.AbstractEventLoop) -> None:
        self._loop = loop

    def subscribe(self) -> asyncio.Queue:
        q: asyncio.Queue = asyncio.Queue(maxsize=500)
        self._subs.add(q)
        return q

    def unsubscribe(self, q: asyncio.Queue) -> None:
        self._subs.discard(q)

    def tail(self, limit: int = 200, since_seq: int = 0) -> list[LogLine]:
        """Return up to `limit` lines with seq > since_seq."""
        out = [ll for ll in self._ring if ll.seq > since_seq]
        return out[-limit:]

    def all_lines(self) -> list[LogLine]:
        return list(self._ring)


# Module-level singleton
_sink: LogSink | None = None


def init(cap: int = RING_CAP, loop: asyncio.AbstractEventLoop | None = None) -> LogSink:
    global _sink
    _sink = LogSink(cap=cap)
    if loop:
        _sink.set_loop(loop)
    root = logging.getLogger()
    root.addHandler(_sink)
    return _sink


def get() -> LogSink | None:
    return _sink
