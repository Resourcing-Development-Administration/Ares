"""
Session — agent conversation session persistence and resume.
Port of ARTEX agent/session.go.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any


class SessionStore:
    """
    Persists agent conversation history to a JSONL file so sessions can be
    resumed after restart. Missing file = fresh session (no error).
    """

    def __init__(self, base_dir: str):
        self._base = Path(base_dir)
        self._base.mkdir(parents=True, exist_ok=True)

    def _path(self, session_id: str) -> Path:
        safe = "".join(c for c in session_id if c.isalnum() or c in "-_.")
        if not safe:
            raise ValueError(f"invalid session id: {session_id!r}")
        return self._base / f"{safe}.jsonl"

    def load(self, session_id: str) -> list[dict]:
        p = self._path(session_id)
        if not p.exists():
            return []
        messages: list[dict] = []
        try:
            for line in p.read_text(encoding="utf-8").splitlines():
                line = line.strip()
                if line:
                    messages.append(json.loads(line))
        except (json.JSONDecodeError, OSError):
            return []
        return messages

    def append(self, session_id: str, message: dict[str, Any]) -> None:
        p = self._path(session_id)
        with p.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(message, ensure_ascii=False) + "\n")

    def delete(self, session_id: str) -> None:
        try:
            self._path(session_id).unlink(missing_ok=True)
        except OSError:
            pass

    def list_sessions(self) -> list[str]:
        return [p.stem for p in self._base.glob("*.jsonl")]


_store: SessionStore | None = None


def init(base_dir: str) -> SessionStore:
    global _store
    _store = SessionStore(base_dir)
    return _store


def get() -> SessionStore | None:
    return _store
