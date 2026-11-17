"""
Intent claim leases — prevents duplicate concurrent agent runs on the same intent.

Port of ARTEX intent claim fencing (S3c).
A claim has a 15s heartbeat interval and a 90s TTL.
A stale worker's claim expires so a new worker can take over.
"""
from __future__ import annotations

import asyncio
import secrets
import time
from dataclasses import dataclass, field


TTL: float = 90.0
HEARTBEAT_INTERVAL: float = 15.0


@dataclass
class _Claim:
    owner_token: str
    acquired_at: float = field(default_factory=time.monotonic)
    last_heartbeat: float = field(default_factory=time.monotonic)


def new_owner_token() -> str:
    return secrets.token_hex(16)


class ClaimStore:
    """In-memory, asyncio-safe claim store for intent IDs."""

    def __init__(self) -> None:
        self._claims: dict[str, _Claim] = {}
        self._lock = asyncio.Lock()
        self._cleanup_task: asyncio.Task | None = None

    def _ensure_cleanup(self) -> None:
        if self._cleanup_task is None or self._cleanup_task.done():
            try:
                loop = asyncio.get_running_loop()
                self._cleanup_task = loop.create_task(self._cleanup_loop())
            except RuntimeError:
                pass

    async def _cleanup_loop(self) -> None:
        while True:
            await asyncio.sleep(TTL / 2)
            async with self._lock:
                now = time.monotonic()
                stale = [
                    k for k, c in self._claims.items()
                    if (now - c.last_heartbeat) > TTL
                ]
                for k in stale:
                    del self._claims[k]

    async def claim(self, intent_id: str, owner_token: str) -> bool:
        """Acquire claim. Returns True if acquired, False if held by another owner."""
        self._ensure_cleanup()
        async with self._lock:
            existing = self._claims.get(intent_id)
            if existing is not None:
                now = time.monotonic()
                if (now - existing.last_heartbeat) <= TTL:
                    return existing.owner_token == owner_token
                # stale — evict
                del self._claims[intent_id]
            self._claims[intent_id] = _Claim(owner_token=owner_token)
            return True

    async def heartbeat(self, intent_id: str, owner_token: str) -> bool:
        """Renew claim TTL. Returns False if expired or wrong token."""
        async with self._lock:
            c = self._claims.get(intent_id)
            if c is None:
                return False
            if c.owner_token != owner_token:
                return False
            now = time.monotonic()
            if (now - c.last_heartbeat) > TTL:
                del self._claims[intent_id]
                return False
            c.last_heartbeat = now
            return True

    async def release(self, intent_id: str, owner_token: str) -> bool:
        """Release claim. Returns False if not held by this owner."""
        async with self._lock:
            c = self._claims.get(intent_id)
            if c is None or c.owner_token != owner_token:
                return False
            del self._claims[intent_id]
            return True

    def is_stale(self, intent_id: str) -> bool:
        """Synchronous check — True if no heartbeat in >TTL seconds."""
        c = self._claims.get(intent_id)
        if c is None:
            return True
        return (time.monotonic() - c.last_heartbeat) > TTL

    async def run_with_heartbeat(
        self,
        intent_id: str,
        owner_token: str,
        coro,
    ):
        """Run coro while maintaining heartbeat for the claim."""
        async def _hb():
            while True:
                await asyncio.sleep(HEARTBEAT_INTERVAL)
                if not await self.heartbeat(intent_id, owner_token):
                    return

        task = asyncio.create_task(_hb())
        try:
            return await coro
        finally:
            task.cancel()
            await self.release(intent_id, owner_token)


# global store — one per process
_global_store: ClaimStore | None = None


def get_store() -> ClaimStore:
    global _global_store
    if _global_store is None:
        _global_store = ClaimStore()
    return _global_store

# ARTEX-port: intent claim leases with heartbeat fencing for concurrent agents
