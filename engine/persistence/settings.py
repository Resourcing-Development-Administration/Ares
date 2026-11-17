"""
DB-backed settings store — PostgreSQL key-value store for runtime config.
Port of ARTEX db/settings.go.
"""
from __future__ import annotations

import base64
import hashlib
import os
from typing import Any

SETTINGS_DDL = """
CREATE TABLE IF NOT EXISTS settings (
    key        TEXT PRIMARY KEY,
    value      TEXT NOT NULL DEFAULT '',
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
"""

# Settings that are stored encrypted
_SECRET_KEYS = frozenset([
    "auth.password_hash",
    "llm.api_key",
    "notify.slack_token",
    "notify.pagerduty_key",
    "smtp.password",
])


def _is_secret(key: str) -> bool:
    return key in _SECRET_KEYS or key.endswith(".secret") or key.endswith(".key")


def _derive_key() -> bytes:
    """Derive an encryption key from a machine-specific secret."""
    machine_id = ""
    for path in ("/etc/machine-id", "/var/lib/dbus/machine-id"):
        try:
            machine_id = open(path).read().strip()
            break
        except OSError:
            pass
    seed = (machine_id or "ares-default-seed-" + os.environ.get("HOSTNAME", ""))
    return hashlib.sha256(seed.encode()).digest()


def _seal(value: str) -> str:
    """XOR-based lightweight encryption for secret settings."""
    key = _derive_key()
    data = value.encode("utf-8")
    out = bytes(b ^ key[i % len(key)] for i, b in enumerate(data))
    return base64.b64encode(out).decode()


def _open(ciphertext: str) -> str:
    key = _derive_key()
    data = base64.b64decode(ciphertext)
    out = bytes(b ^ key[i % len(key)] for i, b in enumerate(data))
    return out.decode("utf-8")


class SettingsStore:
    """PostgreSQL-backed key-value settings store."""

    def __init__(self, pool: Any):
        self._pool = pool

    async def get(self, key: str) -> tuple[str, bool]:
        """Return (value, found). Decrypts secret keys automatically."""
        async with self._pool.acquire() as conn:
            row = await conn.fetchrow(
                "SELECT value FROM settings WHERE key=$1", key
            )
            if not row:
                return "", False
            value = row["value"]
            if _is_secret(key):
                try:
                    value = _open(value)
                except Exception:
                    return "", False
            return value, True

    async def set(self, key: str, value: str) -> None:
        stored = _seal(value) if _is_secret(key) else value
        async with self._pool.acquire() as conn:
            await conn.execute(
                """INSERT INTO settings(key, value)
                   VALUES($1, $2)
                   ON CONFLICT (key) DO UPDATE
                   SET value=EXCLUDED.value, updated_at=now()""",
                key, stored,
            )

    async def insert_if_absent(self, key: str, value: str) -> bool:
        """Write only when the key does not exist. Returns True if inserted."""
        stored = _seal(value) if _is_secret(key) else value
        async with self._pool.acquire() as conn:
            result = await conn.execute(
                """INSERT INTO settings(key, value)
                   VALUES($1, $2)
                   ON CONFLICT (key) DO NOTHING""",
                key, stored,
            )
            return result.split()[-1] == "1"

    async def get_bool(self, key: str, default: bool = False) -> bool:
        value, found = await self.get(key)
        if not found:
            return default
        return value.lower() in ("true", "1", "yes")

    async def set_bool(self, key: str, value: bool) -> None:
        await self.set(key, "true" if value else "false")

    async def get_int(self, key: str, default: int = 0) -> int:
        value, found = await self.get(key)
        if not found:
            return default
        try:
            return int(value)
        except ValueError:
            return default

    async def set_int(self, key: str, value: int) -> None:
        await self.set(key, str(value))

    async def list_all(self, prefix: str = "") -> dict[str, str]:
        """Return all non-secret settings with optional key prefix."""
        async with self._pool.acquire() as conn:
            rows = await conn.fetch(
                "SELECT key, value FROM settings WHERE key LIKE $1 ORDER BY key",
                f"{prefix}%",
            )
            return {
                r["key"]: r["value"]
                for r in rows
                if not _is_secret(r["key"])
            }

    async def delete(self, key: str) -> bool:
        async with self._pool.acquire() as conn:
            result = await conn.execute(
                "DELETE FROM settings WHERE key=$1", key
            )
            return result.split()[-1] == "1"
