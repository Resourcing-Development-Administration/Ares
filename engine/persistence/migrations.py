"""
Migraciones de DB versionadas con verificación de checksum SHA-256.

Cada migración es un archivo .sql en engine/persistence/sql/ nombrado
NNN_descripcion.sql (NNN = número de versión con cero-padding).

Invariante de integridad: una vez que una migración fue aplicada, su
checksum se guarda en ares_schema_migrations. Si el archivo .sql cambia
después de aplicado, MigrationManager.migrate() falla con MigrationError
(la migración ya no es confiable). Nunca edites una migración ya aplicada:
creá una nueva.
"""
from __future__ import annotations
import hashlib
import os
import re
from pathlib import Path
from typing import Any

_SQL_DIR = Path(__file__).parent / "sql"

_CREATE_MIGRATIONS_TABLE = """
CREATE TABLE IF NOT EXISTS ares_schema_migrations (
    version     INTEGER PRIMARY KEY,
    name        TEXT NOT NULL,
    checksum    TEXT NOT NULL,
    applied_at  TIMESTAMPTZ DEFAULT NOW()
);
"""


class MigrationError(Exception):
    pass


def _sha256(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()


def _list_migration_files() -> list[tuple[int, str, Path]]:
    """Devuelve [(version, name, path)] ordenado por versión."""
    result = []
    for path in sorted(_SQL_DIR.glob("*.sql")):
        m = re.match(r"^(\d+)_(.+)\.sql$", path.name)
        if not m:
            continue
        version = int(m.group(1))
        name = m.group(2)
        result.append((version, name, path))
    return sorted(result)


class MigrationManager:
    """Gestiona migraciones SQL versionadas contra una conexión asyncpg.

    Uso:
        mm = MigrationManager(conn_or_pool)
        await mm.migrate()           # aplica todas las pendientes
        status = await mm.status()   # lista de {version, name, applied, checksum_ok}
    """

    def __init__(self, pool: Any) -> None:
        self._pool = pool

    async def migrate(self) -> list[int]:
        """Aplica todas las migraciones pendientes. Devuelve versiones aplicadas."""
        async with self._pool.acquire() as conn:
            await conn.execute(_CREATE_MIGRATIONS_TABLE)
            applied = await self._applied_versions(conn)
            applied_new = []
            for version, name, path in _list_migration_files():
                sql_text = path.read_text(encoding="utf-8")
                checksum = _sha256(sql_text)
                if version in applied:
                    # verificar integridad del checksum
                    stored = applied[version]["checksum"]
                    if stored != checksum:
                        raise MigrationError(
                            f"Migration {version:03d}_{name}.sql fue modificada después "
                            f"de aplicarse (checksum esperado {stored[:8]}…, "
                            f"actual {checksum[:8]}…). Creá una nueva migración."
                        )
                    continue
                # aplicar migración en transacción
                async with conn.transaction():
                    await conn.execute(sql_text)
                    await conn.execute(
                        "INSERT INTO ares_schema_migrations (version, name, checksum) "
                        "VALUES ($1, $2, $3)",
                        version, name, checksum,
                    )
                applied_new.append(version)
        return applied_new

    async def status(self) -> list[dict]:
        """Estado de cada migración: {version, name, applied, checksum_ok}."""
        async with self._pool.acquire() as conn:
            await conn.execute(_CREATE_MIGRATIONS_TABLE)
            applied = await self._applied_versions(conn)

        result = []
        for version, name, path in _list_migration_files():
            sql_text = path.read_text(encoding="utf-8")
            checksum = _sha256(sql_text)
            if version in applied:
                stored = applied[version]["checksum"]
                result.append({
                    "version": version,
                    "name": name,
                    "applied": True,
                    "checksum_ok": stored == checksum,
                    "applied_at": str(applied[version].get("applied_at", "")),
                })
            else:
                result.append({
                    "version": version,
                    "name": name,
                    "applied": False,
                    "checksum_ok": None,
                    "applied_at": None,
                })
        return result

    async def _applied_versions(self, conn: Any) -> dict[int, dict]:
        rows = await conn.fetch(
            "SELECT version, name, checksum, applied_at FROM ares_schema_migrations"
        )
        return {r["version"]: dict(r) for r in rows}
