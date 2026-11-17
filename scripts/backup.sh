#!/usr/bin/env bash
# Ares backup: Postgres dump + data/ archive
set -euo pipefail

DEST="${ARES_BACKUP_DIR:-$HOME/.ares/backups}"
STAMP=$(date +%Y%m%d-%H%M%S)
mkdir -p "$DEST"

# Postgres dump
if [[ -n "${ARES_DATABASE_DSN:-}" ]]; then
  PG_DUMP="$DEST/ares-pg-$STAMP.dump"
  pg_dump --format=custom "$ARES_DATABASE_DSN" -f "$PG_DUMP"
  echo "postgres: $PG_DUMP"
else
  echo "ARES_DATABASE_DSN not set; skipping Postgres backup"
fi

# Data directory archive
DATA_DIR="${ARES_DATA_DIR:-data}"
if [[ -d "$DATA_DIR" ]]; then
  TARBALL="$DEST/ares-data-$STAMP.tar.gz"
  tar -czf "$TARBALL" "$DATA_DIR"
  echo "data: $TARBALL"
else
  echo "data dir '$DATA_DIR' not found; skipping"
fi

echo "backup complete: $DEST"
