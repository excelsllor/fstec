#!/usr/bin/env bash
# Резервная копия PostgreSQL + файлового volume. Запускать на хосте с docker compose.
set -euo pipefail

OUT_DIR="${OUT_DIR:-$PWD/backups}"
PG_CONTAINER="${PG_CONTAINER:-fstec-postgres}"
DATA_VOLUME="${DATA_VOLUME:-services_data}"
STAMP="$(date +%Y%m%d_%H%M%S)"
mkdir -p "$OUT_DIR"

echo "[1/2] PostgreSQL"
docker exec "$PG_CONTAINER" sh -lc 'pg_dump -U "$POSTGRES_USER" "$POSTGRES_DB"' \
  | gzip > "$OUT_DIR/postgres_${STAMP}.sql.gz"

echo "[2/2] Files ($DATA_VOLUME)"
docker run --rm -v "${DATA_VOLUME}:/data:ro" -v "$OUT_DIR:/backup" alpine \
  tar czf "/backup/data_${STAMP}.tgz" -C / data

echo "OK: $OUT_DIR/postgres_${STAMP}.sql.gz, $OUT_DIR/data_${STAMP}.tgz"
