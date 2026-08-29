#!/bin/sh
# RedPulse - Disaster Recovery Restore Script
# Usage: ./scripts/restore.sh <backup_file.sql.gz> [--no-stop]
# Restores DB from gzip backup and runs migrations.
set -e

if [ -z "$1" ]; then
  echo "Usage: $0 <backup_file.sql.gz> [--no-stop]"
  echo "Available backups:"
  ls -lh ./backups/*.sql.gz 2>/dev/null || echo "  (none)"
  exit 1
fi

FILEPATH="$1"
if [ ! -f "$FILEPATH" ]; then
  echo "[restore] ERROR: File not found: $FILEPATH"
  exit 1
fi

DB_URL="${DATABASE_URL:-postgresql://RedPulse:${POSTGRES_PASSWORD}@postgres:5432/${POSTGRES_DB:-RedPulse}}"
SYNC_URL=$(echo "$DB_URL" | sed 's/postgresql+asyncpg:\/\//postgresql:\/\//')

echo "[restore] Verifying backup integrity..."
gzip -t "$FILEPATH" || { echo "[restore] gzip verify FAILED"; exit 1; }
echo "[restore] Verify OK"

if [ "$2" != "--no-stop" ]; then
  echo "[restore] Stopping api/worker (if running)..."
  docker compose stop api worker 2>/dev/null || echo "[restore] compose stop skipped (not running)"
fi

echo "[restore] Restoring to DB: $SYNC_URL (DB will be overwritten!)"
echo "[restore] Press Ctrl+C within 5s to cancel..."
sleep 5

if echo "$DB_URL" | grep -qi "postgres"; then
  if command -v psql >/dev/null 2>&1; then
    gunzip -c "$FILEPATH" | psql "$SYNC_URL"
  else
    echo "[restore] psql not found - cannot restore postgres dump (fallback: dummy restore skipped)"
  fi
else
  echo "[restore] SQLite restore: gunzip dump to test.db not implemented for postgres URL"
fi

echo "[restore] Running migrations..."
if command -v alembic >/dev/null 2>&1; then
  alembic upgrade head || echo "[restore] alembic upgrade head failed (check DB_URL)"
else
  echo "[restore] alembic not found - skip migrations"
fi

if [ "$2" != "--no-stop" ]; then
  echo "[restore] Restarting api/worker..."
  docker compose up -d api worker 2>/dev/null || echo "[restore] compose up skipped"
fi

echo "[restore] Verifying health..."
sleep 3
curl -f http://localhost:8000/health/detailed 2>/dev/null | head -c 500 && echo || echo "[restore] health check: curl failed (service may still be starting)"

echo "[restore] Done."
