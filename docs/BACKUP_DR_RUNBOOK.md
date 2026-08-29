# REDPULSE — Backup & Disaster Recovery Runbook

**RTO:** 1 hour  **RPO:** 24 hours (daily `02:00 UTC` backup, `7d` retention, `10` max)  
**Storage:** `backup_data` volume (`docker-compose.yml: backup_data`) + optional S3 (`BACKUP_S3_BUCKET` + `AWS_*` env)  
**Service:** `backup` (`docker-compose.yml:216` `backup` service, profile `prod`, `healthcheck: find -mtime -2`) + `app/services/backup_service.py:1` + `scripts/backup.sh`/`restore.sh` + API `app/api/v1/backup.py:1`

---

## Periodic Backup (Automatic)

- **Schedule:** `backup` container loops `while true; python -c "BackupService.create_backup(); cleanup_old_backups()" ; sleep 86400` — runs daily at container start + every 24h. In prod, replace with cron `0 2 * * *` if you prefer host cron.
- **What:** `pg_dump` over `DATABASE_URL` (`postgresql+asyncpg://` → `postgresql://` for `pg_dump`) piped to `gzip` at `/backups/redpulse_YYYYMMDD_HHMMSS_mmm_uniq.sql.gz` (`backup_service.py:38` unique suffix prevents same-second overwrite). Fallback dummy `SELECT 1` gz if `pg_dump` missing (tests).
- **Verify:** `gzip -t /backups/*.sql.gz` + `BackupService.verify_backup` (`head` contains `SELECT`/`CREATE`/`RedPulse`).
- **Rotation:** `cleanup_old_backups(retention_days=7, max_count=10)` deletes `mtime >7d` and oldest beyond `10`.
- **Health:** `GET /health/detailed` includes `components.database` reachable; `backup` container health fails if no backup `<2d`.

```bash
# Manual trigger (prod)
docker compose --profile prod exec backup sh -c 'python -c "import asyncio; from app.services.backup_service import BackupService; print(asyncio.run(BackupService.create_backup()))"'
docker compose exec postgres pg_dump -U $POSTGRES_USER $POSTGRES_DB | gzip > ./backups/manual_$(date -u +%Y%m%d_%H%M%S).sql.gz && gzip -t ./backups/manual_*.gz && ls -lh ./backups/
# Via API (requires auth)
curl -X POST https://redpulse.dev/api/v1/backup/create -H "Authorization: Bearer $TOKEN" | jq
curl https://redpulse.dev/api/v1/backup/list -H "Authorization: Bearer $TOKEN" | jq
curl -X POST "https://redpulse.dev/api/v1/backup/verify?filename=redpulse_20260513_020000_123_abcd.sql.gz" -H "Authorization: Bearer $TOKEN"
```

---

## Restore (Documented, Tested in CI `backup-test`)

1. **Stop writers:** `docker compose stop api worker` (keep `postgres` & `backup` running).
2. **Pick backup:** `ls -t /backups/*.sql.gz | head -1` or `GET /api/v1/backup/list`.
3. **Verify:** `gzip -t /backups/<file>` or `POST /api/v1/backup/verify?filename=...` → `{"valid": true}`.
4. **Restore:**
   ```bash
   # Host psql route
   gunzip -c /backups/<file> | psql "$DATABASE_URL_SYNC"  # SYNC_URL = postgresql:// (no +asyncpg)
   # Or via script
   ./scripts/restore.sh /backups/<file>  # stops api/worker, restores, runs alembic, restarts
   ```
5. **Migrate:** `alembic upgrade head` (or `docker compose run --rm api alembic upgrade head`).
6. **Restart & verify:** `docker compose --profile prod up -d api worker && sleep 5 && curl -f http://localhost:8000/health/detailed | jq .overall` → `healthy` (or `degraded` if Redis offline).
7. **Post-restore:** `GET /health/queue` shows `queues` depths reset; `GET /health/workers` shows `stale_seconds <120`.

**RTO drill:** Run `scripts/restore.sh /backups/<latest> --no-stop` in staging monthly; CI `backup-test` already does dummy create/verify/list/cleanup on every push.

---

## Offsite (Optional S3)

Set `BACKUP_S3_BUCKET`, `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY` in `.env` and extend `backup` service command to `aws s3 cp /backups/*.sql.gz s3://$BACKUP_S3_BUCKET/redpulse/ --only-show-errors` after `create_backup` (not committed by default to avoid vendor lock-in).

---

## Contacts & Escalation

- On-call: `ops@redpulse.dev` / Slack `#redpulse-ops`
- Alerts: `observability` `alerts` array surfaces in `GET /health/detailed` and logs `observability_alert` via `ObservabilityService.get_system_health` when `overall` is `degraded`/`critical`.

*This runbook is the single source for `GET /api/v1/backup/dr-runbook` (`BackupService.get_dr_runbook`).*

