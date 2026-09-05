# RedPulse on Fly.io — production deploy runbook (API + Worker + Upstash Redis)

> Goal: real nuclei scans (45s+) as background jobs. Vercel keeps serving the
> Next.js frontend; Fly.io serves the FastAPI backend + Celery worker.
> Temp free domain at the end: `https://redpulse-api.fly.dev`.

## 0. Prereqs (one time)

```bash
# install flyctl + login (needs YOUR Fly.io account — card required, pay-per-second billing)
fly auth login
```

## 1. Redis (Upstash, free tier is enough for the job queue)

1. https://console.upstash.com → Create Database → name `redpulse-queue`, region `eu-west-2`, TLS enabled.
2. Copy the **Redis URL** (`rediss://default:XXXX@...:6379`). Celery accepts `rediss://`.
3. This ONE url serves as `REDIS_URL`, `CELERY_BROKER_URL`, `CELERY_RESULT_BACKEND`.

## 2. Launch the two apps (creates free *.fly.dev subdomains)

```bash
cd reconpilot
fly launch --no-deploy -c fly.api.toml       # app: redpulse-api
fly launch --no-deploy -c fly.worker.toml    # app: redpulse-worker
```

## 3. Secrets (never in git — Supabase pooler URL, NOT direct host)

```bash
# API app
fly secrets set -a redpulse-api \
  DATABASE_URL="postgresql+asyncpg://postgres.bleihgyanobwmpfupbgg:PASSWORD@aws-0-eu-west-2.pooler.supabase.com:6543/postgres" \
  REDIS_URL="rediss://..." \
  CELERY_BROKER_URL="rediss://..." \
  CELERY_RESULT_BACKEND="rediss://..." \
  JWT_SECRET="$(python -c 'import secrets;print(secrets.token_hex(32))')" \
  NEXT_PUBLIC_API_URL="https://redpulse-api.fly.dev"

# Worker app (same values + nuclei already in image via Dockerfile)
fly secrets set -a redpulse-worker \
  DATABASE_URL="postgresql+asyncpg://postgres.bleihgyanobwmpfupbgg:PASSWORD@aws-0-eu-west-2.pooler.supabase.com:6543/postgres" \
  REDIS_URL="rediss://..." \
  CELERY_BROKER_URL="rediss://..." \
  CELERY_RESULT_BACKEND="rediss://..." \
  JWT_SECRET="<same-as-api>"
```

Why pooler, not `db.*.supabase.co`: the direct host is IPv6-only and
Supabase pooler (transaction mode) is what serverless/long-lived workers
can actually reach. `app/db/session.py` already sets
`statement_cache_size=0` for exactly this.

## 4. Size machines + deploy

```bash
fly scale memory 512 -a redpulse-api
fly scale memory 1024 -a redpulse-worker   # nuclei needs 1GB+ for 12k templates
fly deploy -c fly.api.toml
fly deploy -c fly.worker.toml
fly scale count worker=1 -a redpulse-worker
```

## 5. Verify (real scan, timed)

```bash
curl https://redpulse-api.fly.dev/health
# signup -> create project/engagement -> authorize (~same E2E as before)
# POST /api/v1/projects/{id}/pentest/report  -> 202 {job_id} in <1s  (NOT 45s!)
# GET  /api/v1/projects/{id}/pentest/jobs/{job_id} (poll) -> completed in ~45-60s, findings: 0, synthetic: 0
fly logs -a redpulse-worker   # watch: nuclei_start ... nuclei_end elapsed=48s
```

Then point the frontend at it: Vercel → `redpulse-frontend` →
`NEXT_PUBLIC_API_URL=https://redpulse-api.fly.dev` → Redeploy.

## Cost reality check (2026, pay-per-second, lhr)

| Piece | Size | ~Cost |
|---|---|---|
| redpulse-api (always-on, warm UX) | shared 512MB | ~$4/mo |
| redpulse-worker (always-on, queue must be watched) | shared 1GB | ~$8/mo |
| Postgres | Supabase (existing) | $0 |
| Redis queue | Upstash free tier | $0 |
| `redpulse-api.fly.dev` subdomain + custom domain later | — | $0 |
| **Total** | | **~$12/mo** |

Worker MUST stay on (min 1): a scale-to-zero worker never wakes for queue
depth — Fly can't autostart on Redis backlog. That is the single biggest
cost driver and it is unavoidable on any platform for real background scans.
