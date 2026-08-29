# REDPULSE — Observability Runbook (Queue, Workers, Failure Rate, Latency)

**Endpoints:** `GET /health` (liveness), `GET /health/detailed` (full), `GET /health/queue` (queues+workers), `GET /health/workers` + `POST /health/workers/heartbeat` (`app/api/v1/observability.py:1`), `X-Response-Time-ms` header (`app/main.py:110` metrics middleware)  
**Service:** `app/services/observability_service.py:1` — thresholds, `record_api_request`, `get_api_metrics`, `check_alerts` + auto `logger.warning` on `degraded`/`critical`

---

## What is Monitored

| Signal | Source | Healthy | Degraded | Critical / Down | Where |
|--------|--------|---------|----------|-----------------|-------|
| **DB** | `SELECT now()` latency | `reachable && latency <500ms` | `latency >500ms` | `unreachable` → `down` | `GET /health/detailed` `components.database` |
| **Redis queues** | `LLEN default/scans/celery` via `redis.asyncio` | `<100` | `100-500` | `>500` | `queues.depths`, `queues.health` |
| **Celery workers (live)** | `celery_app.control.inspect().stats()/active()` | `count>=1` | `0` (degraded) | ` inspect error` | `components.celery` |
| **Workers (DB heartbeat)** | `WorkerHealth` table `last_heartbeat`, `consecutive_failures` | `stale<120s && failures<3` | `stale 120-600s` | `stale>600s` or `failures>=3` → `crashed/down` | `workers_db.details[]` |
| **API latency** | `metrics_middleware` `_API_METRICS["latencies"]` last 1000, p95 | `p95 <500ms` | `500-1000ms` | `>1000ms` | `components.api.latency_ms.p95`, `api.latency_ms` |
| **Failure rate** | `failures/requests` where `status>=500` | `<5%` | `5-15%` | `>15%` | `api.failure_rate`, `api.by_status` |

*All thresholds are constants at top of `observability_service.py:16` for tuning.*

---

## Queue Health

```bash
curl -f http://localhost:8000/health/queue | jq
# {
#   "queues": {"default": 12, "scans": 85, "celery": 0},
#   "queue_health": "healthy|degraded|critical",
#   "celery": {"status": "healthy", "count": 2, "workers": [...]},
#   "workers_db": [{"worker_name":"celery@worker-1","stale_seconds":12.3,"status":"healthy", ...}],
#   "alerts": []
# }
```

- **Depth** is Redis `LLEN`. In `docker-compose.yml` `redis` is `7-alpine` with `maxmemory 256mb` (prod `512mb` in `docker-compose.prod.yml`). If `queue_health: critical`, scale `worker` replicas (`WORKER_REPLICAS=2` in `docker-compose.yml:153`, `4` in prod) or drain `beat`.
- **Stale workers:** `heartbeat` is `POST /health/workers/heartbeat` from each Celery worker every 30s (`ObservabilityService.heartbeat`). If `stale_seconds >120` → `degraded`, `>600` → `down`, `consecutive_failures>=3` → `crashed`. The `worker` container should call this on start and every `CELERY_WORKER_HIJACK` (add to `celery_app` worker init).

---

## Workers: Active Count, Crash Detection

```bash
curl http://localhost:8000/health/workers | jq
# {"success":true,"data":[{"worker_name":"celery@worker-1","status":"healthy","stale_seconds":8.1,"jobs_processed":42,"jobs_failed":1, ...}], "count":1}
```

- **Active count:** `celery.inspect().stats()` live + `WorkerHealth` persisted. If `workers_db.crashed >0` or `celery.count==0`, `overall: degraded`.
- **Crash alert:** `Worker X is crashed (stale 650s, failures 3)` appears in `GET /health/detailed` `alerts` and is `logger.warning`'d (`observability_service.py: alert`). Wire this log to your alert sink (e.g., Upstash, Datadog, or `app/services/alert_service.py` webhook `X-RedPulse-Signature`).

---

## API Latency & Failure Rate

Every request passes `metrics_middleware` (`app/main.py:113`) which does:

```python
start = time.time()
response = await call_next(request)
latency_ms = (time.time()-start)*1000
ObservabilityService.record_api_request(latency_ms, response.status_code)
response.headers["X-Response-Time-ms"] = str(round(latency_ms,1))
```

- **Latency:** `GET /health/detailed` → `api.latency_ms {avg,p50,p95,p99,min,max}` and `components.api.latency_ms`. `X-Response-Time-ms` also on every response for client-side tracing.
- **Failure rate:** `api.by_status` counts per status, `api.failure_rate = failures/requests` where failures are `5xx`.
- **Alert:** If `p95>1000ms` or `failure_rate>15%` → `health: critical` and alert string `API latency critical: p95 ...` is appended to `alerts` and `logger.warning("observability_alert ...")`. For `500-1000ms` or `5-15%` → `degraded`.

**Reset window:** In-memory ring of last `1000` latencies; `last_reset` timestamp in `api.window_seconds`. Call `ObservabilityService.reset_api_metrics()` from a cron or after deploy if you want a fresh window (or wait for natural roll-over). For cross-process sharing, back with Redis `INCR` + `LPUSH` (not yet — single-process `memory://` fallback).

---

## Auto-Alert When Degraded

`get_system_health` already does:

```python
if alerts and overall in ("degraded","critical","down"):
    logger.warning("observability_alert overall=%s alerts=%s api=%s", overall, alerts, api_metrics)
```

- **In prod:** Ship these `WARNING` logs to your sink: `docker-compose.yml` `logging: json-file` ships to `docker logs` → FluentBit → Slack `#redpulse-ops` (or Telegram via `alert_service.py`).
- **To add webhook alert:** In `get_system_health` after the `logger.warning`, call `await AlertService().send_custom(webhook_url, {"overall": overall, "alerts": alerts})` (same HMAC as `custom_webhooks`).

**Tune thresholds** by editing constants at `app/services/observability_service.py:16` and redeploying (no DB migration needed).

---

## Quick Checks

```bash
curl -f http://localhost:8000/health && curl -s http://localhost:8000/health/detailed | jq .overall, .alerts
curl -s http://localhost:8000/health/queue | jq .queue_health, .queues
curl -s http://localhost:8000/health/workers | jq
# Simulate load / failure to see alert flip:
# for i in $(seq 1 50); do curl -s http://localhost:8000/api/v1/auth/me >/dev/null; done  # 401s are not 5xx, so need a 500 path for failure_rate demo
```

*All three health endpoints are unauthenticated (for load-balancer probes) but rate-limited via SlowAPI `memory://` fallback.*

