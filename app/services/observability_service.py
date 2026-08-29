"""RedPulse - System Observability: Queue Health, Worker Crashes, DB, Redis."""
from __future__ import annotations

import logging
import time
from datetime import datetime, timezone, timedelta
from typing import Dict, Any, List, Optional

from sqlalchemy import select, func
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.models import WorkerHealth

logger = logging.getLogger(__name__)

# Thresholds
HEARTBEAT_STALE_SECONDS = 120  # 2 minutes without heartbeat = degraded
CRASH_THRESHOLD_FAILURES = 3  # consecutive failures = crashed
QUEUE_DEPTH_WARN = 100
QUEUE_DEPTH_CRITICAL = 500
API_LATENCY_WARN_MS = 500  # p95 >500ms => degraded
API_LATENCY_CRITICAL_MS = 1000  # p95 >1000ms => critical
API_FAILURE_RATE_WARN = 0.05  # 5% 5xx => degraded
API_FAILURE_RATE_CRITICAL = 0.15  # 15% => critical

# In-memory API metrics (ring buffer, per-process)
_API_METRICS = {
    "requests": 0,
    "failures": 0,  # 5xx count
    "latencies": [],  # last N latencies in ms
    "by_status": {},  # status code -> count
    "last_reset": time.time(),
}
_MAX_LATENCIES = 1000


class ObservabilityService:
    """Checks health of queues, workers, DB, and reports status.

    Also tracks API latency / failure rate via record_api_request() called from middleware.
    """

    @staticmethod
    def record_api_request(latency_ms: float, status_code: int):
        """Record an API request for latency/failure metrics (called from middleware)."""
        _API_METRICS["requests"] += 1
        if status_code >= 500:
            _API_METRICS["failures"] += 1
        _API_METRICS["by_status"][str(status_code)] = _API_METRICS["by_status"].get(str(status_code), 0) + 1
        _API_METRICS["latencies"].append(latency_ms)
        if len(_API_METRICS["latencies"]) > _MAX_LATENCIES:
            _API_METRICS["latencies"] = _API_METRICS["latencies"][-_MAX_LATENCIES:]

    @staticmethod
    def get_api_metrics() -> Dict[str, Any]:
        """Return API latency and failure rate metrics."""
        reqs = _API_METRICS["requests"]
        fails = _API_METRICS["failures"]
        lats = _API_METRICS["latencies"]
        if lats:
            sorted_lats = sorted(lats)
            n = len(sorted_lats)
            avg = sum(lats) / n
            p50 = sorted_lats[int(n * 0.5)] if n > 0 else 0
            p95 = sorted_lats[int(n * 0.95)] if n > 0 else 0
            p99 = sorted_lats[int(n * 0.99)] if n > 0 else 0
            max_lat = max(lats)
            min_lat = min(lats)
        else:
            avg = p50 = p95 = p99 = max_lat = min_lat = 0
        failure_rate = (fails / reqs) if reqs > 0 else 0
        health = "healthy"
        if reqs > 20:  # need enough samples
            if p95 > API_LATENCY_CRITICAL_MS or failure_rate > API_FAILURE_RATE_CRITICAL:
                health = "critical"
            elif p95 > API_LATENCY_WARN_MS or failure_rate > API_FAILURE_RATE_WARN:
                health = "degraded"
        return {
            "requests": reqs,
            "failures": fails,
            "failure_rate": round(failure_rate, 4),
            "by_status": dict(_API_METRICS["by_status"]),
            "latency_ms": {
                "avg": round(avg, 1),
                "p50": round(p50, 1),
                "p95": round(p95, 1),
                "p99": round(p99, 1),
                "min": round(min_lat, 1),
                "max": round(max_lat, 1),
            },
            "health": health,
            "window_seconds": round(time.time() - _API_METRICS["last_reset"], 1),
        }

    @staticmethod
    def reset_api_metrics():
        _API_METRICS["requests"] = 0
        _API_METRICS["failures"] = 0
        _API_METRICS["latencies"] = []
        _API_METRICS["by_status"] = {}
        _API_METRICS["last_reset"] = time.time()

    @staticmethod
    def check_alerts(health_payload: Dict[str, Any]) -> List[str]:
        """Return list of alert strings if degradation detected (for auto-alert)."""
        alerts = list(health_payload.get("alerts", []))
        # API latency / failure alerts
        api_health = health_payload.get("components", {}).get("api", {}) or health_payload.get("api", {})
        if isinstance(api_health, dict) and api_health.get("health") in ("degraded", "critical"):
            alerts.append(f"API health {api_health['health']}: p95 {api_health.get('latency_ms', {}).get('p95')}ms, failure_rate {api_health.get('failure_rate')}")
        # Also check top-level api metrics if present
        if health_payload.get("api") and isinstance(health_payload["api"], dict):
            if health_payload["api"].get("health") == "critical":
                alerts.append(f"API latency critical: {health_payload['api']['latency_ms']['p95']}ms")
        return alerts

    @staticmethod
    async def check_db(db: AsyncSession) -> Dict[str, Any]:
        """Check DB connectivity with a simple query."""
        start = time.time()
        try:
            await db.execute(select(func.now()))
            latency_ms = round((time.time() - start) * 1000, 1)
            return {"status": "healthy", "latency_ms": latency_ms, "reachable": True}
        except Exception as e:
            logger.error("db_health_check_failed: %s", e)
            return {"status": "down", "error": str(e)[:500], "reachable": False}

    @staticmethod
    async def check_redis() -> Dict[str, Any]:
        """Check Redis connectivity and get queue depths."""
        try:
            from app.db.session import async_session_factory  # ensure import side-effect not needed
            import os
            import redis.asyncio as redis

            redis_url = os.environ.get("REDIS_URL", os.environ.get("CELERY_BROKER_URL", "redis://localhost:6379/1"))
            # For tests, redis may not be available - graceful fallback
            client = redis.from_url(redis_url, socket_connect_timeout=2, socket_timeout=2)
            start = time.time()
            pong = await client.ping()
            latency_ms = round((time.time() - start) * 1000, 1)
            # Queue depths (Celery queues are lists in Redis)
            queues = ["default", "scans", "celery"]
            depths = {}
            for q in queues:
                try:
                    length = await client.llen(q)
                    depths[q] = length
                except Exception:
                    depths[q] = None
            await client.aclose()
            status = "healthy"
            if any((v or 0) > QUEUE_DEPTH_CRITICAL for v in depths.values() if v is not None):
                status = "critical"
            elif any((v or 0) > QUEUE_DEPTH_WARN for v in depths.values() if v is not None):
                status = "degraded"
            return {"status": status, "reachable": True, "latency_ms": latency_ms, "pong": pong, "queues": depths}
        except Exception as e:
            logger.warning("redis_health_check_failed: %s", e)
            return {"status": "down", "reachable": False, "error": str(e)[:500], "queues": {}}

    @staticmethod
    async def check_celery_workers() -> Dict[str, Any]:
        """Inspect Celery workers via control (if broker available)."""
        try:
            from app.services.celery_app import celery_app

            inspect = celery_app.control.inspect(timeout=3)
            # Active workers
            stats = inspect.stats() or {}
            active = inspect.active() or {}
            # stats is dict worker_name -> info
            workers = []
            for worker_name, info in stats.items():
                workers.append({
                    "worker": worker_name,
                    "status": "healthy",
                    "pool": info.get("pool", {}),
                    "total_tasks": info.get("total", {}),
                    "active_tasks": len(active.get(worker_name, [])),
                })
            if not workers:
                # No workers registered - for tests or offline, report degraded not down
                return {"status": "degraded", "workers": [], "message": "No active Celery workers detected (offline or not running)", "count": 0}
            return {"status": "healthy", "workers": workers, "count": len(workers)}
        except Exception as e:
            logger.warning("celery_worker_check_failed: %s", e)
            return {"status": "degraded", "workers": [], "error": str(e)[:500], "count": 0}

    @staticmethod
    async def get_worker_health_db(db: AsyncSession) -> List[Dict[str, Any]]:
        """Get persisted worker health from DB (heartbeat table)."""
        result = await db.execute(select(WorkerHealth).order_by(WorkerHealth.last_heartbeat.desc()))
        rows = result.scalars().all()
        now = datetime.now(timezone.utc)
        out = []
        for w in rows:
            hb = w.last_heartbeat
            if hb.tzinfo is None:
                hb = hb.replace(tzinfo=timezone.utc)
            stale_seconds = (now - hb).total_seconds()
            derived_status = w.status
            if stale_seconds > HEARTBEAT_STALE_SECONDS and w.status == "healthy":
                derived_status = "degraded"
            if stale_seconds > HEARTBEAT_STALE_SECONDS * 5:
                derived_status = "down"
            if w.consecutive_failures >= CRASH_THRESHOLD_FAILURES:
                derived_status = "crashed"
            out.append({
                "worker_name": w.worker_name,
                "queue": w.queue,
                "status": derived_status,
                "stored_status": w.status,
                "last_heartbeat": hb.isoformat(),
                "stale_seconds": round(stale_seconds, 1),
                "jobs_processed": w.jobs_processed,
                "jobs_failed": w.jobs_failed,
                "consecutive_failures": w.consecutive_failures,
                "metadata": w.metadata_json,
            })
        return out

    @staticmethod
    async def heartbeat(
        db: AsyncSession,
        worker_name: str,
        queue: str = "default",
        status: str = "healthy",
        jobs_processed: Optional[int] = None,
        jobs_failed: Optional[int] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> WorkerHealth:
        """Upsert worker heartbeat - called by Celery workers periodically."""
        result = await db.execute(select(WorkerHealth).where(WorkerHealth.worker_name == worker_name))
        worker = result.scalar_one_or_none()
        now = datetime.now(timezone.utc)
        if worker:
            worker.last_heartbeat = now
            worker.status = status
            worker.queue = queue
            if jobs_processed is not None:
                worker.jobs_processed = jobs_processed
            if jobs_failed is not None:
                worker.jobs_failed = jobs_failed
                if jobs_failed > 0:
                    worker.consecutive_failures = (worker.consecutive_failures or 0) + 1
                else:
                    worker.consecutive_failures = 0
            if metadata is not None:
                worker.metadata_json = metadata
            worker.updated_at = now
        else:
            worker = WorkerHealth(
                worker_name=worker_name,
                queue=queue,
                status=status,
                last_heartbeat=now,
                jobs_processed=jobs_processed or 0,
                jobs_failed=jobs_failed or 0,
                metadata_json=metadata,
            )
            db.add(worker)
        await db.commit()
        await db.refresh(worker)
        return worker

    @staticmethod
    async def get_system_health(db: AsyncSession) -> Dict[str, Any]:
        """Aggregate system health for /health/detailed - includes API latency/failure rate."""
        db_health = await ObservabilityService.check_db(db)
        redis_health = await ObservabilityService.check_redis()
        celery_health = await ObservabilityService.check_celery_workers()
        worker_db_health = await ObservabilityService.get_worker_health_db(db)
        api_metrics = ObservabilityService.get_api_metrics()

        # Overall status: worst of components
        statuses = [db_health.get("status"), redis_health.get("status"), celery_health.get("status"), api_metrics.get("health")]
        # Map to severity: down/critical > degraded > healthy
        if "down" in statuses or "critical" in statuses or "crashed" in statuses:
            overall = "critical" if "down" in statuses or "critical" in statuses else "degraded"
            # If DB is down, overall is down
            if db_health.get("status") == "down":
                overall = "down"
        elif "degraded" in statuses:
            overall = "degraded"
        else:
            overall = "healthy"

        # Queue health summary
        queue_depths = redis_health.get("queues", {})
        queue_health = "healthy"
        if any((v or 0) > QUEUE_DEPTH_CRITICAL for v in queue_depths.values() if isinstance(v, int)):
            queue_health = "critical"
        elif any((v or 0) > QUEUE_DEPTH_WARN for v in queue_depths.values() if isinstance(v, int)):
            queue_health = "degraded"

        # Worker crash detection
        crashed_workers = [w for w in worker_db_health if w["status"] in ("crashed", "down")]
        alerts = [
            f"Worker {w['worker_name']} is {w['status']} (stale {w['stale_seconds']}s, failures {w['consecutive_failures']})"
            for w in worker_db_health if w["status"] in ("crashed", "down", "degraded")
        ] + (
            [f"Queue depth critical: {queue_depths}"] if queue_health == "critical" else
            ([f"Queue depth degraded: {queue_depths}"] if queue_health == "degraded" else [])
        )
        # API latency / failure alerts
        if api_metrics.get("health") == "critical":
            alerts.append(f"API latency critical: p95 {api_metrics['latency_ms']['p95']}ms, failure_rate {api_metrics['failure_rate']:.1%} ({api_metrics['failures']}/{api_metrics['requests']})")
        elif api_metrics.get("health") == "degraded":
            alerts.append(f"API latency degraded: p95 {api_metrics['latency_ms']['p95']}ms, failure_rate {api_metrics['failure_rate']:.1%}")

        # Auto-alert hook: if degraded/critical, log warning (could forward to webhook/Slack)
        if alerts and overall in ("degraded", "critical", "down"):
            logger.warning("observability_alert overall=%s alerts=%s api=%s", overall, alerts, api_metrics)

        return {
            "overall": overall,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "components": {
                "database": db_health,
                "redis": redis_health,
                "celery": celery_health,
                "workers_db": {"count": len(worker_db_health), "crashed": len(crashed_workers), "details": worker_db_health},
                "api": api_metrics,
            },
            "queues": {"health": queue_health, "depths": queue_depths},
            "api": api_metrics,
            "alerts": alerts,
            "alert_count": len(alerts),
        }
