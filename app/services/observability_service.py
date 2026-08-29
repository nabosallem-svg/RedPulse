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


class ObservabilityService:
    """Checks health of queues, workers, DB, and reports status."""

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
        """Aggregate system health for /health/detailed."""
        db_health = await ObservabilityService.check_db(db)
        redis_health = await ObservabilityService.check_redis()
        celery_health = await ObservabilityService.check_celery_workers()
        worker_db_health = await ObservabilityService.get_worker_health_db(db)

        # Overall status: worst of components
        statuses = [db_health.get("status"), redis_health.get("status"), celery_health.get("status")]
        # Map to severity: down/critical > degraded > healthy
        if "down" in statuses or "critical" in statuses or "crashed" in statuses:
            overall = "critical" if "down" in statuses else "degraded"
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
        return {
            "overall": overall,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "components": {
                "database": db_health,
                "redis": redis_health,
                "celery": celery_health,
                "workers_db": {"count": len(worker_db_health), "crashed": len(crashed_workers), "details": worker_db_health},
            },
            "queues": {"health": queue_health, "depths": queue_depths},
            "alerts": [
                f"Worker {w['worker_name']} is {w['status']} (stale {w['stale_seconds']}s, failures {w['consecutive_failures']})"
                for w in worker_db_health if w["status"] in ("crashed", "down", "degraded")
            ] + (
                [f"Queue depth critical: {queue_depths}"] if queue_health == "critical" else
                ([f"Queue depth degraded: {queue_depths}"] if queue_health == "degraded" else [])
            ),
        }
