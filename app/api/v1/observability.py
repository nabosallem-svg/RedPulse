"""RedPulse - Observability & Health Endpoints.

Provides:
  GET /health/detailed   - overall system health (DB, Redis, Celery, queues)
  GET /health/queue      - queue depths and worker heartbeats
  POST /health/workers/heartbeat  - worker heartbeat (for Celery workers to report)
  GET /health/workers    - list worker health from DB
"""
from __future__ import annotations

from typing import Optional

from fastapi import APIRouter, Depends, Request
from pydantic import BaseModel, Field
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_db
from app.services.observability_service import ObservabilityService

router = APIRouter(tags=["observability"])


class HeartbeatRequest(BaseModel):
    worker_name: str = Field(..., max_length=255)
    queue: str = Field("default", max_length=100)
    status: str = Field("healthy", pattern="^(healthy|degraded|down|crashed)$")
    jobs_processed: Optional[int] = None
    jobs_failed: Optional[int] = None
    metadata: Optional[dict] = None


@router.get("/health/detailed")
async def detailed_health(
    db: AsyncSession = Depends(get_db),
):
    """Detailed system health - no auth required for load balancers (but rate-limited)."""
    health = await ObservabilityService.get_system_health(db)
    # HTTP 200 even if degraded, but 503 if down? For simplicity return 200 with status field
    # Load balancer can check health['overall'] == 'healthy'
    return health


@router.get("/health/queue")
async def queue_health(
    db: AsyncSession = Depends(get_db),
):
    """Queue-specific health - depths, worker heartbeats, alerts."""
    redis_health = await ObservabilityService.check_redis()
    worker_db = await ObservabilityService.get_worker_health_db(db)
    celery = await ObservabilityService.check_celery_workers()
    # Derive alerts
    depths = redis_health.get("queues", {})
    stale_workers = [w for w in worker_db if w["status"] in ("degraded", "down", "crashed")]
    return {
        "queues": depths,
        "queue_health": redis_health.get("status"),
        "celery": celery,
        "workers_db": worker_db,
        "alerts": [
            f"Worker {w['worker_name']} is {w['status']} (stale {w['stale_seconds']}s)"
            for w in stale_workers
        ],
        "timestamp": redis_health.get("timestamp"),
    }


@router.get("/health/workers")
async def list_workers(
    db: AsyncSession = Depends(get_db),
):
    """List worker health from DB heartbeat table."""
    workers = await ObservabilityService.get_worker_health_db(db)
    return {"success": True, "data": workers, "count": len(workers)}


@router.post("/health/workers/heartbeat")
async def worker_heartbeat(
    data: HeartbeatRequest,
    db: AsyncSession = Depends(get_db),
):
    """Upsert worker heartbeat - workers call this every 30s."""
    worker = await ObservabilityService.heartbeat(
        db,
        worker_name=data.worker_name,
        queue=data.queue,
        status=data.status,
        jobs_processed=data.jobs_processed,
        jobs_failed=data.jobs_failed,
        metadata=data.metadata,
    )
    return {
        "success": True,
        "data": {
            "worker_name": worker.worker_name,
            "status": worker.status,
            "last_heartbeat": worker.last_heartbeat.isoformat() if worker.last_heartbeat else None,
        },
    }
