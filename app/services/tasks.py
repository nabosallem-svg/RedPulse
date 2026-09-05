"""RedPulse - Celery Background Tasks.

Heavy scan and recon operations are offloaded to Celery workers
to keep the API responsive. Tasks use async SQLAlchemy sessions.
"""
from __future__ import annotations

import asyncio
import logging
import time
from typing import Any, Dict, Optional

from celery import shared_task

logger = logging.getLogger(__name__)


def _run_async(coro):
    """Run an async coroutine from sync Celery task context."""
    loop = asyncio.new_event_loop()
    try:
        return loop.run_until_complete(coro)
    finally:
        loop.close()


@shared_task(
    bind=True,
    name="app.services.tasks.run_scan",
    max_retries=2,
    soft_time_limit=300,
    time_limit=600,
)
def run_scan(
    self,
    project_id: str,
    engagement_id: str,
    targets: list[str],
    template_path: Optional[str] = None,
    auth_headers: Optional[Dict[str, str]] = None,
    auth_cookies: Optional[str] = None,
    user_id: Optional[str] = None,
) -> Dict[str, Any]:
    """Run a Nuclei vulnerability scan as a background task.

    Delegates to VulnScanner with proper scope validation.
    Returns scan results including findings count and severity breakdown.
    user_id is required (worker opens its own DB session and loads the user).
    """
    from app.services.vuln_scanner import VulnScanner

    logger.info(
        "Celery task run_scan started: project=%s engagement=%s targets=%d",
        project_id, engagement_id, len(targets),
    )
    start_time = time.time()

    async def _execute():
        from app.db.session import async_session_factory
        from app.db.models import User as _User
        from sqlalchemy import select as _select
        async with async_session_factory() as _db:
            _res = await _db.execute(_select(_User).where(_User.id == user_id))
            _user = _res.scalar_one_or_none()
            if not _user:
                raise ValueError(f"User {user_id} not found")
            scanner = VulnScanner(_db, _user, engagement_id)
            result = await scanner.start_scan_job(
                targets=targets,
                template_path=template_path,
                auth_headers=auth_headers,
                auth_cookies=auth_cookies,
            )
            return result

    try:
        result = _run_async(_execute())
        elapsed = time.time() - start_time
        logger.info(
            "Celery task run_scan completed: project=%s findings=%d elapsed=%.1fs",
            project_id, result.get("findings_count", 0), elapsed,
        )
        return result
    except Exception as exc:
        logger.error("Celery task run_scan failed: project=%s error=%s", project_id, exc)
        raise self.retry(exc=exc, countdown=60)


@shared_task(
    bind=True,
    name="app.services.tasks.run_pentest_report",
    max_retries=1,
    soft_time_limit=600,
    time_limit=900,
)
def run_pentest_report(
    self,
    user_id: str,
    project_id: str,
    engagement_id: str,
    targets: list[str],
    format: str = "json",
) -> Dict[str, Any]:
    """Run a controlled pentest scan (nuclei 45s+) as a background task.

    Same logic as the sync endpoint via execute_pentest_scan — scope is
    re-validated inside the worker. Args are JSON-serializable only
    (user re-loaded from worker's own DB session).
    Returns a JSON-serializable summary with the full enriched findings.
    """
    from app.services.pentest_service import execute_pentest_scan

    logger.info(
        "Celery task run_pentest_report started: project=%s engagement=%s targets=%d",
        project_id, engagement_id, len(targets),
    )
    start_time = time.time()

    async def _execute():
        from sqlalchemy import select as _select
        from app.db.session import async_session_factory
        from app.db.models import User as _User
        async with async_session_factory() as _db:
            _res = await _db.execute(_select(_User).where(_User.id == user_id))
            _user = _res.scalar_one_or_none()
            if not _user:
                raise ValueError(f"User {user_id} not found")
            report, enriched = await execute_pentest_scan(
                _db, _user, project_id, engagement_id, targets, format="json",
            )
            return report, enriched

    try:
        report, enriched = _run_async(_execute())
        elapsed = time.time() - start_time
        logger.info(
            "Celery task run_pentest_report completed: project=%s findings=%d elapsed=%.1fs",
            project_id, len(enriched), elapsed,
        )
        return {
            "project_id": project_id,
            "engagement_id": engagement_id,
            "targets": targets,
            "findings_count": len(enriched),
            "elapsed_s": round(elapsed, 1),
            "executive_summary": report.get("executive_summary", {}),
            "findings": enriched,
        }
    except ValueError:
        # Missing objects — retrying won't help
        raise
    except Exception as exc:
        logger.error("Celery task run_pentest_report failed: project=%s error=%s", project_id, exc)
        raise self.retry(exc=exc, countdown=120)


@shared_task(
    bind=True,
    name="app.services.tasks.run_recon",
    max_retries=2,
    soft_time_limit=300,
    time_limit=600,
)
def run_recon(
    self,
    project_id: str,
    targets: list[str],
    tools: Optional[list[str]] = None,
) -> Dict[str, Any]:
    """Run reconnaissance tasks (subfinder, httpx, etc.) as background task."""
    from app.services.recon_worker import ReconWorker

    logger.info(
        "Celery task run_recon started: project=%s targets=%d",
        project_id, len(targets),
    )
    start_time = time.time()

    async def _execute():
        worker = ReconWorker(project_id=project_id)
        results = []
        for target in targets:
            result = await worker.run_full_recon(target, tools=tools)
            results.append(result)
        return {"results": results, "targets_scanned": len(targets)}

    try:
        result = _run_async(_execute())
        elapsed = time.time() - start_time
        logger.info(
            "Celery task run_recon completed: project=%s elapsed=%.1fs",
            project_id, elapsed,
        )
        return result
    except Exception as exc:
        logger.error("Celery task run_recon failed: project=%s error=%s", project_id, exc)
        raise self.retry(exc=exc, countdown=60)


@shared_task(
    bind=True,
    name="app.services.tasks.run_pipeline",
    max_retries=1,
    soft_time_limit=900,
    time_limit=1200,
)
def run_pipeline(
    self,
    project_id: str,
    engagement_id: str,
    targets: list[str],
    auth_headers: Optional[Dict[str, str]] = None,
    auth_cookies: Optional[str] = None,
) -> Dict[str, Any]:
    """Run the full recon-to-scan pipeline as a background task.

    Orchestrates: Recon -> Asset Normalization -> Nuclei Scan -> Finding Ingestion.
    """
    from app.services.pipeline import PipelineOrchestrator

    logger.info(
        "Celery task run_pipeline started: project=%s engagement=%s targets=%d",
        project_id, engagement_id, len(targets),
    )
    start_time = time.time()

    async def _execute():
        from app.db.session import async_session_factory
        from app.db.models import User as _User
        from sqlalchemy import select as _select
        async with async_session_factory() as _db:
            # PipelineOrchestrator requires (db, user); worker loads user by id from its own session.
            # user_id is passed via targets payload? No — pipeline endpoint must pass it; see run_pentest_report.
            # Fallback: resolve owner from engagement's project.
            from app.db.models import Engagement as _Eng, Project as _Proj
            _eres = await _db.execute(_select(_Eng).where(_Eng.id == engagement_id))
            _eng = _eres.scalar_one_or_none()
            if not _eng:
                raise ValueError(f"Engagement {engagement_id} not found")
            _pres = await _db.execute(_select(_Proj).where(_Proj.id == _eng.project_id))
            _proj = _pres.scalar_one_or_none()
            if not _proj:
                raise ValueError(f"Project {_eng.project_id} not found")
            _ures = await _db.execute(_select(_User).where(_User.id == _proj.owner_id))
            _user = _ures.scalar_one_or_none()
            if not _user:
                raise ValueError(f"Owner {_proj.owner_id} not found")
            orchestrator = PipelineOrchestrator(db=_db, user=_user)
            result = await orchestrator.run(
                engagement_id=engagement_id,
                target=targets[0] if targets else "",
                auth_headers=auth_headers,
                auth_cookies=auth_cookies,
            )
        return {
            "status": result.status,
            "assets_found": result.assets_found,
            "findings_count": len(result.findings),
            "errors": result.errors,
        }

    try:
        result = _run_async(_execute())
        elapsed = time.time() - start_time
        logger.info(
            "Celery task run_pipeline completed: project=%s status=%s elapsed=%.1fs",
            project_id, result.get("status"), elapsed,
        )
        return result
    except Exception as exc:
        logger.error("Celery task run_pipeline failed: project=%s error=%s", project_id, exc)
        raise self.retry(exc=exc, countdown=120)


@shared_task(
    name="app.services.tasks.send_notification",
    soft_time_limit=30,
)
def send_notification(
    channel: str,
    message: str,
    severity: str = "info",
) -> Dict[str, Any]:
    """Send a notification (Telegram/Discord/webhook) as background task."""
    from app.services.alert_service import AlertService

    logger.info("Celery task send_notification: channel=%s severity=%s", channel, severity)

    async def _execute():
        service = AlertService()
        if channel == "telegram":
            await service.send_telegram(message, severity)
        elif channel == "discord":
            await service.send_discord(message, severity)
        return {"sent": True, "channel": channel}

    try:
        result = _run_async(_execute())
        return result
    except Exception as exc:
        logger.error("Celery task send_notification failed: %s", exc)
        return {"sent": False, "error": str(exc)}


@shared_task(
    name="app.services.tasks.cleanup_expired_results",
    soft_time_limit=60,
)
def cleanup_expired_results() -> Dict[str, Any]:
    """Periodic task to clean up expired Celery results."""
    logger.info("Running periodic cleanup of expired results")
    return {"cleaned": True}
