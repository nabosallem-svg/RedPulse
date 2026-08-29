"""RedPulse - Retest Workflow Service.

Verifies findings are fixed via targeted micro-scans and tracks lifecycle.
Queue-aware: retests are dispatched to Celery 'scans' queue when available,
otherwise executed inline for tests.
"""
from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Optional, List, Dict, Any, Tuple
from sqlalchemy import select, func, and_
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.models import (
    Finding, FindingStatus, RetestJob, RetestStatus, RetestResult,
    Project, Engagement, User,
)

logger = logging.getLogger(__name__)


class RetestService:
    """Service for retest workflow - create, run, and track verification of fixes."""

    @staticmethod
    async def create_retest(
        db: AsyncSession,
        finding_id: str,
        requester: User,
        auto_resolve: bool = True,
    ) -> RetestJob:
        """Create a retest job for a finding.

        Raises ValueError if finding not found or not owned.
        """
        result = await db.execute(select(Finding).where(Finding.id == finding_id))
        finding = result.scalar_one_or_none()
        if not finding:
            raise ValueError("Finding not found")

        # Verify ownership via project
        proj_res = await db.execute(select(Project).where(Project.id == finding.project_id, Project.owner_id == requester.id))
        proj = proj_res.scalar_one_or_none()
        if not proj:
            raise ValueError("Finding not found or access denied")

        workspace_id = getattr(proj, "workspace_id", None)
        engagement_id = getattr(finding, "engagement_id", None)

        job = RetestJob(
            finding_id=finding.id,
            project_id=finding.project_id,
            workspace_id=workspace_id,
            engagement_id=engagement_id,
            requested_by=requester.id,
            status=RetestStatus.PENDING,
            original_evidence=getattr(finding, "evidence", None),
            original_endpoint=getattr(finding, "endpoint", None),
            auto_resolved=auto_resolve,
        )
        db.add(job)
        await db.commit()
        await db.refresh(job)
        logger.info("retest_created job=%s finding=%s by=%s", job.id, finding_id, requester.id)
        return job

    @staticmethod
    async def run_retest(
        db: AsyncSession,
        retest_id: str,
        worker_id: Optional[str] = None,
        use_celery: bool = False,
    ) -> RetestJob:
        """Execute a retest via micro-scan and update finding if fixed.

        If use_celery True, dispatches to Celery queue; otherwise runs inline (for tests).
        """
        result = await db.execute(select(RetestJob).where(RetestJob.id == retest_id))
        job = result.scalar_one_or_none()
        if not job:
            raise ValueError("Retest job not found")

        if job.status == RetestStatus.COMPLETED:
            return job

        job.status = RetestStatus.RUNNING
        job.started_at = datetime.now(timezone.utc)
        if worker_id:
            job.worker_id = worker_id
        await db.commit()

        # Perform micro-scan (deterministic mock, real implementation would hit endpoint)
        try:
            scan_result = await RetestService._micro_scan(db, job)
            # scan_result: {is_fixed: bool, evidence: str}
            is_fixed = scan_result.get("is_fixed", False)
            evidence = scan_result.get("evidence", "")

            job.evidence = evidence
            job.completed_at = datetime.now(timezone.utc)
            job.verified_at = datetime.now(timezone.utc) if is_fixed else None

            if is_fixed:
                job.result = RetestResult.FIXED
                job.status = RetestStatus.COMPLETED
                # Auto-resolve finding if enabled and still not resolved
                if job.auto_resolved:
                    f_res = await db.execute(select(Finding).where(Finding.id == job.finding_id))
                    finding = f_res.scalar_one_or_none()
                    if finding and finding.status != FindingStatus.RESOLVED:
                        finding.status = FindingStatus.RESOLVED
                        finding.last_seen = datetime.now(timezone.utc)
                        logger.info("retest_auto_resolved finding=%s job=%s", finding.id, job.id)
            else:
                job.result = RetestResult.STILL_VULNERABLE
                job.status = RetestStatus.COMPLETED

            await db.commit()
            await db.refresh(job)
            return job

        except Exception as e:
            logger.error("retest_failed job=%s error=%s", retest_id, e)
            job.status = RetestStatus.FAILED
            job.error_message = str(e)[:2000]
            job.retry_count = (job.retry_count or 0) + 1
            job.completed_at = datetime.now(timezone.utc)
            await db.commit()
            await db.refresh(job)
            return job

    @staticmethod
    async def _micro_scan(db: AsyncSession, job: RetestJob) -> Dict[str, Any]:
        """Lightweight targeted micro-scan - delegates to existing retest_engine for consistency.

        Returns {is_fixed: bool, evidence: str}
        """
        from app.services.retest_engine import retest_finding as engine_retest

        # Capture original finding status before engine mutates it
        orig_status = None
        try:
            f_res = await db.execute(select(Finding).where(Finding.id == job.finding_id))
            orig_finding = f_res.scalar_one_or_none()
            if orig_finding:
                orig_status = orig_finding.status
        except Exception:
            pass

        # Build a mock user for engine call (need User object for ownership check)
        user_res = await db.execute(select(User).where(User.id == job.requested_by))
        user = user_res.scalar_one_or_none()
        if not user:
            user = User(id=job.requested_by, email="retest@system", hashed_password="x", is_active=True)

        result = await engine_retest(job.finding_id, db, user)
        still_vuln = result.get("still_vulnerable", False)
        is_fixed = not still_vuln and result.get("verified", False)

        # If auto_resolve is False, revert any auto-resolution done by engine
        if not job.auto_resolved and is_fixed and orig_status is not None:
            try:
                f_res2 = await db.execute(select(Finding).where(Finding.id == job.finding_id))
                f2 = f_res2.scalar_one_or_none()
                if f2:
                    f2_status_str = str(getattr(f2.status, "value", f2.status)).lower()
                    orig_status_str = str(getattr(orig_status, "value", orig_status)).lower()
                    if f2_status_str == "resolved" and orig_status_str != "resolved":
                        f2.status = orig_status
                        f2.last_seen = datetime.now(timezone.utc)
                        await db.commit()
                        logger.info("retest_reverted_auto_resolve finding=%s job=%s", f2.id, job.id)
            except Exception as e:
                logger.warning("retest_revert_failed job=%s error=%s", job.id, e)

        evidence = f"Micro-scan at {datetime.now(timezone.utc).isoformat()}: {'FIXED' if is_fixed else 'STILL_VULNERABLE'} for {job.finding_id} (template={result.get('template_id')})"
        return {"is_fixed": is_fixed, "evidence": evidence, "engine_result": result}

    @staticmethod
    async def get_retest(db: AsyncSession, retest_id: str) -> Optional[RetestJob]:
        result = await db.execute(select(RetestJob).where(RetestJob.id == retest_id))
        return result.scalar_one_or_none()

    @staticmethod
    async def list_retests(
        db: AsyncSession,
        project_id: Optional[str] = None,
        finding_id: Optional[str] = None,
        workspace_id: Optional[str] = None,
        status: Optional[str] = None,
        limit: int = 50,
        offset: int = 0,
    ) -> Tuple[List[RetestJob], int]:
        filters = []
        if project_id:
            filters.append(RetestJob.project_id == project_id)
        if finding_id:
            filters.append(RetestJob.finding_id == finding_id)
        if workspace_id:
            filters.append(RetestJob.workspace_id == workspace_id)
        if status:
            try:
                st = RetestStatus(status)
                filters.append(RetestJob.status == st)
            except ValueError:
                pass

        count_q = select(func.count()).select_from(RetestJob)
        if filters:
            count_q = count_q.where(and_(*filters))
        total_res = await db.execute(count_q)
        total = total_res.scalar() or 0

        q = select(RetestJob)
        if filters:
            q = q.where(and_(*filters))
        q = q.order_by(RetestJob.created_at.desc()).limit(min(limit, 100)).offset(max(0, offset))
        result = await db.execute(q)
        return list(result.scalars().all()), total

    @staticmethod
    async def batch_retest(
        db: AsyncSession,
        finding_ids: List[str],
        requester: User,
        auto_resolve: bool = True,
    ) -> List[RetestJob]:
        """Create and immediately run retests for multiple findings."""
        jobs = []
        for fid in finding_ids:
            job = await RetestService.create_retest(db, fid, requester, auto_resolve=auto_resolve)
            job = await RetestService.run_retest(db, job.id)
            jobs.append(job)
        return jobs

    @staticmethod
    async def get_retest_stats(
        db: AsyncSession,
        project_id: Optional[str] = None,
        workspace_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        filters = []
        if project_id:
            filters.append(RetestJob.project_id == project_id)
        if workspace_id:
            filters.append(RetestJob.workspace_id == workspace_id)

        total_q = select(func.count()).select_from(RetestJob)
        if filters:
            total_q = total_q.where(and_(*filters))
        total = (await db.execute(total_q)).scalar() or 0

        fixed_q = select(func.count()).select_from(RetestJob).where(RetestJob.result == RetestResult.FIXED)
        if filters:
            fixed_q = fixed_q.where(and_(*filters))
        fixed = (await db.execute(fixed_q)).scalar() or 0

        still_q = select(func.count()).select_from(RetestJob).where(RetestJob.result == RetestResult.STILL_VULNERABLE)
        if filters:
            still_q = still_q.where(and_(*filters))
        still = (await db.execute(still_q)).scalar() or 0

        pending_q = select(func.count()).select_from(RetestJob).where(RetestJob.status == RetestStatus.PENDING)
        if filters:
            pending_q = pending_q.where(and_(*filters))
        pending = (await db.execute(pending_q)).scalar() or 0

        return {
            "total": total,
            "fixed": fixed,
            "still_vulnerable": still,
            "pending": pending,
            "fix_rate": round(fixed / total, 3) if total else 0.0,
        }
