"""RedPulse - Remediation Verification (Retest) Workflow.

Mounted at /api/v1/findings - all paths are relative to that prefix.
"""
from __future__ import annotations

import logging
from typing import Optional, List

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel, Field
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_current_user, get_db
from app.db.models import User
from app.services.retest_engine import retest_finding
from app.services.retest_service import RetestService
from app.services.audit_service import AuditService

logger = logging.getLogger(__name__)
router = APIRouter(tags=["retest"])


class BatchRetestRequest(BaseModel):
    finding_ids: List[str] = Field(..., min_length=1, max_length=20, description="Findings to retest")
    auto_resolve: bool = Field(True, description="Auto-mark RESOLVED if fixed")


# Legacy single verify-fix (preserved for compatibility)
@router.post("/{finding_id}/verify-fix")
async def verify_fix(
    finding_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Verify fix for a single finding via targeted micro-scan."""
    try:
        result = await retest_finding(finding_id, db, current_user)
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Retest failed: {e}")
    return {"success": True, "data": result}


@router.post("/{finding_id}/retest")
async def create_and_run_retest(
    finding_id: str,
    request: Request,
    auto_resolve: bool = Query(True, description="Auto-resolve if fixed"),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Create and run a tracked retest job for a finding (new workflow)."""
    try:
        job = await RetestService.create_retest(db, finding_id, current_user, auto_resolve=auto_resolve)
        job = await RetestService.run_retest(db, job.id)
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))

    try:
        await AuditService.log(
            db, action="retest.create", resource_type="finding", resource_id=finding_id,
            user_id=current_user.id, project_id=job.project_id, workspace_id=job.workspace_id,
            details={"retest_id": job.id, "result": str(job.result.value if hasattr(job.result, "value") else job.result) if job.result else None, "auto_resolve": auto_resolve},
            request=request,
        )
    except Exception:
        pass

    return {
        "success": True,
        "data": {
            "id": job.id,
            "finding_id": job.finding_id,
            "status": job.status.value if hasattr(job.status, "value") else str(job.status),
            "result": job.result.value if hasattr(job.result, "value") and job.result else None,
            "verified_at": job.verified_at.isoformat() if job.verified_at else None,
            "auto_resolved": job.auto_resolved,
            "project_id": job.project_id,
        },
    }


@router.post("/batch-retest")
async def batch_retest(
    data: BatchRetestRequest,
    request: Request,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Batch retest multiple findings (POST /api/v1/findings/batch-retest)."""
    try:
        jobs = await RetestService.batch_retest(db, data.finding_ids, current_user, auto_resolve=data.auto_resolve)
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))

    try:
        await AuditService.log(
            db, action="retest.batch", resource_type="finding", user_id=current_user.id,
            details={"finding_ids": data.finding_ids, "count": len(jobs)},
            request=request,
        )
    except Exception:
        pass

    return {
        "success": True,
        "data": [
            {
                "id": j.id,
                "finding_id": j.finding_id,
                "status": j.status.value if hasattr(j.status, "value") else str(j.status),
                "result": j.result.value if hasattr(j.result, "value") and j.result else None,
            }
            for j in jobs
        ],
        "meta": {"total": len(jobs), "fixed": sum(1 for j in jobs if j.result and str(j.result.value if hasattr(j.result, "value") else j.result) == "fixed")},
    }
