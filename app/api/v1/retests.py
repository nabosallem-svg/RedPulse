"""RedPulse - Retest Jobs Listing & Stats.

Mounted at /api/v1/retests (top-level) - separate from /api/v1/findings retest creation.
"""
from __future__ import annotations

from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_current_user, get_db
from app.db.models import User, Project
from app.services.retest_service import RetestService

router = APIRouter(tags=["retest"])


@router.get("", tags=["retest"])
async def list_retests(
    project_id: Optional[str] = Query(None),
    finding_id: Optional[str] = Query(None),
    status: Optional[str] = Query(None),
    limit: int = Query(50, ge=1, le=100),
    offset: int = Query(0, ge=0),
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """List retest jobs with filters."""
    if project_id:
        proj_res = await db.execute(select(Project).where(Project.id == project_id, Project.owner_id == current_user.id))
        if not proj_res.scalar_one_or_none():
            raise HTTPException(status_code=404, detail="Project not found or access denied")

    jobs, total = await RetestService.list_retests(
        db, project_id=project_id, finding_id=finding_id, status=status, limit=limit, offset=offset
    )
    return {
        "success": True,
        "data": [
            {
                "id": j.id,
                "finding_id": j.finding_id,
                "project_id": j.project_id,
                "status": j.status.value if hasattr(j.status, "value") else str(j.status),
                "result": j.result.value if hasattr(j.result, "value") and j.result else None,
                "requested_by": j.requested_by,
                "verified_at": j.verified_at.isoformat() if j.verified_at else None,
                "created_at": j.created_at.isoformat() if j.created_at else None,
            }
            for j in jobs
        ],
        "meta": {"total": total, "limit": limit, "offset": offset},
    }


@router.get("/{retest_id}", tags=["retest"])
async def get_retest(
    retest_id: str,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    job = await RetestService.get_retest(db, retest_id)
    if not job:
        raise HTTPException(status_code=404, detail="Retest not found")
    proj_res = await db.execute(select(Project).where(Project.id == job.project_id, Project.owner_id == current_user.id))
    if not proj_res.scalar_one_or_none():
        raise HTTPException(status_code=404, detail="Retest not found or access denied")
    return {
        "success": True,
        "data": {
            "id": job.id,
            "finding_id": job.finding_id,
            "project_id": job.project_id,
            "status": job.status.value if hasattr(job.status, "value") else str(job.status),
            "result": job.result.value if hasattr(job.result, "value") and job.result else None,
            "evidence": job.evidence,
            "verified_at": job.verified_at.isoformat() if job.verified_at else None,
            "auto_resolved": job.auto_resolved,
            "created_at": job.created_at.isoformat() if job.created_at else None,
        },
    }


@router.get("/stats/summary", tags=["retest"])
async def retest_stats(
    project_id: Optional[str] = Query(None),
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    if project_id:
        proj_res = await db.execute(select(Project).where(Project.id == project_id, Project.owner_id == current_user.id))
        if not proj_res.scalar_one_or_none():
            raise HTTPException(status_code=404, detail="Project not found or access denied")
    stats = await RetestService.get_retest_stats(db, project_id=project_id)
    return {"success": True, "data": stats}
