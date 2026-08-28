"""RedPulse - Recon API Endpoints.

Endpoints for creating and managing recon jobs, viewing assets.
All endpoints enforce scope validation before execution.
"""

import logging
from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select, func
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_db, get_current_user
from app.db.models import (
    User, ReconJob, ReconJobStatus, ReconTool, Asset,
    Engagement, Project, Authorization,
)
from app.schemas import ReconJobCreate, ReconJobSchema, AssetSchema, APIResponse
from app.services.worker import worker

logger = logging.getLogger("redpulse.api.recon")

router = APIRouter(tags=["recon"])


async def _verify_engagement_access(
    engagement_id: str,
    current_user: User,
    db: AsyncSession,
) -> Engagement:
    """Verify user has access to this engagement via project ownership."""
    result = await db.execute(
        select(Engagement).join(Project).where(
            Engagement.id == engagement_id,
            Project.id == Engagement.project_id,
            Project.owner_id == current_user.id,
        )
    )
    engagement = result.scalar_one_or_none()
    if not engagement:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Engagement not found or access denied",
        )
    return engagement


async def _verify_job_access(
    job_id: str,
    current_user: User,
    db: AsyncSession,
) -> ReconJob:
    """Verify user has access to this recon job."""
    result = await db.execute(
        select(ReconJob).join(Engagement).join(Project).where(
            ReconJob.id == job_id,
            Engagement.id == ReconJob.engagement_id,
            Project.id == Engagement.project_id,
            Project.owner_id == current_user.id,
        )
    )
    job = result.scalar_one_or_none()
    if not job:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Recon job not found or access denied",
        )
    return job


@router.post("/jobs", response_model=APIResponse, status_code=status.HTTP_201_CREATED)
async def create_recon_job(
    data: ReconJobCreate,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Create and execute a recon job.

    Validates scope before execution. If scope validation fails,
    the job is created with FAILED status and an error message.
    """
    # Verify engagement access
    engagement = await _verify_engagement_access(data.engagement_id, current_user, db)

    # Verify authorization exists and is verified
    auth_result = await db.execute(
        select(Authorization).where(
            Authorization.engagement_id == engagement.id,
            Authorization.user_id == current_user.id,
            Authorization.verified == True,
        )
    )
    auth = auth_result.scalar_one_or_none()
    if not auth:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="No verified authorization for this engagement. "
                   "Complete authorization via DNS TXT or bug bounty program first.",
        )

    # Create job
    tool_enum = ReconTool(data.tool)
    job = ReconJob(
        engagement_id=data.engagement_id,
        user_id=current_user.id,
        tool=tool_enum,
        target=data.target,
        status=ReconJobStatus.PENDING,
    )
    db.add(job)
    await db.commit()
    await db.refresh(job)

    # Execute job (scope validated inside worker)
    job = await worker.run_job(job.id, db, current_user)

    return APIResponse(
        success=job.status == ReconJobStatus.COMPLETED,
        data=ReconJobSchema.model_validate(job).model_dump(),
    )


@router.get("/jobs", response_model=APIResponse)
async def list_recon_jobs(
    engagement_id: Optional[str] = None,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """List recon jobs for the current user, optionally filtered by engagement."""
    query = (
        select(ReconJob)
        .join(Engagement)
        .join(Project)
        .where(Project.owner_id == current_user.id)
    )
    if engagement_id:
        query = query.where(ReconJob.engagement_id == engagement_id)
    query = query.order_by(ReconJob.created_at.desc()).limit(100)

    result = await db.execute(query)
    jobs = result.scalars().all()

    return APIResponse(
        data=[ReconJobSchema.model_validate(j).model_dump() for j in jobs],
    )


@router.get("/jobs/{job_id}", response_model=APIResponse)
async def get_recon_job(
    job_id: str,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Get a specific recon job."""
    job = await _verify_job_access(job_id, current_user, db)
    return APIResponse(data=ReconJobSchema.model_validate(job).model_dump())


@router.get("/assets", response_model=APIResponse)
async def list_assets(
    engagement_id: Optional[str] = None,
    asset_type: Optional[str] = None,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """List discovered assets, optionally filtered by engagement and type."""
    query = (
        select(Asset)
        .join(Engagement)
        .join(Project)
        .where(Project.owner_id == current_user.id)
    )
    if engagement_id:
        query = query.where(Asset.engagement_id == engagement_id)
    if asset_type:
        query = query.where(Asset.asset_type == asset_type)
    query = query.order_by(Asset.last_seen.desc()).limit(200)

    result = await db.execute(query)
    assets = result.scalars().all()

    return APIResponse(
        data=[AssetSchema.model_validate(a).model_dump() for a in assets],
    )


@router.get("/assets/{asset_id}", response_model=APIResponse)
async def get_asset(
    asset_id: str,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Get a specific asset."""
    result = await db.execute(
        select(Asset).join(Engagement).join(Project).where(
            Asset.id == asset_id,
            Project.owner_id == current_user.id,
        )
    )
    asset = result.scalar_one_or_none()
    if not asset:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Asset not found or access denied",
        )
    return APIResponse(data=AssetSchema.model_validate(asset).model_dump())


@router.get("/tools/status", response_model=APIResponse)
async def get_tools_status(
    current_user: User = Depends(get_current_user),
):
    """Check which recon tools are available on the system."""
    status_dict = await worker.check_availability()
    return APIResponse(data=status_dict)
