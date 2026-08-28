"""RedPulse - Pipeline API Endpoints.

Orchestrates the full recon-to-assessment pipeline via a single API call.
"""

import logging
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_db, get_current_user
from app.db.models import User, Engagement, Project, Authorization
from app.schemas import PipelineRunRequest, APIResponse
from app.services.pipeline import PipelineOrchestrator

logger = logging.getLogger("redpulse.api.pipeline")

router = APIRouter(tags=["pipeline"])


@router.post("/run", response_model=APIResponse, status_code=status.HTTP_200_OK)
async def run_pipeline(
    data: PipelineRunRequest,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> APIResponse:
    """Run the full recon-to-assessment pipeline.

    Executes:
    1. Scope validation for target
    2. Recon jobs (subfinder/httpx/nmap)
    3. Asset normalization and DB insertion
    4. Nuclei assessment on discovered assets
    5. Finding ingestion with fingerprint deduplication

    If recon fails, assessment is skipped but the pipeline completes gracefully.
    If 0 assets are found, assessment is skipped.
    """
    # Verify engagement access
    from sqlalchemy import select
    result = await db.execute(
        select(Engagement).join(Project).where(
            Engagement.id == data.engagement_id,
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

    # Verify authorization exists
    auth_result = await db.execute(
        select(Authorization).where(
            Authorization.engagement_id == engagement.id,
            Authorization.user_id == current_user.id,
        )
    )
    auth = auth_result.scalar_one_or_none()
    if not auth:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="No authorization for this engagement. Complete DNS TXT or bug bounty verification first.",
        )

    # Run pipeline
    orchestrator = PipelineOrchestrator(db=db, user=current_user)
    pipeline_result = await orchestrator.run(
        engagement_id=data.engagement_id,
        target=data.target,
        recon_tools=data.recon_tools,
        run_assessment=data.run_assessment,
        template_path=data.template_path,
        auth_headers=data.auth_headers,
        auth_cookies=data.auth_cookies,
    )

    return APIResponse(
        success=pipeline_result.status != "failed",
        data=pipeline_result.to_dict(),
    )
