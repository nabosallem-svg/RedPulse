"""RedPulse - Engagements Routes.

Handles engagement creation, listing, and retrieval for authenticated users.
Engagements belong to projects, and users can only access engagements
under projects they own.
"""

from typing import List

from fastapi import APIRouter, Depends, HTTPException, status, Query
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_current_user, get_db
from app.db.models import Project, Engagement, User
from app.schemas import EngagementCreate, EngagementSchema


router = APIRouter(tags=["engagements"])


@router.post(
    "/", response_model=EngagementSchema, status_code=status.HTTP_201_CREATED
)
async def create_engagement(
    data: EngagementCreate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> EngagementSchema:
    """Create a new engagement under a project owned by the current user.

    Args:
        data: Engagement creation data (name, project_id)
        db: Database session
        current_user: Authenticated user

    Returns:
        Created engagement schema

    Raises:
        HTTPException: 404 if the project doesn't exist or isn't owned by current user
    """
    # Verify project exists and is owned by current user
    result = await db.execute(
        select(Project).where(
            Project.id == data.project_id, Project.owner_id == current_user.id
        )
    )
    project = result.scalar_one_or_none()

    if project is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Project not found or not owned by current user",
        )

    engagement = Engagement(
        name=data.name,
        project_id=data.project_id,
        status=getattr(data, "status", None) or "draft",
        description=getattr(data, "description", None),
    )
    db.add(engagement)
    await db.commit()
    await db.refresh(engagement)
    return EngagementSchema(
        id=engagement.id,
        name=engagement.name,
        description=engagement.description,
        status=engagement.status,
        project_id=engagement.project_id,
        created_at=engagement.created_at,
    )


@router.get("/", response_model=None)
async def list_engagements(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
    page: int = Query(1, ge=1, description="Page number"),
    per_page: int = Query(50, ge=1, le=100, description="Items per page"),
):
    """List all engagements under projects owned by the current user (paginated)."""
    # Get all projects owned by current user
    result = await db.execute(select(Project).where(Project.owner_id == current_user.id))
    projects = result.scalars().all()

    # Get all engagements for those projects
    engagements = []
    for project in projects:
        proj_result = await db.execute(
            select(Engagement).where(Engagement.project_id == project.id)
        )
        for eng in proj_result.scalars().all():
            engagements.append(
                EngagementSchema(
                    id=eng.id,
                    name=eng.name,
                    description=eng.description,
                    status=eng.status,
                    project_id=eng.project_id,
                    created_at=eng.created_at,
                )
            )

    total = len(engagements)
    pages = (total + per_page - 1) // per_page if total else 1
    start = (page - 1) * per_page
    end = start + per_page
    paginated = engagements[start:end]
    return {"success": True, "data": paginated, "meta": {"page": page, "per_page": per_page, "total": total, "pages": pages}}


@router.get("/{engagement_id}", response_model=EngagementSchema)
async def get_engagement(
    engagement_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> EngagementSchema:
    """Get a single engagement by ID.

    Only returns the engagement if it belongs to a project owned by the current user.
    Returns 404 if the engagement exists but belongs to a project owned by another user.

    Args:
        engagement_id: Engagement UUID
        db: Database session
        current_user: Authenticated user

    Returns:
        Engagement schema

    Raises:
        HTTPException: 404 if engagement not found or not accessible
    """
    # First check if engagement exists and belongs to user's project
    result = await db.execute(
        select(Engagement)
        .join(Project)
        .where(
            Engagement.id == engagement_id,
            Project.id == Engagement.project_id,
            Project.owner_id == current_user.id,
        )
    )
    engagement = result.scalar_one_or_none()

    if engagement is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Engagement not found or not accessible",
        )

    return EngagementSchema(
        id=engagement.id,
        name=engagement.name,
        description=engagement.description,
        status=engagement.status,
        project_id=engagement.project_id,
        created_at=engagement.created_at,
    )