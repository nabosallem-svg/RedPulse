"""ReconPilot - Projects Routes.

Handles project creation, listing, and retrieval for authenticated users.
Each project is owned by a single user, and users can only access their own projects.
"""

from typing import List

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_current_user, get_db
from app.db.models import Project, User
from app.schemas import ProjectCreate, ProjectSchema


router = APIRouter(tags=["projects"])


@router.post(
    "/", response_model=ProjectSchema, status_code=status.HTTP_201_CREATED
)
async def create_project(
    data: ProjectCreate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> ProjectSchema:
    """Create a new project owned by the current user.

    Args:
        data: Project creation data
        db: Database session
        current_user: Authenticated user

    Returns:
        Created project schema

    Raises:
        HTTPException: 400 if project name already exists for this user
    """
    # Check if project name already exists for this user
    result = await db.execute(
        select(Project).where(Project.name == data.name, Project.owner_id == current_user.id)
    )
    existing = result.scalar_one_or_none()
    if existing:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Project with this name already exists",
        )

    project = Project(
        name=data.name,
        owner_id=current_user.id,
        description=data.description,
    )
    db.add(project)
    await db.commit()
    await db.refresh(project)
    return ProjectSchema(
        id=project.id,
        name=project.name,
        description=project.description,
        status=project.status,
        owner_id=project.owner_id,
        created_at=project.created_at,
    )


@router.get("/", response_model=List[ProjectSchema])
async def list_projects(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> List[ProjectSchema]:
    """List all projects owned by the current user.

    Args:
        db: Database session
        current_user: Authenticated user

    Returns:
        List of project schemas
    """
    result = await db.execute(select(Project).where(Project.owner_id == current_user.id))
    projects = result.scalars().all()
    return [
        ProjectSchema(
            id=p.id,
            name=p.name,
            description=p.description,
            status=p.status,
            owner_id=p.owner_id,
            created_at=p.created_at,
        )
        for p in projects
    ]


@router.get("/{project_id}", response_model=ProjectSchema)
async def get_project(
    project_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> ProjectSchema:
    """Get a single project by ID.

    Only returns the project if it belongs to the current user.
    Returns 404 if the project exists but belongs to another user
    (never leak other users' projects).

    Args:
        project_id: Project UUID
        db: Database session
        current_user: Authenticated user

    Returns:
        Project schema

    Raises:
        HTTPException: 404 if project not found or not owned by current user
    """
    result = await db.execute(
        select(Project).where(
            Project.id == project_id, Project.owner_id == current_user.id
        )
    )
    project = result.scalar_one_or_none()

    if project is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Project not found",
        )

    return ProjectSchema(
        id=project.id,
        name=project.name,
        description=project.description,
        status=project.status,
        owner_id=project.owner_id,
        created_at=project.created_at,
    )