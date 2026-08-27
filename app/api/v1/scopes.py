"""RedPulse - Scopes API Routes.

Scope engine for authorized target management.
"""

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from typing import List, Optional

from app.schemas.scopes import ProjectScopeCreate, ProjectScopeDB
from app.models import Project, Scope
from app.core.security import require_project_access
from app.config import get_settings
from app.core.logging import structured_log

router = APIRouter(prefix="/{project_id}/scopes", tags=["scopes"])


@router.post(
    "", response_model=ProjectScopeDB,
    status_code=status.HTTP_201_CREATED,
)
async def add_scope(
    project_id: str,
    scope_data: ProjectScopeCreate,
    current_user: User = Depends(require_project_access),
    db: AsyncSession = ...,
):
    """Add an authorized scope to a project."""
    # Verify project exists and user has access
    project = await db.get(Project, project_id)
    if not project:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Project not found",
        )
    
    # Check user has Admin or Owner role
    member = await db.execute(
        select(OrganizationMember).join(
            Project.organization
        ).where(
            Project.id == project_id,
            OrganizationMember.user_id == current_user.id,
            OrganizationMember.role.in_(["Owner", "Admin"]),
        )
    )
    if not member.scalar_one_or_none():
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Insufficient permissions - only Org Owners and Admins can add scopes",
        )
    
    # Check for duplicate scope
    result = await db.execute(
        select(Scope).filter(
            Scope.project_id == project_id,
            Scope.value == scope_data.value,
        )
    )
    existing = result.scalar_one_or_none()
    if existing:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Scope '{scope_data.value}' already exists for this project",
        )
    
    # Create the scope with project isolation
    scope = Scope(
        value=scope_data.value,
        scope_type=scope_data.scope_type,
        is_wildcard=scope_data.is_wildcard,
        project_id=project_id,
    )
    
    db.add(scope)
    await db.commit()
    await db.refresh(scope)
    
    # Log the action
    await structured_log(
        event="scope_added",
        project_id=project_id,
        scope_value=scope_data.value,
        user_id=current_user.id,
        level="INFO",
    )
    
    return scope


@router.get("", response_model=List[ProjectScopeDB])
async def list_scopes(
    project_id: str,
    current_user: User = Depends(require_project_access),
    db: AsyncSession = ...,
):
    """List all scopes for a project."""
    # Verify project exists and user has access
    project = await db.get(Project, project_id)
    if not project:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Project not found",
        )
    
    result = await db.execute(
        select(Scope).filter(Scope.project_id == project_id)
    )
    scopes = result.scalars().all()
    
    return scopes


@router.post("/{scope_id}/validate", response_model=dict)
async def validate_scope_target(
    project_id: str,
    scope_id: str,
    target: str,
    current_user: User = Depends(require_project_access),
    db: AsyncSession = ...,
):
    """Validate if a target belongs to the project's authorized scope."""
    # Verify project exists
    project = await db.get(Project, project_id)
    if not project:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Project not found",
        )
    
    # Check the specific scope entry
    result = await db.execute(
        select(Scope).filter(
            Scope.project_id == project_id,
            Scope.id == scope_id,
        )
    )
    scope = result.scalar_one_or_none()
    
    if not scope:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Scope not found",
        )
    
    # Normalize and check
    normalized = target.strip().lower()
    if normalized == scope.value.lower() or (
        scope.is_wildcard and normalized.startswith(scope.value.lower())
    ):
        in_scope = True
    else:
        # Check subdomain relationship
        # e.g., if scope is "example.com" and target is "sub.example.com"
        in_scope = scope.value in normalized or normalized.startswith(scope.value + ".")
    
    return {
        "target": target,
        "scope_id": scope_id,
        "scope_value": scope.value,
        "in_scope": in_scope,
    }