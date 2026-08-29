"""RedPulse - Workspace API Endpoints.

Multi-tenancy workspace management with RBAC.
"""
from __future__ import annotations

import logging
import re

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_current_user, get_db
from app.db.models import User, Workspace, WorkspaceMember, WorkspaceRole
from app.services.workspace_service import WorkspaceService
from app.schemas import APIResponse

logger = logging.getLogger(__name__)
router = APIRouter(tags=["workspaces"])


def _validate_slug(slug: str) -> str:
    """Validate and normalize workspace slug."""
    slug = slug.lower().strip()
    if not re.match(r"^[a-z0-9]([a-z0-9\-]*[a-z0-9])?$", slug):
        raise HTTPException(
            status_code=400,
            detail="Slug must contain only lowercase letters, numbers, and hyphens",
        )
    if len(slug) < 3 or len(slug) > 100:
        raise HTTPException(
            status_code=400,
            detail="Slug must be 3-100 characters long",
        )
    return slug


@router.post("", status_code=status.HTTP_201_CREATED)
async def create_workspace(
    data: dict,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> APIResponse:
    """Create a new workspace."""
    name = data.get("name", "").strip()
    slug = data.get("slug", "").strip()
    description = data.get("description", "")

    if not name:
        raise HTTPException(status_code=400, detail="Name is required")
    if not slug:
        # Auto-generate slug from name
        slug = re.sub(r"[^a-z0-9]+", "-", name.lower()).strip("-")

    slug = _validate_slug(slug)

    # Check slug uniqueness
    existing = await db.execute(
        select(Workspace).where(Workspace.slug == slug)
    )
    if existing.scalar_one_or_none():
        raise HTTPException(status_code=409, detail="Workspace slug already taken")

    workspace = await WorkspaceService.create_workspace(
        db, current_user, name, slug, description,
    )

    return APIResponse(
        success=True,
        data={
            "id": workspace.id,
            "name": workspace.name,
            "slug": workspace.slug,
            "description": workspace.description,
            "owner_id": workspace.owner_id,
            "created_at": workspace.created_at.isoformat() if workspace.created_at else None,
        },
    )


@router.get("")
async def list_workspaces(
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> APIResponse:
    """List all workspaces the current user belongs to."""
    workspaces = await WorkspaceService.get_user_workspaces(db, current_user.id)

    return APIResponse(
        success=True,
        data=[
            {
                "id": w.id,
                "name": w.name,
                "slug": w.slug,
                "description": w.description,
                "owner_id": w.owner_id,
                "is_active": w.is_active,
                "created_at": w.created_at.isoformat() if w.created_at else None,
            }
            for w in workspaces
        ],
    )


@router.get("/{workspace_id}")
async def get_workspace(
    workspace_id: str,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> APIResponse:
    """Get workspace details."""
    has_access, role = await WorkspaceService.check_workspace_access(
        db, workspace_id, current_user.id, "workspace:read",
    )
    if not has_access:
        raise HTTPException(status_code=404, detail="Workspace not found")

    result = await db.execute(
        select(Workspace).where(Workspace.id == workspace_id)
    )
    workspace = result.scalar_one_or_none()
    if not workspace:
        raise HTTPException(status_code=404, detail="Workspace not found")

    stats = await WorkspaceService.get_workspace_stats(db, workspace_id)

    return APIResponse(
        success=True,
        data={
            "id": workspace.id,
            "name": workspace.name,
            "slug": workspace.slug,
            "description": workspace.description,
            "owner_id": workspace.owner_id,
            "is_active": workspace.is_active,
            "your_role": role.value if role else None,
            "stats": stats,
            "created_at": workspace.created_at.isoformat() if workspace.created_at else None,
        },
    )


# ==================== Members ====================

@router.get("/{workspace_id}/members")
async def list_members(
    workspace_id: str,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> APIResponse:
    """List workspace members."""
    has_access, _ = await WorkspaceService.check_workspace_access(
        db, workspace_id, current_user.id, "member:read",
    )
    if not has_access:
        raise HTTPException(status_code=404, detail="Workspace not found")

    result = await db.execute(
        select(WorkspaceMember).where(
            WorkspaceMember.workspace_id == workspace_id,
        )
    )
    members = result.scalars().all()

    return APIResponse(
        success=True,
        data=[
            {
                "id": m.id,
                "user_id": m.user_id,
                "role": m.role.value,
                "joined_at": m.joined_at.isoformat() if m.joined_at else None,
            }
            for m in members
        ],
    )


@router.post("/{workspace_id}/members")
async def invite_member(
    workspace_id: str,
    data: dict,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> APIResponse:
    """Invite a member to the workspace."""
    email = data.get("email", "").strip()
    role_str = data.get("role", "viewer")

    if not email:
        raise HTTPException(status_code=400, detail="Email is required")

    try:
        role = WorkspaceRole(role_str)
    except ValueError:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid role: {role_str}. Must be admin, analyst, or viewer",
        )

    try:
        member = await WorkspaceService.invite_member(
            db, workspace_id, current_user.id, email, role,
        )
    except PermissionError as e:
        raise HTTPException(status_code=403, detail=str(e))
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

    return APIResponse(
        success=True,
        data={
            "id": member.id,
            "user_id": member.user_id,
            "role": member.role.value,
        },
    )


@router.delete("/{workspace_id}/members/{member_id}")
async def remove_member(
    workspace_id: str,
    member_id: str,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> APIResponse:
    """Remove a member from the workspace."""
    try:
        removed = await WorkspaceService.remove_member(
            db, workspace_id, current_user.id, member_id,
        )
    except PermissionError as e:
        raise HTTPException(status_code=403, detail=str(e))
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

    if not removed:
        raise HTTPException(status_code=404, detail="Member not found")

    return APIResponse(success=True, data={"removed": True})


# ==================== Projects ====================

@router.get("/{workspace_id}/projects")
async def list_workspace_projects(
    workspace_id: str,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> APIResponse:
    """List all projects in a workspace."""
    try:
        projects = await WorkspaceService.get_workspace_projects(
            db, workspace_id, current_user.id,
        )
    except PermissionError as e:
        raise HTTPException(status_code=403, detail=str(e))

    return APIResponse(
        success=True,
        data=[
            {
                "id": p.id,
                "name": p.name,
                "description": p.description,
                "status": p.status.value if hasattr(p.status, "value") else str(p.status),
                "created_at": p.created_at.isoformat() if p.created_at else None,
            }
            for p in projects
        ],
    )
