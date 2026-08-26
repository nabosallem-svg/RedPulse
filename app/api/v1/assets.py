"""ReconPilot - Assets API Routes.

Asset intelligence and discovery.
"""

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from typing import List, Optional

from app.schemas.assets import AssetCreate, AssetUpdate, AssetDB, AssetInScopeQuery
from app.models import Project, Asset
from app.core.security import require_project_access
from app.config import get_settings
from app.core.logging import structured_log

router = APIRouter(prefix="/{project_id}/assets", tags=["assets"])


@router.post(
    "", response_model=AssetDB,
    status_code=status.HTTP_201_CREATED,
)
async def create_asset(
    asset_data: AssetCreate,
    project_id: str,
    current_user: User = Depends(require_project_access),
    db: AsyncSession = ...,
):
    """Create a new asset in a project."""
    # Verify project exists and user has access
    project = await db.get(Project, project_id)
    if not project:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Project not found",
        )
    
    # Check user has at least Analyst role
    member = await db.execute(
        select(OrganizationMember).join(
            Project.organization
        ).where(
            Project.id == project_id,
            OrganizationMember.user_id == current_user.id,
            OrganizationMember.role.in_(["Owner", "Admin", "Analyst"]),
        )
    )
    if not member.scalar_one_or_none():
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Insufficient permissions",
        )
    
    # Check for duplicate (same hostname + scheme)
    result = await db.execute(
        select(Asset).filter(
            Asset.project_id == project_id,
            Asset.hostname == asset_data.hostname,
            Asset.scheme == asset_data.scheme,
        )
    )
    existing = result.scalar_one_or_none()
    if existing:
        # Update existing asset instead
        existing.last_seen = datetime.utcnow()
        existing.last_checked = datetime.utcnow()
        existing.is_active = True
        if asset_data.ip:
            existing.ip = asset_data.ip
        if asset_data.status_code:
            existing.status_code = asset_data.status_code
        await db.commit()
        await db.refresh(existing)
        await structured_log(
            event="asset_updated",
            project_id=project_id,
            asset_id=existing.id,
            user_id=current_user.id,
            level="INFO",
        )
        return existing
    
    # Create the new asset
    asset = Asset(
        hostname=asset_data.hostname,
        scheme=asset_data.scheme,
        port=asset_data.port,
        ip=asset_data.ip,
        project_id=project_id,
        source=asset_data.source,
        in_scope="pending_review",  # New assets need review
    )
    
    db.add(asset)
    await db.commit()
    await db.refresh(asset)
    
    # Log the action
    await structured_log(
        event="asset_created",
        project_id=project_id,
        asset_id=asset.id,
        user_id=current_user.id,
        level="INFO",
    )
    
    return asset


@router.get("", response_model=List[AssetDB])
async def list_assets(
    project_id: str,
    current_user: User = Depends(require_project_access),
    db: AsyncSession = ...,
    in_scope: Optional[str] = None,
):
    """List all assets for a project."""
    # Verify project exists and user has access
    project = await db.get(Project, project_id)
    if not project:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Project not found",
        )
    
    query = select(Asset).filter(Asset.project_id == project_id)
    
    # Filter by scope status if specified
    if in_scope:
        query = query.filter(Asset.in_scope == in_scope)
    
    result = await db.execute(query)
    assets = result.scalars().all()
    
    return assets


@router.get("/{asset_id}", response_model=AssetDB)
async def get_asset(
    asset_id: str,
    project_id: str,
    current_user: User = Depends(require_project_access),
    db: AsyncSession = ...,
):
    """Get a specific asset by ID."""
    # Verify project exists and user has access
    project = await db.get(Project, project_id)
    if not project:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Project not found",
        )
    
    result = await db.execute(
        select(Asset).filter(
            Asset.id == asset_id,
            Asset.project_id == project_id,
        )
    )
    asset = result.scalar_one_or_none()
    
    if not asset:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Asset not found",
        )
    
    return asset


@router.post("/{asset_id}/update-scope", response_model=AssetDB)
async def update_asset_scope(
    asset_id: str,
    project_id: str,
    in_scope: str,
    current_user: User = Depends(require_project_access),
    db: AsyncSession = ...,
):
    """Update the scope status of an asset."""
    # Verify project exists and user has access
    project = await db.get(Project, project_id)
    if not project:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Project not found",
        )
    
    # Valid scope states
    valid_states = ["in_scope", "out_of_scope", "pending_review"]
    if in_scope not in valid_states:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid scope state. Must be one of: {', '.join(valid_states)}",
        )
    
    # Get the asset
    result = await db.execute(
        select(Asset).filter(
            Asset.id == asset_id,
            Asset.project_id == project_id,
        )
    )
    asset = result.scalar_one_or_none()
    
    if not asset:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Asset not found",
        )
    
    # Update scope status
    old_status = asset.in_scope
    asset.in_scope = in_scope
    
    # Log scope change
    from app.core.security import ScopeEngine
    scope_engine = ScopeEngine(project_id=project_id, db=db)
    await scope_engine.log_scope_decision(
        asset_id=asset.id,
        target=asset.hostname,
        decision=in_scope,
        reason="manual_update_by_user",
    )
    
    await db.commit()
    await db.refresh(asset)
    
    # Log the action
    await structured_log(
        event="asset_scope_updated",
        project_id=project_id,
        asset_id=asset.id,
        old_status=old_status,
        new_status=in_scope,
        user_id=current_user.id,
        level="INFO",
    )
    
    return asset