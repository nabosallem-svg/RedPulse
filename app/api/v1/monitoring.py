"""ReconPilot - Monitoring API Routes.

Continuous attack-surface monitoring configuration and cycles.
"""

from fastapi import APIRouter, Depends, HTTPException, status, BackgroundTasks
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from typing import List, Optional

from app.schemas.monitoring import (
    MonitoringConfigCreate, MonitoringConfigDB, MonitoringCycleRequest,
    MonitoringChangeDetected
)
from app.models import Project, MonitoringConfig
from app.core.security import require_project_access
from app.config import get_settings
from app.core.logging import structured_log

router = APIRouter(prefix="/{project_id}/monitoring", tags=["monitoring"])


@router.post("/config", response_model=MonitoringConfigDB, status_code=status.HTTP_201_CREATED)
async def create_monitoring_config(
    config_data: MonitoringConfigCreate,
    project_id: str,
    current_user: User = Depends(require_project_access),
    db: AsyncSession = ...,
):
    """Create a continuous monitoring configuration."""
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
            detail="Insufficient permissions - only Org Owners and Admins can configure monitoring",
        )
    
    # Check if monitoring config already exists for this project
    result = await db.execute(
        select(MonitoringConfig).filter(MonitoringConfig.project_id == project_id)
    )
    existing = result.scalar_one_or_none()
    if existing:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Monitoring config already exists for this project",
        )
    
    # Create the monitoring config
    monitoring = MonitoringConfig(
        name=config_data.name,
        frequency=config_data.frequency,
        profile=config_data.profile,
        project_id=project_id,
    )
    
    db.add(monitoring)
    await db.commit()
    await db.refresh(monitoring)
    
    # Log the action
    await structured_log(
        event="monitoring_config_created",
        project_id=project_id,
        monitoring_id=monitoring.id,
        user_id=current_user.id,
        level="INFO",
    )
    
    return monitoring


@router.get("/config", response_model=List[MonitoringConfigDB])
async def list_monitoring_configs(
    project_id: str,
    current_user: User = Depends(require_project_access),
    db: AsyncSession = ...,
):
    """List monitoring configurations for a project."""
    # Verify project exists and user has access
    project = await db.get(Project, project_id)
    if not project:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Project not found",
        )
    
    result = await db.execute(
        select(MonitoringConfig).filter(MonitoringConfig.project_id == project_id)
    )
    configs = result.scalars().all()
    
    return configs


@router.post("/cycle/start", response_model=dict)
async def start_monitoring_cycle(
    request: MonitoringCycleRequest,
    background_tasks: BackgroundTasks,
    project_id: str,
    current_user: User = Depends(require_project_access),
    db: AsyncSession = ...,
):
    """Start a continuous monitoring cycle."""
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
    
    # TODO: Start background monitoring worker
    # For now, return acceptance and log
    await structured_log(
        event="monitoring_cycle_started",
        project_id=project_id,
        user_id=current_user.id,
        level="INFO",
    )
    
    return {
        "project_id": project_id,
        "status": "started",
        "message": "Monitoring cycle started in background",
    }