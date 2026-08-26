"""ReconPilot - Scans API Routes.

Scan job management and monitoring.
"""

from fastapi import APIRouter, Depends, HTTPException, status, BackgroundTasks
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from typing import List, Optional

from app.schemas.scans import ScanCreate, ScanUpdate, ScanDB, ScanJobCreate, ScanJobDB
from app.models import Project, Scan, ScanJob
from app.core.security import require_project_access
from app.config import get_settings
from app.core.logging import structured_log

router = APIRouter(prefix="/{project_id}/scans", tags=["scans"])


@router.post("/", response_model=ScanDB, status_code=status.HTTP_201_CREATED)
async def create_scan(
    scan_data: ScanCreate,
    project_id: str,
    current_user: User = Depends(require_project_access),
    db: AsyncSession = ...,
):
    """Create a new scan job for a project."""
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
            detail="Insufficient permissions - only Org Owners and Admins can create scans",
        )
    
    # Create the scan
    scan = Scan(
        name=scan_data.name,
        description=scan_data.description,
        profile=scan_data.profile,
        project_id=project_id,
    )
    
    db.add(scan)
    await db.commit()
    await db.refresh(scan)
    
    # Create initial scan job
    job = ScanJob(
        scan_id=scan.id,
        project_id=project_id,
        status="pending",
    )
    
    db.add(job)
    await db.commit()
    await db.refresh(job)
    
    # Log the action
    await structured_log(
        event="scan_created",
        project_id=project_id,
        scan_id=scan.id,
        user_id=current_user.id,
        level="INFO",
    )
    
    return scan


@router.get("/", response_model=List[ScanDB])
async def list_scans(
    project_id: str,
    current_user: User = Depends(require_project_access),
    db: AsyncSession = ...,
):
    """List all scans for a project."""
    # Verify project exists and user has access
    project = await db.get(Project, project_id)
    if not project:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Project not found",
        )
    
    result = await db.execute(
        select(Scan).filter(Scan.project_id == project_id)
    )
    scans = result.scalars().all()
    
    return scans


@router.get("/{scan_id}", response_model=ScanDB)
async def get_scan(
    scan_id: str,
    project_id: str,
    current_user: User = Depends(require_project_access),
    db: AsyncSession = ...,
):
    """Get a specific scan by ID."""
    # Verify project exists and user has access
    project = await db.get(Project, project_id)
    if not project:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Project not found",
        )
    
    result = await db.execute(
        select(Scan).filter(Scan.id == scan_id, Scan.project_id == project_id)
    )
    scan = result.scalar_one_or_none()
    
    if not scan:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Scan not found",
        )
    
    return scan


@router.post("/{scan_id}/start", response_model=ScanJobDB)
async def start_scan(
    scan_id: str,
    project_id: str,
    background_tasks: BackgroundTasks,
    current_user: User = Depends(require_project_access),
    db: AsyncSession = ...,
):
    """Start a scan job."""
    # Verify project exists and user has access
    project = await db.get(Project, project_id)
    if not project:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Project not found",
        )
    
    # Get the scan
    result = await db.execute(
        select(Scan).filter(Scan.id == scan_id, Scan.project_id == project_id)
    )
    scan = result.scalar_one_or_none()
    
    if not scan:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Scan not found",
        )
    
    # Get the first job or create one
    result = await db.execute(
        select(ScanJob).filter(ScanJob.scan_id == scan_id)
    )
    job = result.scalar_one_or_none()
    
    if not job:
        job = ScanJob(
            scan_id=scan_id,
            project_id=project_id,
            status="pending",
        )
        db.add(job)
        await db.commit()
        await db.refresh(job)
    
    if job.status == "running":
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Scan is already running",
        )
    
    # Update job status to running
    job.status = "running"
    await db.commit()
    await db.refresh(job)
    
    # TODO: Start background recon worker
    # For now, just log and return
    await structured_log(
        event="scan_started",
        project_id=project_id,
        scan_id=scan_id,
        job_id=job.id,
        user_id=current_user.id,
        level="INFO",
    )
    
    return job