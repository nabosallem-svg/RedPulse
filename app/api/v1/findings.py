"""RedPulse - Findings API Routes.

Security finding management, deduplication, and scoring.
"""

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from typing import List, Optional

from app.schemas.findings import (
    FindingCreate, FindingUpdate, FindingDB, FindingSummary,
    FindingStatus, FingerprintRequest
)
from app.models import Project, Finding, Asset, FindingEvent
from app.core.security import require_project_access
from app.config import get_settings
from app.core.logging import structured_log

router = APIRouter(prefix="/{project_id}/findings", tags=["findings"])


@router.post(
    "", response_model=FindingDB,
    status_code=status.HTTP_201_CREATED,
)
async def create_finding(
    finding_data: FindingCreate,
    project_id: str,
    current_user: User = Depends(require_project_access),
    db: AsyncSession = ...,
):
    """Create a new finding after scanner analysis."""
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
    
    # Check for duplicate finding using fingerprint
    # Compute fingerprint from appropriate normalized attributes
    fingerprint = finding_data.fingerprint
    if not fingerprint:
        # Generate stable fingerprint from project + asset + template + endpoint + evidence
        fingerprint_components = [project_id]
        if finding_data.asset_id:
            fingerprint.append(finding_data.asset_id)
        if finding_data.template_id:
            fingerprint.append(finding_data.template_id)
        if finding_data.endpoint:
            fingerprint.append(finding_data.endpoint)
        if finding_data.evidence:
            fingerprint.append(str(finding_data.evidence)[:200])  # Truncate for fingerprint
        
        fingerprint_input = "|".join(fingerprint)
        import hashlib
        fingerprint = hashlib.sha256(fingerprint_input.encode()).hexdigest()[:64]
    
    # Check for existing finding with same fingerprint
    result = await db.execute(
        select(Finding).filter(
            Finding.project_id == project_id,
            Finding.fingerprint == fingerprint,
        )
    )
    existing = result.scalar_one_or_none()
    
    if existing:
        # Update existing finding instead of creating duplicate
        existing.last_seen = datetime.utcnow()
        if existing.status in ("new", "confirmed") and finding_data.status == "confirmed":
            existing.status = "confirmed"
        if existing.status == "resolved" and finding_data.status == "reopened":
            existing.status = "reopened"
            # Create a finding event for regression
            event = FindingEvent(
                finding_id=existing.id,
                event_type="reopened",
                notes=f"Finding reopened - regression detected",
                changed_by=current_user.id,
            )
            db.add(event)
        elif existing.status in ("new", "confirmed") and finding_data.status == "false_positive":
            existing.status = "false_positive"
        
        existing.last_seen = datetime.utcnow()
        await db.commit()
        await db.refresh(existing)
        
        # Log the deduplication
        await structured_log(
            event="finding_deduplicated",
            project_id=project_id,
            finding_id=existing.id,
            existing_fingerprint=fingerprint,
            user_id=current_user.id,
            level="INFO",
        )
        
        return existing
    
    # Create the new finding
    finding = Finding(
        title=finding_data.title,
        template_id=finding_data.template_id,
        category=finding_data.category,
        severity=finding_data.severity,
        confidence=finding_data.confidence,
        priority=finding_data.priority,
        endpoint=finding_data.endpoint,
        evidence=finding_data.evidence,
        description=finding_data.description,
        impact=finding_data.impact,
        remediation=finding_data.remediation,
        fingerprint=fingerprint,
        project_id=project_id,
        asset_id=finding_data.asset_id,
        status=finding_data.status or "new",
    )
    
    db.add(finding)
    await db.commit()
    await db.refresh(finding)
    
    # Create finding event for initial state
    event = FindingEvent(
        finding_id=finding.id,
        event_type="new",
        notes="Finding created from scanner analysis",
        changed_by=current_user.id,
    )
    db.add(event)
    
    await db.commit()
    
    # Log the action
    await structured_log(
        event="finding_created",
        project_id=project_id,
        finding_id=finding.id,
        fingerprint=fingerprint,
        user_id=current_user.id,
        level="INFO",
    )
    
    return finding


@router.get("", response_model=List[FindingSummary])
async def list_findings(
    project_id: str,
    current_user: User = Depends(require_project_access),
    db: AsyncSession = ...,
    status_filter: Optional[str] = None,
    category: Optional[str] = None,
    severity: Optional[str] = None,
):
    """List findings for a project with optional filtering."""
    # Verify project exists and user has access
    project = await db.get(Project, project_id)
    if not project:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Project not found",
        )
    
    query = select(Finding).filter(Finding.project_id == project_id)
    
    # Apply filters
    if status_filter:
        query = query.filter(Finding.status == status_filter)
    
    if category:
        query = query.filter(Finding.category == category)
    
    if severity:
        query = query.filter(Finding.severity == severity)
    
    # Order by priority and severity
    query = query.order_by(Finding.priority.desc(), Finding.severity.desc())
    
    result = await db.execute(query)
    findings = result.scalars().all()
    
    # Convert to summary format
    summaries = []
    for f in findings:
        # Get asset hostname for summary
        asset_hostname = ""
        if f.asset:
            asset_hostname = f.asset.hostname
        
        summaries.append(FindingSummary(
            id=f.id,
            title=f.title,
            severity=f.severity,
            confidence=f.confidence,
            priority=f.priority,
            status=f.status,
            asset_hostname=asset_hostname,
            first_seen=f.first_seen,
            last_seen=f.last_seen,
        ))
    
    return summaries


@router.get("/{finding_id}", response_model=FindingDB)
async def get_finding(
    finding_id: str,
    project_id: str,
    current_user: User = Depends(require_project_access),
    db: AsyncSession = ...,
):
    """Get a specific finding by ID."""
    # Verify project exists and user has access
    project = await db.get(Project, project_id)
    if not project:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Project not found",
        )
    
    result = await db.execute(
        select(Finding).filter(
            Finding.id == finding_id,
            Finding.project_id == project_id,
        )
    )
    finding = result.scalar_one_or_none()
    
    if not finding:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Finding not found",
        )
    
    return finding


@router.post("/{finding_id}/update-status", response_model=FindingDB)
async def update_finding_status(
    finding_id: str,
    project_id: str,
    status: str,
    current_user: User = Depends(require_project_access),
    db: AsyncSession = ...,
):
    """Update a finding's status."""
    # Verify project exists and user has access
    project = await db.get(Project, project_id)
    if not project:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Project not found",
        )
    
    # Valid statuses
    valid_statuses = ["new", "confirmed", "false_positive", "accepted", "resolved", "reopened"]
    if status not in valid_statuses:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid status. Must be one of: {', '.join(valid_statuses)}",
        )
    
    # Get the finding
    result = await db.execute(
        select(Finding).filter(
            Finding.id == finding_id,
            Finding.project_id == project_id,
        )
    )
    finding = result.scalar_one_or_none()
    
    if not finding:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Finding not found",
        )
    
    # Track status change for deduplication
    old_status = finding.status
    finding.status = status
    
    # Create finding event
    event = FindingEvent(
        finding_id=finding.id,
        event_type=status,
        notes=f"Status changed from {old_status} to {status} by user",
        changed_by=current_user.id,
    )
    db.add(event)
    
    # Handle special status logic
    if status == "resolved" and old_status != "resolved":
        # Finding resolved - log it
        pass
    elif status == "reopened" and old_status == "resolved":
        # Regression - finding was resolved but appeared again
        pass
    elif status == "false_positive":
        # Mark as false positive
        pass
    
    finding.last_seen = datetime.utcnow()
    
    await db.commit()
    await db.refresh(finding)
    
    # Log the action
    await structured_log(
        event="finding_status_updated",
        project_id=project_id,
        finding_id=finding.id,
        old_status=old_status,
        new_status=status,
        user_id=current_user.id,
        level="INFO",
    )
    
    return finding