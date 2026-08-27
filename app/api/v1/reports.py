"""RedPulse - Reports API Routes.

Report generation and quality checking.
"""

from fastapi import APIRouter, Depends, HTTPException, status, BackgroundTasks
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from typing import List, Optional

from app.schemas.reports import (
    ReportCreate, ReportDB, ReportQualityCheck, ReportQualityResponse,
    ReportStatus, ReportFormat
)
from app.models import Project, Report
from app.core.security import require_project_access
from app.config import get_settings
from app.core.logging import structured_log

router = APIRouter(prefix="/{project_id}/reports", tags=["reports"])


@router.post(
    "", response_model=ReportDB,
    status_code=status.HTTP_201_CREATED,
)
async def create_report(
    report_data: ReportCreate,
    project_id: str,
    current_user: User = Depends(require_project_access),
    db: AsyncSession = ...,
):
    """Create a new report draft for a project."""
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
    
    # Check for existing draft report
    result = await db.execute(
        select(Report).filter(
            Report.project_id == project_id,
            Report.status == ReportStatus.DRAFT,
        )
    )
    existing = result.scalar_one_or_none()
    if existing:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="A draft report already exists for this project",
        )
    
    # Create the report
    report = Report(
        title=report_data.title,
        description=report_data.description,
        format=report_data.format,
        project_id=project_id,
        status=ReportStatus.DRAFT,
        generated_by=current_user.id,
    )
    
    db.add(report)
    await db.commit()
    await db.refresh(report)
    
    # Log the action
    await structured_log(
        event="report_created",
        project_id=project_id,
        report_id=report.id,
        user_id=current_user.id,
        level="INFO",
    )
    
    return report


@router.get("", response_model=List[ReportDB])
async def list_reports(
    project_id: str,
    current_user: User = Depends(require_project_access),
    db: AsyncSession = ...,
    status_filter: Optional[str] = None,
):
    """List reports for a project."""
    # Verify project exists and user has access
    project = await db.get(Project, project_id)
    if not project:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Project not found",
        )
    
    query = select(Report).filter(Report.project_id == project_id)
    
    if status_filter:
        from app.schemas.reports import ReportStatus
        query = query.filter(Report.status == status_filter)
    
    result = await db.execute(query)
    reports = result.scalars().all()
    
    return reports


@router.get("/{report_id}", response_model=ReportDB)
async def get_report(
    report_id: str,
    project_id: str,
    current_user: User = Depends(require_project_access),
    db: AsyncSession = ...,
):
    """Get a specific report by ID."""
    # Verify project exists and user has access
    project = await db.get(Project, project_id)
    if not project:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Project not found",
        )
    
    result = await db.execute(
        select(Report).filter(
            Report.id == report_id,
            Report.project_id == project_id,
        )
    )
    report = result.scalar_one_or_none()
    
    if not report:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Report not found",
        )
    
    return report


@router.post("/{report_id}/quality-check", response_model=ReportQualityResponse)
async def check_report_quality(
    report_id: str,
    project_id: str,
    current_user: User = Depends(require_project_access),
    db: AsyncSession = ...,
):
    """Run quality checker on a report."""
    # Verify project exists and user has access
    project = await db.get(Project, project_id)
    if not project:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Project not found",
        )
    
    # Get the report
    result = await db.execute(
        select(Report).filter(
            Report.id == report_id,
            Report.project_id == project_id,
        )
    )
    report = result.scalar_one_or_none()
    
    if not report:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Report not found",
        )
    
    # Run quality checks
    checks: Dict[str, bool] = {
        "affected_asset": False,
        "clear_title": bool(report.title and report.title.strip()),
        "evidence": False,
        "reproduction_guidance": False,
        "impact": False,
        "remediation": False,
    }
    
    # Check affected asset - look at associated findings
    from app.models import Finding
    finding_result = await db.execute(
        select(Finding).filter(Finding.project_id == project_id)
    )
    findings = finding_result.scalars().all()
    
    if findings:
        checks["affected_asset"] = True
    
    # Check clear title
    checks["clear_title"] = bool(report.title and report.title.strip())
    
    # Check evidence - look at findings evidence
    if findings:
        has_evidence = any(f.evidence for f in findings if f.evidence)
        checks["evidence"] = has_evidence
    
    # Check reproduction guidance
    # This would be populated when report is generated
    checks["reproduction_guidance"] = False  # Placeholder
    
    # Check impact
    if findings:
        has_impact = any(f.impact for f in findings if f.impact)
        checks["impact"] = has_impact
    
    # Check remediation
    if findings:
        has_remediation = any(f.remediation for f in findings if f.remediation)
        checks["remediation"] = has_remediation
    
    # Calculate score
    score = sum(1 for v in checks.values() if v) * 20  # 6 checks * 20 = 100 max, but we have 6 so max 120 -> cap at 100
    actual_score = min(score, 100)
    
    # Find missing sections
    missing = [k for k, v in checks.items() if not v]
    
    # Generate recommendations
    recommendations = []
    if not checks["affected_asset"]:
        recommendations.append("Add affected asset identification")
    if not checks["clear_title"]:
        recommendations.append("Ensure report has a clear, descriptive title")
    if not checks["evidence"]:
        recommendations.append("Include evidence supporting findings")
    if not checks["reproduction_guidance"]:
        recommendations.append("Add reproduction guidance steps")
    if not checks["impact"]:
        recommendations.append("Include impact analysis")
    if not checks["remediation"]:
        recommendations.append("Include remediation steps")
    
    quality_check = ReportQualityCheck(
        score=actual_score,
        checks=checks,
        missing_sections=missing,
    )
    
    response = ReportQualityResponse(
        report_id=report.id,
        quality=quality_check,
        recommendations=recommendations,
    )
    
    # Log the action
    await structured_log(
        event="report_quality_checked",
        project_id=project_id,
        report_id=report.id,
        quality_score=actual_score,
        user_id=current_user.id,
        level="INFO",
    )
    
    return response