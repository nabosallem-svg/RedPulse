"""RedPulse - Reporting API Endpoints.

Phase 6: Report generation and download endpoints.

GET  /api/v1/reports/{project_id}/summary       — Project summary
GET  /api/v1/reports/{project_id}/export         — Export report (json/csv/html)
GET  /api/v1/reports/{project_id}/findings       — List findings with filters
"""

import json
import logging
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from fastapi.responses import Response, StreamingResponse
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_db, get_current_user
from app.db.models import (
    User, Project, Engagement, FindingSeverity,
)
from app.services.report_service import ReportService

logger = logging.getLogger("redpulse.api.reports")

router = APIRouter(tags=["reports"])


@router.get("/{project_id}/summary")
async def get_report_summary(
    project_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Get project-level report summary with severity breakdown.

    Returns total findings, severity distribution, and high-severity count.
    """
    # Verify project access
    project = await _verify_project_access(db, project_id, current_user.id)

    service = ReportService(db)
    summary = await service.get_project_summary(project_id)

    return {
        "success": True,
        "data": summary,
    }


@router.get("/{project_id}/export")
async def export_report(
    project_id: str,
    request: Request,
    format: str = Query("json", description="Export format: json, csv, html"),
    engagement_id: Optional[str] = Query(None, description="Filter by engagement ID"),
    min_severity: str = Query("high", description="Minimum severity: critical, high, medium, low, info"),
    platform: Optional[str] = Query(None, description="Bounty platform: hackerone, bugcrowd (JSON only)"),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Export findings as a downloadable report.

    Supported formats:
    - **json**: Structured JSON report (default). If `platform` is set, outputs
      HackerOne or Bugcrowd compatible format.
    - **csv**: CSV spreadsheet with PoC curl commands and reproduction steps.
    - **html**: Printable HTML report with PoC evidence and styling.
    """
    # Verify project access
    project = await _verify_project_access(db, project_id, current_user.id)

    # Parse min_severity
    severity_map = {
        "critical": FindingSeverity.CRITICAL,
        "high": FindingSeverity.HIGH,
        "medium": FindingSeverity.MEDIUM,
        "low": FindingSeverity.LOW,
        "info": FindingSeverity.INFO,
    }
    min_sev = severity_map.get(min_severity.lower())
    if not min_sev:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid min_severity: {min_severity}. Must be one of: critical, high, medium, low, info",
        )

    service = ReportService(db)

    # Audit export before generating (best-effort)
    try:
        from app.services.audit_service import AuditService as _AS2
        ws_id = project.workspace_id if hasattr(project, "workspace_id") else None
        await _AS2.log_export(
            db, project_id=project_id, workspace_id=ws_id,
            user_id=current_user.id, export_format=format.lower(),
            request=request,
        )
        # Dispatch webhook event
        if ws_id:
            try:
                from app.services.custom_webhook_service import CustomWebhookService as _CW2
                await _CW2.dispatch(db, ws_id, "export.created", {"project_id": project_id, "format": format.lower(), "min_severity": min_severity, "via": "jwt"})
            except Exception:
                pass
    except Exception:
        pass

    if format.lower() == "json":
        json_str = await service.export_json(
            project_id, engagement_id, min_sev, platform=platform or "hackerone"
        )
        return Response(
            content=json_str,
            media_type="application/json",
            headers={
                "Content-Disposition": f'attachment; filename="redpulse-report-{project_id[:8]}.json"'
            },
        )

    elif format.lower() == "csv":
        csv_str = await service.export_csv(project_id, engagement_id, min_sev)
        return Response(
            content=csv_str,
            media_type="text/csv",
            headers={
                "Content-Disposition": f'attachment; filename="redpulse-report-{project_id[:8]}.csv"'
            },
        )

    elif format.lower() == "html":
        html_str = await service.export_html(project_id, engagement_id, min_sev)
        return Response(
            content=html_str,
            media_type="text/html",
            headers={
                "Content-Disposition": f'attachment; filename="redpulse-report-{project_id[:8]}.html"'
            },
        )

    else:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Unsupported format: {format}. Must be one of: json, csv, html",
        )


@router.get("/{project_id}/findings")
async def list_findings(
    project_id: str,
    engagement_id: Optional[str] = Query(None, description="Filter by engagement ID"),
    min_severity: str = Query("info", description="Minimum severity filter"),
    include_resolved: bool = Query(False, description="Include resolved findings"),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """List findings for a project with filtering options.

    Returns findings sorted by severity (critical first).
    """
    # Verify project access
    project = await _verify_project_access(db, project_id, current_user.id)

    severity_map = {
        "critical": FindingSeverity.CRITICAL,
        "high": FindingSeverity.HIGH,
        "medium": FindingSeverity.MEDIUM,
        "low": FindingSeverity.LOW,
        "info": FindingSeverity.INFO,
    }
    min_sev = severity_map.get(min_severity.lower(), FindingSeverity.INFO)

    service = ReportService(db)
    findings = await service.get_findings_for_project(
        project_id, engagement_id, min_sev, include_resolved
    )

    from app.services.report_service import _finding_to_dict

    return {
        "success": True,
        "data": {
            "project_id": project_id,
            "findings_count": len(findings),
            "findings": [_finding_to_dict(f) for f in findings],
        },
    }


async def _verify_project_access(db: AsyncSession, project_id: str, user_id: str) -> Project:
    """Verify user has access to the project. Raises 404 if not found."""
    result = await db.execute(
        select(Project).where(
            Project.id == project_id,
            Project.owner_id == user_id,
        )
    )
    project = result.scalar_one_or_none()
    if not project:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Project not found or access denied",
        )
    return project
