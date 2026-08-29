"""RedPulse - Public API (API Key Auth).

Provides external integrations with stable, versioned endpoints
authenticated via X-API-Key header. Respects workspace scoping
and scope checks.

Endpoints:
- GET /api/v1/public/projects           (scan:read / read)
- GET /api/v1/public/projects/{id}
- POST /api/v1/public/scans             (scan:create)
- GET /api/v1/public/scans/{id}
- GET /api/v1/public/findings           (finding:read)
- POST /api/v1/public/exports           (report:export / finding:export)
"""
from __future__ import annotations

import logging
from typing import Optional, List

from fastapi import APIRouter, Depends, HTTPException, Request, Query, status
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps_api_key import get_api_key, get_api_key_user, require_api_key_scope
from app.api.deps import get_db
from app.db.models import ApiKey, User, Project, Finding, VulnerabilityScan
from app.services.audit_service import AuditService
from app.services.custom_webhook_service import CustomWebhookService

logger = logging.getLogger(__name__)
router = APIRouter(tags=["public-api"])


class PublicScanCreate(BaseModel):
    project_id: Optional[str] = Field(default=None, description="Project ID for scan (optional if workspace-bound key)")
    engagement_id: Optional[str] = Field(default=None)
    target: str = Field(..., max_length=500)
    profile: str = Field(default="standard", pattern="^(quick|standard|deep)$")
    engagement_name: Optional[str] = None


class PublicExportCreate(BaseModel):
    project_id: str = Field(..., max_length=36)
    format: str = Field(..., pattern="^(json|csv|html|pdf)$", description="Export format")
    min_severity: Optional[str] = Field(default=None, pattern="^(critical|high|medium|low|info)$")


@router.get("/projects")
async def public_list_projects(
    api_key: ApiKey = Depends(require_api_key_scope("read")),
    user: User = Depends(get_api_key_user),
    db: AsyncSession = Depends(get_db),
):
    """List projects accessible to the API key's user (and workspace if bound)."""
    # If key is workspace-bound, only return projects in that workspace
    q = select(Project).where(Project.owner_id == user.id)
    if api_key.workspace_id:
        q = q.where(Project.workspace_id == api_key.workspace_id)
    q = q.order_by(Project.created_at.desc()).limit(100)
    result = await db.execute(q)
    projects = result.scalars().all()

    # Lightweight audit for API key usage
    try:
        await AuditService.log(
            db, action="api_key.use", resource_type="project", user_id=user.id,
            api_key_id=api_key.id, workspace_id=api_key.workspace_id,
            details={"endpoint": "public_list_projects", "count": len(projects)},
        )
    except Exception:
        pass

    return {
        "success": True,
        "data": [
            {"id": p.id, "name": p.name, "status": p.status.value if hasattr(p.status, "value") else str(p.status), "workspace_id": p.workspace_id, "created_at": p.created_at.isoformat() if p.created_at else None}
            for p in projects
        ],
    }


@router.get("/projects/{project_id}")
async def public_get_project(
    project_id: str,
    api_key: ApiKey = Depends(require_api_key_scope("read")),
    user: User = Depends(get_api_key_user),
    db: AsyncSession = Depends(get_db),
):
    """Get a single project (owner check + workspace binding)."""
    result = await db.execute(select(Project).where(Project.id == project_id))
    project = result.scalar_one_or_none()
    if not project or str(project.owner_id) != str(user.id):
        raise HTTPException(status_code=404, detail="Project not found")

    if api_key.workspace_id and str(project.workspace_id) != str(api_key.workspace_id):
        raise HTTPException(status_code=403, detail="Project not in API key's workspace scope")

    return {
        "success": True,
        "data": {
            "id": project.id,
            "name": project.name,
            "description": project.description,
            "status": project.status.value if hasattr(project.status, "value") else str(project.status),
            "workspace_id": project.workspace_id,
            "created_at": project.created_at.isoformat() if project.created_at else None,
        },
    }


@router.get("/findings")
async def public_list_findings(
    project_id: Optional[str] = Query(default=None),
    severity: Optional[str] = Query(default=None, pattern="^(critical|high|medium|low|info)$"),
    limit: int = Query(default=20, ge=1, le=100),
    api_key: ApiKey = Depends(require_api_key_scope("finding:read")),
    user: User = Depends(get_api_key_user),
    db: AsyncSession = Depends(get_db),
):
    """List findings (supports API key scope finding:read or admin/write)."""
    # Must own project if project_id given
    if project_id:
        result = await db.execute(select(Project).where(Project.id == project_id))
        project = result.scalar_one_or_none()
        if not project or str(project.owner_id) != str(user.id):
            raise HTTPException(status_code=404, detail="Project not found")
        if api_key.workspace_id and str(project.workspace_id) != str(api_key.workspace_id):
            raise HTTPException(status_code=403, detail="Project not in workspace scope")

        q = select(Finding).where(Finding.project_id == project_id)
    else:
        # List all findings across owned projects (respect workspace binding)
        proj_q = select(Project.id).where(Project.owner_id == user.id)
        if api_key.workspace_id:
            proj_q = proj_q.where(Project.workspace_id == api_key.workspace_id)
        proj_result = await db.execute(proj_q)
        proj_ids = [r[0] for r in proj_result.all()]
        if not proj_ids:
            return {"success": True, "data": [], "meta": {"total": 0}}
        q = select(Finding).where(Finding.project_id.in_(proj_ids))

    if severity:
        q = q.where(Finding.severity == severity)  # type: ignore

    q = q.order_by(Finding.created_at.desc()).limit(limit)
    result = await db.execute(q)
    findings = result.scalars().all()

    return {
        "success": True,
        "data": [
            {
                "id": f.id,
                "title": f.title,
                "severity": f.severity.value if hasattr(f.severity, "value") else str(f.severity),
                "project_id": f.project_id,
                "status": f.status.value if hasattr(f.status, "value") else str(f.status),
                "endpoint": f.endpoint,
                "created_at": f.created_at.isoformat() if f.created_at else None,
            }
            for f in findings
        ],
        "meta": {"count": len(findings)},
    }


@router.post("/scans", status_code=status.HTTP_201_CREATED)
async def public_create_scan(
    data: PublicScanCreate,
    request: Request,
    api_key: ApiKey = Depends(require_api_key_scope("scan:create")),
    user: User = Depends(get_api_key_user),
    db: AsyncSession = Depends(get_db),
):
    """Create a scan via Public API (requires scan:create scope).

    For MVP, this creates a VulnerabilityScan record and audits the event.
    Does NOT run the actual scanner inline - suitable for async triggering.
    """
    # Determine project/engagement context
    # If project_id provided, verify ownership
    workspace_id = api_key.workspace_id
    project_id = data.project_id

    if project_id:
        result = await db.execute(select(Project).where(Project.id == project_id))
        project = result.scalar_one_or_none()
        if not project or str(project.owner_id) != str(user.id):
            raise HTTPException(status_code=404, detail="Project not found")
        if workspace_id and str(project.workspace_id) != str(workspace_id):
            raise HTTPException(status_code=403, detail="Project not in workspace scope")
        workspace_id = project.workspace_id  # use project's workspace
        # Need an engagement - create or pick first
        from app.db.models import Engagement
        eng_q = await db.execute(select(Engagement).where(Engagement.project_id == project_id).limit(1))
        engagement = eng_q.scalar_one_or_none()
        if not engagement:
            raise HTTPException(status_code=400, detail="Project has no engagement - create one via UI/API first")
        engagement_id = engagement.id
    elif data.engagement_id:
        from app.db.models import Engagement
        result = await db.execute(select(Engagement).where(Engagement.id == data.engagement_id))
        engagement = result.scalar_one_or_none()
        if not engagement:
            raise HTTPException(status_code=404, detail="Engagement not found")
        # Verify ownership via project
        proj_q = await db.execute(select(Project).where(Project.id == engagement.project_id))
        proj = proj_q.scalar_one_or_none()
        if not proj or str(proj.owner_id) != str(user.id):
            raise HTTPException(status_code=403, detail="Access denied to engagement")
        if workspace_id and proj.workspace_id and str(proj.workspace_id) != str(workspace_id):
            raise HTTPException(status_code=403, detail="Engagement not in workspace scope")
        engagement_id = engagement.id
        project_id = proj.id
        workspace_id = proj.workspace_id
    else:
        raise HTTPException(status_code=400, detail="Either project_id or engagement_id is required")

    # Create scan record
    scan = VulnerabilityScan(
        engagement_id=engagement_id,
        user_id=user.id,
        target=data.target,
        status="pending",
    )
    db.add(scan)
    await db.commit()
    await db.refresh(scan)

    # Audit log: scan creation via Public API
    try:
        await AuditService.log_scan(
            db, scan_id=scan.id, project_id=project_id, workspace_id=workspace_id,
            user_id=user.id, api_key_id=api_key.id, target=data.target, profile=data.profile,
            request=request, status="success",
        )
        # Also generic public API audit
        await AuditService.log(
            db, action="scan.create", resource_type="scan", resource_id=scan.id,
            user_id=user.id, api_key_id=api_key.id, workspace_id=workspace_id, project_id=project_id,
            details={"target": data.target, "profile": data.profile, "via": "public_api"},
            request=request,
        )
    except Exception:
        pass

    # Dispatch webhook event if workspace-bound
    if workspace_id:
        try:
            await CustomWebhookService.dispatch(
                db, workspace_id, "scan.started",
                {"scan_id": scan.id, "project_id": project_id, "target": data.target, "profile": data.profile, "via": "public_api"},
            )
        except Exception:
            pass

    return {
        "success": True,
        "data": {
            "id": scan.id,
            "engagement_id": engagement_id,
            "project_id": project_id,
            "target": scan.target,
            "status": str(scan.status.value if hasattr(scan.status, "value") else scan.status),
            "created_at": scan.created_at.isoformat() if scan.created_at else None,
        },
    }


@router.get("/scans/{scan_id}")
async def public_get_scan(
    scan_id: str,
    api_key: ApiKey = Depends(require_api_key_scope("scan:read")),
    user: User = Depends(get_api_key_user),
    db: AsyncSession = Depends(get_db),
):
    """Get scan status (requires scan:read)."""
    result = await db.execute(select(VulnerabilityScan).where(VulnerabilityScan.id == scan_id))
    scan = result.scalar_one_or_none()
    if not scan or str(scan.user_id) != str(user.id):
        raise HTTPException(status_code=404, detail="Scan not found")

    return {
        "success": True,
        "data": {
            "id": scan.id,
            "engagement_id": scan.engagement_id,
            "target": scan.target,
            "status": str(scan.status.value if hasattr(scan.status, "value") else scan.status),
            "created_at": scan.created_at.isoformat() if scan.created_at else None,
            "completed_at": scan.completed_at.isoformat() if scan.completed_at else None,
        },
    }


@router.post("/exports")
async def public_create_export(
    data: PublicExportCreate,
    request: Request,
    api_key: ApiKey = Depends(require_api_key_scope("finding:export")),
    user: User = Depends(get_api_key_user),
    db: AsyncSession = Depends(get_db),
):
    """Trigger an export via Public API (requires finding:export or report:export or write/admin).

    Returns findings in requested format metadata and audits the export.
    """
    # Verify project ownership
    result = await db.execute(select(Project).where(Project.id == data.project_id))
    project = result.scalar_one_or_none()
    if not project or str(project.owner_id) != str(user.id):
        raise HTTPException(status_code=404, detail="Project not found")

    workspace_id = project.workspace_id
    if api_key.workspace_id and str(workspace_id) != str(api_key.workspace_id):
        raise HTTPException(status_code=403, detail="Project not in workspace scope")

    # Fetch findings count for audit
    cnt_q = await db.execute(select(Finding).where(Finding.project_id == data.project_id))
    findings = cnt_q.scalars().all()

    # Scope filter by severity if requested
    if data.min_severity:
        # Simple filter: include that severity and higher
        severity_order = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
        min_rank = severity_order.get(data.min_severity.lower(), 0)
        findings = [f for f in findings if severity_order.get(str(f.severity.value if hasattr(f.severity, "value") else f.severity).lower(), 0) >= min_rank]

    # Audit export
    try:
        await AuditService.log_export(
            db, project_id=data.project_id, workspace_id=workspace_id,
            user_id=user.id, api_key_id=api_key.id, export_format=data.format,
            count=len(findings), request=request,
        )
        await AuditService.log(
            db, action=f"export.{data.format}", resource_type="export",
            user_id=user.id, api_key_id=api_key.id, workspace_id=workspace_id, project_id=data.project_id,
            details={"format": data.format, "count": len(findings), "min_severity": data.min_severity, "via": "public_api"},
            request=request,
        )
    except Exception:
        pass

    # Dispatch webhook
    if workspace_id:
        try:
            await CustomWebhookService.dispatch(
                db, workspace_id, "export.created",
                {"project_id": data.project_id, "format": data.format, "count": len(findings), "via": "public_api"},
            )
        except Exception:
            pass

    return {
        "success": True,
        "data": {
            "project_id": data.project_id,
            "format": data.format,
            "findings_count": len(findings),
            "download_url": f"/api/v1/projects/{data.project_id}/exports?format={data.format}",
            "message": f"Export prepared for {len(findings)} findings in {data.format} format",
        },
    }
