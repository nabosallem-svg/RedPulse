from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from typing import List, Optional

from app.api.deps import get_db, get_current_user
from app.services.vuln_scanner import VulnScanner
from app.schemas import EngagementSchema as Engagement

router = APIRouter(tags=["vulnerability"])


@router.post("/scan", response_model=dict)
async def start_vuln_scan(
    engagement_id: str,
    targets: List[str],
    template_path: Optional[str] = None,
    request: Request = None,
    db: AsyncSession = Depends(get_db),
    current_user = Depends(get_current_user),
) -> dict:
    """Start a Nuclei-based vulnerability scan for an engagement.

    Validates scope for all targets, runs nuclei templates,
    returns findings with severity filtering.
    """
    scanner = VulnScanner(db=db, current_user=current_user, engagement_id=engagement_id)
    result = await scanner.start_scan_job(targets=targets, template_path=template_path)

    # Audit log (best-effort)
    try:
        from app.services.audit_service import AuditService
        from app.db.models import Engagement, Project
        eng_q = await db.execute(select(Engagement).where(Engagement.id == engagement_id))
        eng = eng_q.scalar_one_or_none()
        proj = None
        ws_id = None
        proj_id = None
        if eng:
            proj_q = await db.execute(select(Project).where(Project.id == eng.project_id))
            proj = proj_q.scalar_one_or_none()
            ws_id = proj.workspace_id if proj else None
            proj_id = proj.id if proj else None
        await AuditService.log(
            db, action="scan.create", resource_type="scan",
            user_id=getattr(current_user, "id", None), workspace_id=ws_id, project_id=proj_id,
            details={"targets": targets[:5], "count": len(targets), "template": template_path, "engagement_id": engagement_id},
            request=request,
        )
    except Exception:
        pass

    return result


@router.post("/scan-single", response_model=dict)
async def scan_single_target(
    engagement_id: str,
    target: str,
    template_path: Optional[str] = None,
    db: AsyncSession = Depends(get_db),
    current_user = Depends(get_current_user),
) -> dict:
    """Scan a single target with Nuclei.

    Useful for quick manual verification of a specific host.
    """
    scanner = VulnScanner(db=db, current_user=current_user, engagement_id=engagement_id)
    findings = await scanner.scan_targets([target], template_path=template_path)
    return {
        "target": target,
        "findings": findings,
        "findings_count": len(findings),
    }


@router.post("/scope-check", response_model=dict)
async def check_target_scope(
    engagement_id: str,
    target: str,
    db: AsyncSession = Depends(get_db),
    current_user = Depends(get_current_user),
) -> dict:
    """Check if a target belongs to the engagement's in-scope scope.

    Returns validation result without performing a full scan.
    """
    from app.services.recon_engine import ReconEngine

    try:
        await ReconEngine._validate_target_static(
            engagement_id=engagement_id,
            host_or_url=target,
            db=db,
            current_user=current_user,
        )
        return {"target": target, "in_scope": True, "detail": "Target is in scope"}
    except Exception as e:
        return {"target": target, "in_scope": False, "detail": str(e)}


@router.post("/templates/list", response_model=dict)
async def list_nuclei_templates(
    db: AsyncSession = Depends(get_db),
    current_user = Depends(get_current_user),
) -> dict:
    """List available Nuclei templates (placeholder).

    In production would scan the templates directory and return
    available check IDs and severity levels.
    """
    import os

    template_dirs = []
    if os.path.exists("nuclei-templates"):
        template_dirs.append("nuclei-templates")
    if os.path.exists("/etc/nuclei/templates"):
        template_dirs.append("/etc/nuclei/templates")

    return {
        "template_dirs": template_dirs,
        "note": "Template listing - configure Nuclei paths in .env",
    }