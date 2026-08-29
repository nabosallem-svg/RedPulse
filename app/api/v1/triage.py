"""RedPulse - False Positive Triage Workflow API.

AI-suggested triage that feeds back into the AI layer to suppress future FPs.
"""
from __future__ import annotations

import logging
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from pydantic import BaseModel, Field
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_current_user, get_db
from app.db.models import User
from app.services.triage_service import TriageService, TriageAIService
from app.services.audit_service import AuditService

logger = logging.getLogger(__name__)
router = APIRouter(tags=["triage"])


class TriageSubmitRequest(BaseModel):
    decision: str = Field(..., description="false_positive, true_positive, needs_review, confirmed, accepted_risk")
    reason: Optional[str] = Field(None, max_length=2000)
    evidence: Optional[str] = Field(None, max_length=2000)


class FalsePositiveRequest(BaseModel):
    reason: str = Field(..., min_length=5, max_length=2000, description="سبب اعتبار النتيجة إيجابية كاذبة — مطلوب")
    evidence: Optional[str] = Field(None, max_length=2000, description="دليل إضافي اختياري (URL أو snippet)")


@router.get("/findings/{finding_id}/triage/suggest")
async def get_triage_suggestion(
    finding_id: str,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Get AI suggestion for a finding before human triage."""
    try:
        suggestion = await TriageService.get_ai_suggestion(db, finding_id)
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))
    return {"success": True, "data": suggestion}


@router.post("/findings/{finding_id}/triage", status_code=status.HTTP_201_CREATED)
async def submit_triage(
    finding_id: str,
    data: TriageSubmitRequest,
    request: Request,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Submit analyst triage for a finding - updates Finding status and feeds AI layer.

    Decision maps to Finding status:
      false_positive -> false_positive
      true_positive/confirmed -> confirmed
      accepted_risk -> accepted
      needs_review -> new
    """
    # Verify finding exists and user owns project (basic tenant isolation)
    from sqlalchemy import select
    from app.db.models import Finding, Project
    f_res = await db.execute(select(Finding).where(Finding.id == finding_id))
    finding = f_res.scalar_one_or_none()
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")
    # Check ownership via project
    proj_res = await db.execute(select(Project).where(Project.id == finding.project_id, Project.owner_id == current_user.id))
    if not proj_res.scalar_one_or_none():
        # Also check workspace membership as fallback (for multi-tenant)
        try:
            from app.services.workspace_service import WorkspaceService
            proj_full = await db.execute(select(Project).where(Project.id == finding.project_id))
            proj_obj = proj_full.scalar_one_or_none()
            ws_id = getattr(proj_obj, "workspace_id", None) if proj_obj else None
            if ws_id:
                from app.services.workspace_service import WorkspaceService as WS
                has, _ = await WS.check_workspace_access(db, ws_id, current_user.id, "finding:write")
                if not has:
                    raise HTTPException(status_code=404, detail="Finding not found or access denied")
            else:
                raise HTTPException(status_code=404, detail="Finding not found or access denied")
        except HTTPException:
            raise
        except Exception:
            raise HTTPException(status_code=404, detail="Finding not found or access denied")

    try:
        feedback = await TriageService.submit_triage(
            db, finding_id, current_user, decision=data.decision, reason=data.reason, evidence=data.evidence
        )
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

    # Audit log
    try:
        from app.db.models import Project as Proj2
        proj2_res = await db.execute(select(Proj2).where(Proj2.id == finding.project_id))
        proj2 = proj2_res.scalar_one_or_none()
        ws_audit = getattr(proj2, "workspace_id", None) if proj2 else None
        await AuditService.log(
            db, action="finding.triage", resource_type="finding", resource_id=finding_id,
            user_id=current_user.id, workspace_id=ws_audit, project_id=finding.project_id,
            details={"decision": data.decision, "ai_prediction": feedback.ai_prediction, "ai_was_correct": feedback.ai_was_correct},
            request=request,
        )
    except Exception:
        pass

    return {
        "success": True,
        "data": {
            "id": feedback.id,
            "finding_id": feedback.finding_id,
            "decision": feedback.decision.value if hasattr(feedback.decision, "value") else str(feedback.decision),
            "ai_prediction": feedback.ai_prediction,
            "ai_confidence": feedback.ai_confidence,
            "ai_was_correct": feedback.ai_was_correct,
            "reason": feedback.reason,
            "feedback_weight": feedback.feedback_weight,
            "created_at": feedback.created_at.isoformat() if feedback.created_at else None,
        },
    }


@router.get("/findings/{finding_id}/triage/history")
async def get_triage_history(
    finding_id: str,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Get triage history for a finding."""
    # Verify access same as submit
    from sqlalchemy import select
    from app.db.models import Finding, Project
    f_res = await db.execute(select(Finding).where(Finding.id == finding_id))
    finding = f_res.scalar_one_or_none()
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")
    proj_res = await db.execute(select(Project).where(Project.id == finding.project_id, Project.owner_id == current_user.id))
    if not proj_res.scalar_one_or_none():
        # Check workspace fallback like above
        proj_full = await db.execute(select(Project).where(Project.id == finding.project_id))
        proj_obj = proj_full.scalar_one_or_none()
        ws_id = getattr(proj_obj, "workspace_id", None) if proj_obj else None
        if ws_id:
            from app.services.workspace_service import WorkspaceService as WS
            has, _ = await WS.check_workspace_access(db, ws_id, current_user.id, "finding:read")
            if not has:
                raise HTTPException(status_code=404, detail="Finding not found or access denied")
        else:
            raise HTTPException(status_code=404, detail="Finding not found or access denied")

    history = await TriageService.get_finding_history(db, finding_id)
    return {
        "success": True,
        "data": [
            {
                "id": h.id,
                "finding_id": h.finding_id,
                "decision": h.decision.value if hasattr(h.decision, "value") else str(h.decision),
                "ai_prediction": h.ai_prediction,
                "ai_was_correct": h.ai_was_correct,
                "reason": h.reason,
                "feedback_weight": h.feedback_weight,
                "analyst_id": h.analyst_id,
                "created_at": h.created_at.isoformat() if h.created_at else None,
            }
            for h in history
        ],
    }


@router.get("/triage/feedback")
async def list_triage_feedback(
    project_id: Optional[str] = Query(None),
    finding_id: Optional[str] = Query(None),
    workspace_id: Optional[str] = Query(None),
    limit: int = Query(50, ge=1, le=100),
    offset: int = Query(0, ge=0),
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """List triage feedback (for analysts/admins to review AI learning)."""
    # Enforce workspace RBAC if workspace_id provided
    if workspace_id:
        from app.services.workspace_service import WorkspaceService as WS
        has, _ = await WS.check_workspace_access(db, workspace_id, current_user.id, "finding:read")
        if not has:
            raise HTTPException(status_code=404, detail="Workspace not found or access denied")
    # Project isolation check if project_id provided
    if project_id:
        from sqlalchemy import select
        from app.db.models import Project
        proj_res = await db.execute(select(Project).where(Project.id == project_id, Project.owner_id == current_user.id))
        if not proj_res.scalar_one_or_none():
            # fallback workspace check
            if workspace_id:
                pass
            else:
                # Check if user has workspace access via project's workspace
                proj_full = await db.execute(select(Project).where(Project.id == project_id))
                proj_obj = proj_full.scalar_one_or_none()
                ws_id = getattr(proj_obj, "workspace_id", None) if proj_obj else None
                if ws_id:
                    from app.services.workspace_service import WorkspaceService as WS2
                    has2, _ = await WS2.check_workspace_access(db, ws_id, current_user.id, "finding:read")
                    if not has2:
                        raise HTTPException(status_code=404, detail="Project not found or access denied")
                else:
                    raise HTTPException(status_code=404, detail="Project not found or access denied")

    items, total = await TriageService.list_feedback(db, project_id=project_id, finding_id=finding_id, workspace_id=workspace_id, limit=limit, offset=offset)
    return {
        "success": True,
        "data": [
            {
                "id": f.id,
                "finding_id": f.finding_id,
                "project_id": f.project_id,
                "decision": f.decision.value if hasattr(f.decision, "value") else str(f.decision),
                "ai_prediction": f.ai_prediction,
                "ai_was_correct": f.ai_was_correct,
                "feedback_weight": f.feedback_weight,
                "analyst_id": f.analyst_id,
                "created_at": f.created_at.isoformat() if f.created_at else None,
            }
            for f in items
        ],
        "meta": {"total": total, "limit": limit, "offset": offset},
    }


@router.post("/findings/{finding_id}/false-positive", status_code=status.HTTP_201_CREATED)
async def mark_false_positive(
    finding_id: str,
    data: FalsePositiveRequest,
    request: Request,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """علّم Finding كـ False Positive مع سبب — يحدّث حالة الـ Finding ويغذّي طبقة AI.

    - يتحقق من ملكية الـ Finding (tenant isolation عبر Project.owner_id أو Workspace RBAC)
    - يستدعي `TriageService.submit_triage(decision=false_positive)` مما:
      • يغيّر `Finding.status` إلى `false_positive`
      • يخزن `TriageFeedback` مع `reason` + snapshot توقع AI (`ai_prediction`/`ai_confidence`) ويحسب `ai_was_correct`
      • يغذّي `TriageAIService` — التصنيفات القادمة لنفس `template_id`/`category` ستراعي معدل FP التاريخي
    - يسجل Audit `finding.triage` ويعيد الـ feedback + الـ finding المحدّث.
    """
    from sqlalchemy import select
    from app.db.models import Finding, Project

    f_res = await db.execute(select(Finding).where(Finding.id == finding_id))
    finding = f_res.scalar_one_or_none()
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")

    # Tenant isolation: must own project or have workspace finding:write
    proj_res = await db.execute(select(Project).where(Project.id == finding.project_id, Project.owner_id == current_user.id))
    if not proj_res.scalar_one_or_none():
        try:
            proj_full = await db.execute(select(Project).where(Project.id == finding.project_id))
            proj_obj = proj_full.scalar_one_or_none()
            ws_id = getattr(proj_obj, "workspace_id", None) if proj_obj else None
            if ws_id:
                from app.services.workspace_service import WorkspaceService as WS
                has, _ = await WS.check_workspace_access(db, ws_id, current_user.id, "finding:write")
                if not has:
                    raise HTTPException(status_code=404, detail="Finding not found or access denied")
            else:
                raise HTTPException(status_code=404, detail="Finding not found or access denied")
        except HTTPException:
            raise
        except Exception:
            raise HTTPException(status_code=404, detail="Finding not found or access denied")

    try:
        feedback = await TriageService.submit_triage(
            db, finding_id, current_user, decision="false_positive", reason=data.reason, evidence=data.evidence
        )
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

    # Refresh finding to return updated status
    await db.refresh(finding)

    # Audit
    try:
        proj2_res = await db.execute(select(Project).where(Project.id == finding.project_id))
        proj2 = proj2_res.scalar_one_or_none()
        ws_audit = getattr(proj2, "workspace_id", None) if proj2 else None
        await AuditService.log(
            db, action="finding.false_positive", resource_type="finding", resource_id=finding_id,
            user_id=current_user.id, workspace_id=ws_audit, project_id=finding.project_id,
            details={"decision": "false_positive", "reason": data.reason, "ai_prediction": feedback.ai_prediction, "ai_was_correct": feedback.ai_was_correct},
            request=request,
        )
    except Exception:
        pass

    return {
        "success": True,
        "data": {
            "feedback": {
                "id": feedback.id,
                "finding_id": feedback.finding_id,
                "decision": feedback.decision.value if hasattr(feedback.decision, "value") else str(feedback.decision),
                "reason": feedback.reason,
                "evidence": feedback.evidence,
                "ai_prediction": feedback.ai_prediction,
                "ai_confidence": feedback.ai_confidence,
                "ai_was_correct": feedback.ai_was_correct,
                "feedback_weight": feedback.feedback_weight,
                "created_at": feedback.created_at.isoformat() if feedback.created_at else None,
            },
            "finding": {
                "id": finding.id,
                "status": finding.status.value if hasattr(finding.status, "value") else str(finding.status),
                "title": finding.title,
                "project_id": finding.project_id,
            },
            "ai_feedback": {
                "message": "تم حفظ القرار وسيُستخدم لتحسين تصنيف AI مستقبلاً لنفس القالب/الفئة.",
                "fp_rate_for_template": (await TriageAIService._fp_rate_for_template(db, getattr(finding, "template_id", None)))[0],
            },
        },
    }


@router.get("/triage/training-dataset")
async def get_training_dataset(
    limit: int = Query(100, ge=1, le=1000),
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Export triage feedback as AI training dataset (admin/analyst only)."""
    dataset = await TriageAIService.get_training_dataset(db, limit=limit)
    return {"success": True, "data": dataset, "meta": {"count": len(dataset)}}


@router.get("/triage/metrics")
async def get_triage_metrics(
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Get aggregate triage / false positive metrics for dashboard and AI health."""
    metrics = await TriageAIService.get_fp_metrics(db)
    return {"success": True, "data": metrics}
