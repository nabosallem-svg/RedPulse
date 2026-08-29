"""RedPulse - Duplicate Prediction API Endpoints.

Check findings against public disclosures before report export.
"""
from __future__ import annotations

import logging

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_current_user, get_db
from app.db.models import User
from app.services.duplicate_predictor import DuplicatePredictor
from app.services.workspace_service import WorkspaceService
from app.schemas import APIResponse

logger = logging.getLogger(__name__)
router = APIRouter(tags=["duplicate-prediction"])


@router.post("/findings/{finding_id}/predict-duplicate")
async def predict_duplicate(
    finding_id: str,
    data: dict = None,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> APIResponse:
    """Run duplicate prediction on a finding.

    Analyzes the finding against previously reported findings
    and public disclosures to predict potential duplicates.
    """
    data = data or {}
    workspace_id = data.get("workspace_id")

    if not workspace_id:
        raise HTTPException(status_code=400, detail="workspace_id is required")

    has_access, _ = await WorkspaceService.check_workspace_access(
        db, workspace_id, current_user.id, "finding:read",
    )
    if not has_access:
        raise HTTPException(status_code=403, detail="Access denied")

    prediction = await DuplicatePredictor.predict_duplicates(
        db, finding_id, workspace_id,
    )

    if not prediction:
        raise HTTPException(status_code=404, detail="Finding not found")

    return APIResponse(
        success=True,
        data={
            "id": prediction.id,
            "finding_id": prediction.finding_id,
            "predicted_duplicate": prediction.predicted_duplicate,
            "confidence_score": prediction.confidence_score,
            "similar_report_url": prediction.similar_report_url,
            "similar_report_source": prediction.similar_report_source,
            "similar_report_title": prediction.similar_report_title,
            "reviewed": prediction.reviewed,
        },
    )


@router.get("/projects/{project_id}/duplicate-predictions")
async def list_predictions(
    project_id: str,
    workspace_id: str,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> APIResponse:
    """List duplicate predictions for a project's findings."""
    has_access, _ = await WorkspaceService.check_workspace_access(
        db, workspace_id, current_user.id, "finding:read",
    )
    if not has_access:
        raise HTTPException(status_code=403, detail="Access denied")

    predictions = await DuplicatePredictor.get_predictions_for_export(
        db, project_id, workspace_id,
    )

    return APIResponse(
        success=True,
        data=[
            {
                "id": p.id,
                "finding_id": p.finding_id,
                "predicted_duplicate": p.predicted_duplicate,
                "confidence_score": p.confidence_score,
                "similar_report_url": p.similar_report_url,
                "similar_report_source": p.similar_report_source,
                "similar_report_title": p.similar_report_title,
                "reviewed": p.reviewed,
                "is_duplicate": p.is_duplicate,
            }
            for p in predictions
        ],
    )


@router.post("/duplicate-predictions/{prediction_id}/review")
async def review_prediction(
    prediction_id: str,
    data: dict = None,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> APIResponse:
    """Review a duplicate prediction.

    User determines if the predicted duplicate is actually a duplicate.
    """
    data = data or {}
    is_duplicate = data.get("is_duplicate", False)
    notes = data.get("notes", "")

    try:
        prediction = await DuplicatePredictor.review_prediction(
            db, prediction_id, is_duplicate, notes,
        )
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))

    return APIResponse(
        success=True,
        data={
            "id": prediction.id,
            "reviewed": prediction.reviewed,
            "is_duplicate": prediction.is_duplicate,
            "review_notes": prediction.review_notes,
        },
    )


@router.get("/projects/{project_id}/export-check")
async def check_export_readiness(
    project_id: str,
    workspace_id: str,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> APIResponse:
    """Check if a project's report is ready for export.

    Verifies all duplicate predictions have been reviewed.
    """
    has_access, _ = await WorkspaceService.check_workspace_access(
        db, workspace_id, current_user.id, "report:export",
    )
    if not has_access:
        raise HTTPException(status_code=403, detail="Access denied")

    can_export, message, unreviewed = await DuplicatePredictor.can_export_report(
        db, project_id, workspace_id,
    )

    return APIResponse(
        success=True,
        data={
            "can_export": can_export,
            "message": message,
            "unreviewed_count": len(unreviewed),
            "unreviewed_findings": [
                {
                    "prediction_id": p.id,
                    "finding_id": p.finding_id,
                    "confidence_score": p.confidence_score,
                    "similar_report_title": p.similar_report_title,
                }
                for p in unreviewed
            ],
        },
    )


@router.get("/workspaces/{workspace_id}/duplicate-stats")
async def get_duplicate_stats(
    workspace_id: str,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> APIResponse:
    """Get duplicate prediction statistics for a workspace."""
    has_access, _ = await WorkspaceService.check_workspace_access(
        db, workspace_id, current_user.id, "finding:read",
    )
    if not has_access:
        raise HTTPException(status_code=403, detail="Access denied")

    stats = await DuplicatePredictor.get_prediction_stats(db, workspace_id)
    return APIResponse(success=True, data=stats)
