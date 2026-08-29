"""RedPulse - Human Review Gate API Endpoints.

Every finding and report must pass through human review before export.
This is the safety gate that ensures no vulnerability data leaves the
platform without explicit user approval.
"""
from __future__ import annotations

import logging
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select, func
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_current_user, get_db
from app.db.models import User, Finding, Project
from app.services.review_gate import (
    FindingReview, ReportReview, ReviewStatus, ReviewGateService,
)
from app.schemas import APIResponse

logger = logging.getLogger(__name__)
router = APIRouter(tags=["review-gate"])


# ==================== Finding Reviews ====================

@router.get("/projects/{project_id}/reviews/pending")
async def get_pending_reviews(
    project_id: str,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> APIResponse:
    """Get count of pending reviews for a project."""
    # Verify project ownership
    result = await db.execute(
        select(Project).where(
            Project.id == project_id,
            Project.owner_id == current_user.id,
        )
    )
    if not result.scalar_one_or_none():
        raise HTTPException(status_code=404, detail="Project not found")

    pending = ReviewGateService.get_pending_reviews(db, project_id)
    return APIResponse(success=True, data=pending)


@router.get("/projects/{project_id}/reviews/findings")
async def list_finding_reviews(
    project_id: str,
    status_filter: str = "pending",
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> APIResponse:
    """List finding reviews filtered by status."""
    # Verify project ownership
    result = await db.execute(
        select(Project).where(
            Project.id == project_id,
            Project.owner_id == current_user.id,
        )
    )
    if not result.scalar_one_or_none():
        raise HTTPException(status_code=404, detail="Project not found")

    query = select(FindingReview).where(FindingReview.project_id == project_id)
    if status_filter != "all":
        query = query.where(FindingReview.status == status_filter)
    query = query.order_by(FindingReview.created_at.desc())

    result = await db.execute(query)
    reviews = result.scalars().all()

    return APIResponse(
        success=True,
        data=[
            {
                "id": r.id,
                "finding_id": r.finding_id,
                "status": r.status,
                "reviewer_id": r.reviewer_id,
                "reviewed_at": r.reviewed_at.isoformat() if r.reviewed_at else None,
                "notes": r.notes,
                "original_severity": r.original_severity,
                "reviewed_severity": r.reviewed_severity,
                "created_at": r.created_at.isoformat() if r.created_at else None,
            }
            for r in reviews
        ],
    )


@router.post("/findings/{finding_id}/reviews/approve")
async def approve_finding(
    finding_id: str,
    data: dict = None,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> APIResponse:
    """Approve a finding for export.

    Sets review status to APPROVED, allowing the finding to be
    included in exported reports and PoC documentation.
    """
    data = data or {}
    notes = data.get("notes", "")

    # Get or create review record
    result = await db.execute(
        select(FindingReview).where(FindingReview.finding_id == finding_id)
    )
    review = result.scalar_one_or_none()

    if not review:
        # Get finding to create review
        finding_result = await db.execute(
            select(Finding).where(Finding.id == finding_id)
        )
        finding = finding_result.scalar_one_or_none()
        if not finding:
            raise HTTPException(status_code=404, detail="Finding not found")

        review = FindingReview(
            finding_id=finding_id,
            project_id=finding.project_id,
            original_severity=finding.severity.value if hasattr(finding.severity, 'value') else str(finding.severity),
            original_category=finding.category,
            original_poc=finding.poc_curl,
        )
        db.add(review)

    review.status = ReviewStatus.APPROVED.value
    review.reviewer_id = current_user.id
    review.reviewed_at = datetime.now(timezone.utc)
    review.notes = notes

    await db.commit()
    await db.refresh(review)

    logger.info(
        "Finding %s approved by user %s",
        finding_id, current_user.id,
    )

    return APIResponse(
        success=True,
        data={
            "review_id": review.id,
            "finding_id": finding_id,
            "status": "approved",
            "reviewed_at": review.reviewed_at.isoformat(),
        },
    )


@router.post("/findings/{finding_id}/reviews/reject")
async def reject_finding(
    finding_id: str,
    data: dict = None,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> APIResponse:
    """Reject a finding (do not export).

    Sets review status to REJECTED, preventing the finding from
    being included in any exports.
    """
    data = data or {}
    notes = data.get("notes", "Rejected by reviewer")

    result = await db.execute(
        select(FindingReview).where(FindingReview.finding_id == finding_id)
    )
    review = result.scalar_one_or_none()

    if not review:
        finding_result = await db.execute(
            select(Finding).where(Finding.id == finding_id)
        )
        finding = finding_result.scalar_one_or_none()
        if not finding:
            raise HTTPException(status_code=404, detail="Finding not found")

        review = FindingReview(
            finding_id=finding_id,
            project_id=finding.project_id,
        )
        db.add(review)

    review.status = ReviewStatus.REJECTED.value
    review.reviewer_id = current_user.id
    review.reviewed_at = datetime.now(timezone.utc)
    review.notes = notes

    await db.commit()

    return APIResponse(
        success=True,
        data={
            "review_id": review.id,
            "finding_id": finding_id,
            "status": "rejected",
        },
    )


@router.post("/findings/{finding_id}/reviews/request-changes")
async def request_changes_finding(
    finding_id: str,
    data: dict = None,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> APIResponse:
    """Request changes to a finding before approval.

    Sets review status to CHANGES_REQUESTED.
    """
    data = data or {}
    notes = data.get("notes", "")

    result = await db.execute(
        select(FindingReview).where(FindingReview.finding_id == finding_id)
    )
    review = result.scalar_one_or_none()

    if not review:
        finding_result = await db.execute(
            select(Finding).where(Finding.id == finding_id)
        )
        finding = finding_result.scalar_one_or_none()
        if not finding:
            raise HTTPException(status_code=404, detail="Finding not found")

        review = FindingReview(
            finding_id=finding_id,
            project_id=finding.project_id,
        )
        db.add(review)

    review.status = ReviewStatus.CHANGES_REQUESTED.value
    review.reviewer_id = current_user.id
    review.reviewed_at = datetime.now(timezone.utc)
    review.notes = notes

    await db.commit()

    return APIResponse(
        success=True,
        data={
            "review_id": review.id,
            "finding_id": finding_id,
            "status": "changes_requested",
            "notes": notes,
        },
    )


# ==================== Report Reviews ====================

@router.post("/reports/{report_id}/reviews/approve")
async def approve_report(
    report_id: str,
    data: dict = None,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> APIResponse:
    """Approve a report for export.

    All findings in the report must already be individually approved.
    """
    data = data or {}
    notes = data.get("notes", "")
    project_id = data.get("project_id")

    if not project_id:
        raise HTTPException(status_code=400, detail="project_id is required")

    # Verify project ownership
    result = await db.execute(
        select(Project).where(
            Project.id == project_id,
            Project.owner_id == current_user.id,
        )
    )
    if not result.scalar_one_or_none():
        raise HTTPException(status_code=404, detail="Project not found")

    # Check all findings in this report are approved
    from app.db.models import Finding
    finding_result = await db.execute(
        select(Finding).where(Finding.report_id == report_id)
    )
    findings = finding_result.scalars().all()

    if findings:
        finding_ids = [f.id for f in findings]
        review_result = await db.execute(
            select(FindingReview).where(
                FindingReview.finding_id.in_(finding_ids),
            )
        )
        reviews = review_result.scalars().all()

        unapproved = [
            r.finding_id for r in reviews
            if r.status != ReviewStatus.APPROVED.value
        ]
        if unapproved:
            raise HTTPException(
                status_code=400,
                detail=f"Findings not yet approved for export: {unapproved}",
            )

    # Create/update report review
    report_review_result = await db.execute(
        select(ReportReview).where(ReportReview.report_id == report_id)
    )
    report_review = report_review_result.scalar_one_or_none()

    if not report_review:
        report_review = ReportReview(
            report_id=report_id,
            project_id=project_id,
        )
        db.add(report_review)

    report_review.status = ReviewStatus.APPROVED.value
    report_review.reviewer_id = current_user.id
    report_review.reviewed_at = datetime.now(timezone.utc)
    report_review.notes = notes
    report_review.findings_count = str(len(findings))

    await db.commit()

    return APIResponse(
        success=True,
        data={
            "review_id": report_review.id,
            "report_id": report_id,
            "status": "approved",
            "findings_approved": len(findings),
        },
    )


@router.get("/reports/{report_id}/reviews/status")
async def get_report_review_status(
    report_id: str,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> APIResponse:
    """Check if a report is approved for export."""
    result = await db.execute(
        select(ReportReview).where(ReportReview.report_id == report_id)
    )
    review = result.scalar_one_or_none()

    if not review:
        return APIResponse(
            success=True,
            data={
                "report_id": report_id,
                "status": "pending",
                "can_export": False,
            },
        )

    can_export = ReviewGateService.can_export_report(review)
    return APIResponse(
        success=True,
        data={
            "report_id": report_id,
            "status": review.status,
            "can_export": can_export,
            "reviewed_at": review.reviewed_at.isoformat() if review.reviewed_at else None,
            "exported": review.exported,
        },
    )


# ==================== Batch Approval ====================

@router.post("/projects/{project_id}/reviews/approve-all")
async def approve_all_findings(
    project_id: str,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> APIResponse:
    """Approve all pending findings in a project at once.

    Use with caution - this bulk-approves all findings for export.
    """
    # Verify project ownership
    result = await db.execute(
        select(Project).where(
            Project.id == project_id,
            Project.owner_id == current_user.id,
        )
    )
    if not result.scalar_one_or_none():
        raise HTTPException(status_code=404, detail="Project not found")

    # Find all pending reviews
    result = await db.execute(
        select(FindingReview).where(
            FindingReview.project_id == project_id,
            FindingReview.status == ReviewStatus.PENDING.value,
        )
    )
    pending_reviews = result.scalars().all()

    approved_count = 0
    for review in pending_reviews:
        review.status = ReviewStatus.APPROVED.value
        review.reviewer_id = current_user.id
        review.reviewed_at = datetime.now(timezone.utc)
        review.notes = "Bulk approved by reviewer"
        approved_count += 1

    await db.commit()

    return APIResponse(
        success=True,
        data={
            "project_id": project_id,
            "approved_count": approved_count,
        },
    )
