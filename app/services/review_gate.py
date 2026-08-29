"""RedPulse - Human Review Gate.

Ensures no finding, PoC, or report is exported or shared without explicit
user approval. Every export operation checks the review status first.

Phase 13 Safety Gate: Complete human-in-the-loop review system.
"""
from __future__ import annotations

import logging
from datetime import datetime, timezone
from enum import Enum
from typing import Optional

from sqlalchemy import select, Column, String, Boolean, DateTime, Text, JSON, ForeignKey
from sqlalchemy.orm import relationship

from app.db.base import Base

logger = logging.getLogger(__name__)


class ReviewStatus(str, Enum):
    """Review status for findings and reports."""
    PENDING = "pending"
    APPROVED = "approved"
    REJECTED = "rejected"
    CHANGES_REQUESTED = "changes_requested"


class FindingReview(Base):
    """Tracks human review status for individual findings.

    Every finding starts as PENDING and must be APPROVED before export.
    """
    __tablename__ = "finding_reviews"

    id = Column(String(36), primary_key=True)
    finding_id = Column(String(36), ForeignKey("findings.id"), nullable=False, unique=True)
    project_id = Column(String(36), ForeignKey("projects.id"), nullable=False)
    status = Column(String(20), nullable=False, default=ReviewStatus.PENDING.value)
    reviewer_id = Column(String(36), ForeignKey("users.id"), nullable=True)
    reviewed_at = Column(DateTime, nullable=True)
    notes = Column(Text, nullable=True)
    # Track what was reviewed (PoC content, severity, category)
    reviewed_poc = Column(Text, nullable=True)
    reviewed_severity = Column(String(20), nullable=True)
    reviewed_category = Column(String(50), nullable=True)
    # Original values for comparison
    original_poc = Column(Text, nullable=True)
    original_severity = Column(String(20), nullable=True)
    original_category = Column(String(50), nullable=True)
    created_at = Column(DateTime, nullable=False, default=lambda: datetime.now(timezone.utc))
    updated_at = Column(DateTime, nullable=False, default=lambda: datetime.now(timezone.utc),
                        onupdate=lambda: datetime.now(timezone.utc))

    finding = relationship("Finding", foreign_keys=[finding_id])
    project = relationship("Project", foreign_keys=[project_id])
    reviewer = relationship("User", foreign_keys=[reviewer_id])


class ReportReview(Base):
    """Tracks human review status for exported reports.

    Reports must be fully reviewed before any external export.
    """
    __tablename__ = "report_reviews"

    id = Column(String(36), primary_key=True)
    report_id = Column(String(36), nullable=False, unique=True)
    project_id = Column(String(36), ForeignKey("projects.id"), nullable=False)
    status = Column(String(20), nullable=False, default=ReviewStatus.PENDING.value)
    reviewer_id = Column(String(36), ForeignKey("users.id"), nullable=True)
    reviewed_at = Column(DateTime, nullable=True)
    notes = Column(Text, nullable=True)
    # What the report contains
    findings_count = Column(String(10), nullable=True)
    severity_summary = Column(JSON, nullable=True)
    # Export tracking
    exported = Column(Boolean, default=False)
    exported_at = Column(DateTime, nullable=True)
    exported_to = Column(String(255), nullable=True)
    created_at = Column(DateTime, nullable=False, default=lambda: datetime.now(timezone.utc))
    updated_at = Column(DateTime, nullable=False, default=lambda: datetime.now(timezone.utc),
                        onupdate=lambda: datetime.now(timezone.utc))

    project = relationship("Project", foreign_keys=[project_id])
    reviewer = relationship("User", foreign_keys=[reviewer_id])


class ReviewGateService:
    """Service for managing the human review gate.

    Every export/check passes through this service to ensure compliance.
    """

    @staticmethod
    def can_export_finding(review: FindingReview) -> bool:
        """Check if a finding is approved for export."""
        if review is None:
            return False  # No review record = not approved
        return review.status == ReviewStatus.APPROVED.value

    @staticmethod
    def can_export_report(review: ReportReview) -> bool:
        """Check if a report is approved for export."""
        if review is None:
            return False
        return review.status == ReviewStatus.APPROVED.value and not review.exported

    @staticmethod
    def can_export_findings_batch(reviews: list[FindingReview]) -> Tuple[bool, list[str]]:
        """Check if a batch of findings can be exported.

        Returns:
            Tuple of (all_approved, list_of_unapproved_finding_ids)
        """
        unapproved = []
        for review in reviews:
            if review.status != ReviewStatus.APPROVED.value:
                unapproved.append(review.finding_id)
        return len(unapproved) == 0, unapproved

    @staticmethod
    def get_pending_reviews(db, project_id: str) -> dict:
        """Get count of pending reviews for a project."""
        from sqlalchemy import func

        finding_count = db.execute(
            select(func.count()).select_from(FindingReview).where(
                FindingReview.project_id == project_id,
                FindingReview.status == ReviewStatus.PENDING.value,
            )
        ).scalar() or 0

        report_count = db.execute(
            select(func.count()).select_from(ReportReview).where(
                ReportReview.project_id == project_id,
                ReportReview.status == ReviewStatus.PENDING.value,
            )
        ).scalar() or 0

        return {
            "pending_findings": finding_count,
            "pending_reports": report_count,
            "total_pending": finding_count + report_count,
        }
