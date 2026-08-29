"""RedPulse - Duplicate Prediction Service.

Checks findings against publicly disclosed vulnerabilities before
report export to predict potential duplicates.
"""
from __future__ import annotations

import logging
import hashlib
from datetime import datetime, timezone
from typing import Optional, List, Dict, Any, Tuple

from sqlalchemy import select, and_, func
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.models import (
    Finding, DuplicatePrediction, Project, Workspace,
    FindingSeverity,
)

logger = logging.getLogger(__name__)


class DuplicatePredictor:
    """Predicts duplicate findings against public disclosures."""

    # Known public disclosure sources (for simulation)
    PUBLIC_SOURCES = [
        "hackerone",
        "bugcrowd",
        "cve",
        "github_advisory",
        "nvd",
    ]

    @staticmethod
    def _compute_fingerprint(title: str, template_id: str, endpoint: str) -> str:
        """Compute a stable fingerprint for duplicate matching."""
        key = f"{title.lower().strip()}|{template_id}|{endpoint.lower().strip()}"
        return hashlib.sha256(key.encode()).hexdigest()[:16]

    @staticmethod
    async def predict_duplicates(
        db: AsyncSession,
        finding_id: str,
        workspace_id: str,
    ) -> Optional[DuplicatePrediction]:
        """Analyze a finding and predict if it's a duplicate.

        Uses heuristic matching against known patterns:
        - Exact template ID match with previously reported findings
        - Similar title/endpoint combinations
        - Known CVE patterns

        Returns DuplicatePrediction if analysis was performed, None if skipped.
        """
        # Get the finding
        result = await db.execute(
            select(Finding).where(Finding.id == finding_id)
        )
        finding = result.scalar_one_or_none()
        if not finding:
            return None

        # Check if prediction already exists
        existing = await db.execute(
            select(DuplicatePrediction).where(
                DuplicatePrediction.finding_id == finding_id,
            )
        )
        if existing.scalar_one_or_none():
            return existing.scalar_one_or_none()

        # Run prediction analysis
        is_duplicate, confidence, details = await DuplicatePredictor._analyze_finding(
            db, finding, workspace_id,
        )

        # Create prediction record
        prediction = DuplicatePrediction(
            finding_id=finding_id,
            project_id=finding.project_id,
            workspace_id=workspace_id,
            predicted_duplicate=is_duplicate,
            confidence_score=confidence,
            similar_report_url=details.get("url"),
            similar_report_source=details.get("source"),
            similar_report_title=details.get("title"),
            disclosed_at=details.get("disclosed_at"),
        )
        db.add(prediction)
        await db.commit()
        await db.refresh(prediction)

        return prediction

    @staticmethod
    async def _analyze_finding(
        db: AsyncSession,
        finding: Finding,
        workspace_id: str,
    ) -> Tuple[bool, float, Dict[str, Any]]:
        """Analyze a finding for potential duplicates.

        Returns:
            Tuple of (is_duplicate, confidence, details_dict)
        """
        confidence = 0.0
        details = {}

        # 1. Check for same template_id in other projects (workspace-wide)
        same_template = await db.execute(
            select(Finding)
            .join(Project, Project.id == Finding.project_id)
            .where(
                Project.workspace_id == workspace_id,
                Finding.template_id == finding.template_id,
                Finding.id != finding.id,
                Finding.status.in_(["confirmed", "accepted"]),
            )
        )
        prev_findings = same_template.scalars().all()

        if prev_findings:
            confidence += 0.3
            details["source"] = "internal_previous"
            details["title"] = f"Previously reported: {finding.title}"
            details["url"] = None

        # 2. Check for similar titles (fuzzy match)
        if finding.title:
            similar_title = await db.execute(
                select(Finding)
                .join(Project, Project.id == Finding.project_id)
                .where(
                    Project.workspace_id == workspace_id,
                    Finding.id != finding.id,
                    Finding.title.ilike(f"%{finding.title[:30]}%"),
                )
            )
            similar = similar_title.scalars().all()
            if similar:
                confidence += 0.2
                if "source" not in details:
                    details["source"] = "similar_title"
                    details["title"] = f"Similar to: {similar[0].title}"

        # 3. Check for known CVE patterns
        if finding.template_id and "cve" in finding.template_id.lower():
            confidence += 0.4
            details["source"] = "cve"
            details["url"] = f"https://nvd.nist.gov/vuln/detail/{finding.template_id}"

        # 4. Check for high-severity with common patterns
        if finding.severity in (FindingSeverity.CRITICAL, FindingSeverity.HIGH):
            if finding.category and finding.category.value in ("rce", "ssrf", "sqli"):
                confidence += 0.1

        # Cap confidence at 1.0
        confidence = min(confidence, 1.0)

        # Determine if duplicate based on confidence threshold
        is_duplicate = confidence >= 0.5

        return is_duplicate, confidence, details

    @staticmethod
    async def get_predictions_for_export(
        db: AsyncSession,
        project_id: str,
        workspace_id: str,
    ) -> List[DuplicatePrediction]:
        """Get all unreviewed duplicate predictions for a project's findings.

        Called before report export to check if any findings need review.
        """
        result = await db.execute(
            select(DuplicatePrediction).where(
                DuplicatePrediction.project_id == project_id,
                DuplicatePrediction.workspace_id == workspace_id,
                DuplicatePrediction.reviewed == False,
            ).order_by(DuplicatePrediction.confidence_score.desc())
        )
        return result.scalars().all()

    @staticmethod
    async def review_prediction(
        db: AsyncSession,
        prediction_id: str,
        is_duplicate: bool,
        notes: Optional[str] = None,
    ) -> DuplicatePrediction:
        """User reviews a duplicate prediction and determines if it's real."""
        result = await db.execute(
            select(DuplicatePrediction).where(
                DuplicatePrediction.id == prediction_id,
            )
        )
        prediction = result.scalar_one_or_none()
        if not prediction:
            raise ValueError(f"Prediction {prediction_id} not found")

        prediction.reviewed = True
        prediction.is_duplicate = is_duplicate
        prediction.review_notes = notes

        await db.commit()
        await db.refresh(prediction)
        return prediction

    @staticmethod
    async def can_export_report(
        db: AsyncSession,
        project_id: str,
        workspace_id: str,
    ) -> Tuple[bool, str, List[DuplicatePrediction]]:
        """Check if a report can be exported (all predictions reviewed).

        Returns:
            Tuple of (can_export, message, unreviewed_predictions)
        """
        unreviewed = await DuplicatePredictor.get_predictions_for_export(
            db, project_id, workspace_id,
        )

        if unreviewed:
            return False, (
                f"{len(unreviewed)} duplicate predictions need review "
                f"before export. Review them in the Duplicate Prediction panel."
            ), unreviewed

        return True, "All predictions reviewed, safe to export", []

    @staticmethod
    async def get_prediction_stats(
        db: AsyncSession,
        workspace_id: str,
    ) -> Dict[str, Any]:
        """Get duplicate prediction statistics for a workspace."""
        total = await db.execute(
            select(func.count()).select_from(DuplicatePrediction).where(
                DuplicatePrediction.workspace_id == workspace_id,
            )
        )
        duplicates = await db.execute(
            select(func.count()).select_from(DuplicatePrediction).where(
                DuplicatePrediction.workspace_id == workspace_id,
                DuplicatePrediction.predicted_duplicate == True,
            )
        )
        reviewed = await db.execute(
            select(func.count()).select_from(DuplicatePrediction).where(
                DuplicatePrediction.workspace_id == workspace_id,
                DuplicatePrediction.reviewed == True,
            )
        )

        return {
            "total_predictions": total.scalar() or 0,
            "predicted_duplicates": duplicates.scalar() or 0,
            "reviewed": reviewed.scalar() or 0,
        }
