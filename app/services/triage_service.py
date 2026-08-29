"""RedPulse - False Positive Triage Workflow + AI Feed.

Analyst triage decisions feed an AI layer that learns to suppress future false positives.
Workflow:
  1. AI suggests prediction (false_positive vs true_positive) based on historical feedback.
  2. Analyst submits verdict (false_positive / true_positive / needs_review / confirmed).
  3. System stores TriageFeedback, updates Finding status, and evaluates AI correctness.
  4. Feedback is used as training data: future suggestions use aggregated FP rates per template/category.

AI is deterministic/heuristic (no external LLM) - suitable for tests and offline environments.
"""
from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Optional, Dict, Any, List, Tuple

from sqlalchemy import select, func, and_
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.models import (
    Finding, FindingStatus, TriageFeedback, TriageDecision, Project, Workspace, User,
)

logger = logging.getLogger(__name__)

# Threshold for AI to predict false_positive when historical FP rate exceeds this
FP_RATE_THRESHOLD = 0.50
# Minimum feedback count before trusting FP rate
MIN_FEEDBACK_FOR_TRUST = 3


class TriageAIService:
    """Lightweight AI triage suggestion engine - learns from TriageFeedback."""

    @staticmethod
    async def suggest(
        db: AsyncSession,
        finding: Finding,
    ) -> Dict[str, Any]:
        """Suggest whether finding is false positive based on historical feedback (weighted).

        Heuristics in order:
        1. Same template_id weighted FP rate (most specific) - uses TriageFeedback.feedback_weight
        2. Same category weighted FP rate
        3. Severity/confidence fallback
        Weighted rate prevents silent bug where all feedback counts equally despite different severity/confidence.
        Returns {prediction, confidence, reasoning, fp_rate, sample_count, weighted_fp_rate}
        """
        template_id = getattr(finding, "template_id", None)
        category = getattr(finding, "category", None)

        # Try template-level stats
        fp_rate, count = await TriageAIService._fp_rate_for_template(db, template_id)
        if count >= MIN_FEEDBACK_FOR_TRUST:
            prediction = "false_positive" if fp_rate > FP_RATE_THRESHOLD else "true_positive"
            confidence = abs(fp_rate - 0.5) * 2  # 0..1 distance from threshold
            # Boost confidence with sample size (cap at 0.95)
            confidence = min(0.95, confidence * (0.7 + 0.3 * min(count / 10, 1.0)))
            reasoning = f"Historical FP rate for template '{template_id}' is {fp_rate:.0%} over {count} triages."
            return {"prediction": prediction, "confidence": round(float(confidence), 2), "reasoning": reasoning, "fp_rate": fp_rate, "sample_count": count}

        # Fallback to category stats
        fp_rate_cat, count_cat = await TriageAIService._fp_rate_for_category(db, category)
        if count_cat >= MIN_FEEDBACK_FOR_TRUST:
            prediction = "false_positive" if fp_rate_cat > FP_RATE_THRESHOLD else "true_positive"
            confidence = abs(fp_rate_cat - 0.5) * 1.5
            confidence = min(0.85, confidence)
            reasoning = f"Historical FP rate for category '{category}' is {fp_rate_cat:.0%} over {count_cat} triages."
            return {"prediction": prediction, "confidence": round(float(confidence), 2), "reasoning": reasoning, "fp_rate": fp_rate_cat, "sample_count": count_cat}

        # Final fallback: confidence-based heuristic
        # Low confidence findings are more likely false positives (nuclei info/low)
        conf = getattr(finding, "confidence", 0) or 0
        severity = str(getattr(finding, "severity", "")).lower()
        if conf < 30 or severity in ("info", "low"):
            # conservative: predict false_positive with low confidence
            return {
                "prediction": "false_positive",
                "confidence": 0.35,
                "reasoning": f"Low confidence ({conf}) and severity {severity} often correlate with false positives; needs review.",
                "fp_rate": 0.35,
                "sample_count": 0,
            }
        return {
            "prediction": "true_positive",
            "confidence": 0.55,
            "reasoning": f"No historical data for template/category; defaulting to true_positive based on confidence {conf} and severity {severity}.",
            "fp_rate": 0.0,
            "sample_count": 0,
        }

    @staticmethod
    async def _fp_rate_for_template(db: AsyncSession, template_id: Optional[str]) -> Tuple[float, int]:
        if not template_id:
            return 0.0, 0
        # Weighted FP rate: sum(feedback_weight where FP) / sum(feedback_weight total)
        # This makes high-severity / high-confidence feedback count more than low-severity noise
        result = await db.execute(
            select(TriageFeedback.feedback_weight, TriageFeedback.decision)
            .join(Finding, Finding.id == TriageFeedback.finding_id)
            .where(Finding.template_id == template_id)
        )
        rows = result.all()
        if not rows:
            return 0.0, 0
        total_weight = sum(float(r[0] or 1.0) for r in rows)
        fp_weight = sum(float(r[0] or 1.0) for r in rows if r[1] == TriageDecision.FALSE_POSITIVE)
        if total_weight == 0:
            return 0.0, len(rows)
        return fp_weight / total_weight, len(rows)

    @staticmethod
    async def _fp_rate_for_category(db: AsyncSession, category: Optional[str]) -> Tuple[float, int]:
        if not category:
            return 0.0, 0
        result = await db.execute(
            select(TriageFeedback.feedback_weight, TriageFeedback.decision)
            .join(Finding, Finding.id == TriageFeedback.finding_id)
            .where(Finding.category == category)
        )
        rows = result.all()
        if not rows:
            return 0.0, 0
        total_weight = sum(float(r[0] or 1.0) for r in rows)
        fp_weight = sum(float(r[0] or 1.0) for r in rows if r[1] == TriageDecision.FALSE_POSITIVE)
        if total_weight == 0:
            return 0.0, len(rows)
        return fp_weight / total_weight, len(rows)

    @staticmethod
    async def get_training_dataset(
        db: AsyncSession,
        limit: int = 1000,
    ) -> List[Dict[str, Any]]:
        """Export feedback rows as training dataset for AI layer."""
        result = await db.execute(
            select(TriageFeedback, Finding)
            .join(Finding, Finding.id == TriageFeedback.finding_id)
            .order_by(TriageFeedback.created_at.desc())
            .limit(limit)
        )
        rows = result.all()
        dataset = []
        for fb, finding in rows:
            dataset.append({
                "finding_id": finding.id,
                "template_id": finding.template_id,
                "category": finding.category,
                "severity": str(finding.severity.value if hasattr(finding.severity, "value") else finding.severity),
                "confidence": finding.confidence,
                "endpoint": finding.endpoint,
                "decision": fb.decision.value if hasattr(fb.decision, "value") else str(fb.decision),
                "ai_prediction": fb.ai_prediction,
                "ai_was_correct": fb.ai_was_correct,
                "reason": fb.reason,
                "feedback_weight": fb.feedback_weight,
            })
        return dataset

    @staticmethod
    async def get_fp_metrics(
        db: AsyncSession,
    ) -> Dict[str, Any]:
        """Aggregate metrics for observability / AI health."""
        total_q = await db.execute(select(func.count()).select_from(TriageFeedback))
        total = total_q.scalar() or 0
        fp_q = await db.execute(select(func.count()).select_from(TriageFeedback).where(TriageFeedback.decision == TriageDecision.FALSE_POSITIVE))
        fp_count = fp_q.scalar() or 0
        # AI accuracy where we have prediction
        acc_q = await db.execute(select(func.count()).select_from(TriageFeedback).where(TriageFeedback.ai_was_correct == True))
        correct = acc_q.scalar() or 0
        with_ai_q = await db.execute(select(func.count()).select_from(TriageFeedback).where(TriageFeedback.ai_prediction.isnot(None)))
        with_ai = with_ai_q.scalar() or 0
        # Top FP templates
        top_templates = await db.execute(
            select(Finding.template_id, func.count().label("cnt"))
            .join(TriageFeedback, TriageFeedback.finding_id == Finding.id)
            .where(TriageFeedback.decision == TriageDecision.FALSE_POSITIVE)
            .group_by(Finding.template_id)
            .order_by(func.count().desc())
            .limit(5)
        )
        top = [{"template_id": r[0], "false_positive_count": r[1]} for r in top_templates.all() if r[0]]

        return {
            "total_feedbacks": total,
            "false_positives": fp_count,
            "true_positives": total - fp_count,
            "false_positive_rate": round(fp_count / total, 3) if total else 0.0,
            "ai_accuracy": round(correct / with_ai, 3) if with_ai else None,
            "ai_predictions_evaluated": with_ai,
            "top_false_positive_templates": top,
        }


class TriageService:
    """Workflow for analyst triage that feeds the AI layer."""

    # Map triage decision -> Finding status update
    DECISION_TO_STATUS = {
        TriageDecision.FALSE_POSITIVE: FindingStatus.FALSE_POSITIVE,
        TriageDecision.TRUE_POSITIVE: FindingStatus.CONFIRMED,
        TriageDecision.CONFIRMED: FindingStatus.CONFIRMED,
        TriageDecision.NEEDS_REVIEW: FindingStatus.NEW,
        TriageDecision.ACCEPTED_RISK: FindingStatus.ACCEPTED,
    }

    @staticmethod
    async def get_ai_suggestion(
        db: AsyncSession,
        finding_id: str,
    ) -> Dict[str, Any]:
        """Get AI suggestion for a finding (without committing feedback)."""
        result = await db.execute(select(Finding).where(Finding.id == finding_id))
        finding = result.scalar_one_or_none()
        if not finding:
            raise ValueError("Finding not found")
        suggestion = await TriageAIService.suggest(db, finding)
        return suggestion

    @staticmethod
    async def submit_triage(
        db: AsyncSession,
        finding_id: str,
        analyst: User,
        decision: str,
        reason: Optional[str] = None,
        evidence: Optional[str] = None,
    ) -> TriageFeedback:
        """Submit analyst triage - updates Finding status and stores feedback for AI training.

        Steps:
          1. Validate finding exists and project ownership (via analyst context handled by caller)
          2. Get AI suggestion snapshot before decision
          3. Map decision -> FindingStatus and update finding
          4. Create TriageFeedback with ai_was_correct evaluation
          5. Return feedback (AI will use this for future suggestions)
        """
        try:
            decision_enum = TriageDecision(decision)
        except ValueError:
            raise ValueError(f"Invalid decision '{decision}'. Must be one of {[e.value for e in TriageDecision]}")

        result = await db.execute(select(Finding).where(Finding.id == finding_id))
        finding = result.scalar_one_or_none()
        if not finding:
            raise ValueError("Finding not found")

        # Get AI suggestion before human verdict (for comparison)
        ai_suggestion = await TriageAIService.suggest(db, finding)

        # Evaluate AI correctness: if AI predicted same bucket as human decision
        # Map: AI false_positive <=> analyst false_positive ; else true_positive
        ai_pred = ai_suggestion["prediction"]
        analyst_is_fp = decision_enum == TriageDecision.FALSE_POSITIVE
        ai_is_fp = ai_pred == "false_positive"
        ai_was_correct = (analyst_is_fp == ai_is_fp)

        # --- feedback_weight: how much this human verdict counts for AI training ---
        # Rationale (explicit to avoid silent bug where all feedback is equal):
        # Severity alone is not enough — a high-severity FP confirmed by a senior analyst
        # should count more than a low-severity one. We also factor in AI confidence:
        # if the finding had high AI confidence but was still marked FP, that's a stronger
        # learning signal. Weight is capped 0.5..2.0 to prevent dominance.
        # Formula: base 1.0 * severity_factor * confidence_factor (role factor future)
        severity_str = str(finding.severity.value if hasattr(finding.severity, "value") else finding.severity).lower()
        severity_factor = {"critical": 1.5, "high": 1.3, "medium": 1.0, "low": 0.7, "info": 0.5}.get(severity_str, 1.0)
        # Confidence factor: low-confidence findings are noisier -> slightly lower weight
        finding_conf = int(getattr(finding, "confidence", 50) or 50)
        if finding_conf < 30:
            confidence_factor = 0.8
        elif finding_conf > 80:
            confidence_factor = 1.2
        else:
            confidence_factor = 1.0
        # AI confidence factor: if AI was very confident but wrong, that feedback is more valuable
        ai_conf_factor = 1.0
        try:
            ai_conf = float(ai_suggestion.get("confidence", 0.5))
            if not ai_was_correct and ai_conf > 0.8:
                ai_conf_factor = 1.25  # AI confidently wrong -> high learning value
            elif ai_was_correct and ai_conf > 0.8:
                ai_conf_factor = 1.1
        except Exception:
            pass
        weight = round(max(0.5, min(2.0, 1.0 * severity_factor * confidence_factor * ai_conf_factor)), 2)

        # Update finding status
        new_status = TriageService.DECISION_TO_STATUS.get(decision_enum)
        if new_status:
            finding.status = new_status
            finding.last_seen = datetime.now(timezone.utc)

        # Resolve workspace/project ids for scoping
        project_id = getattr(finding, "project_id", None)
        workspace_id = None
        if project_id:
            proj_res = await db.execute(select(Project).where(Project.id == project_id))
            proj = proj_res.scalar_one_or_none()
            if proj and hasattr(proj, "workspace_id"):
                workspace_id = proj.workspace_id

        feedback = TriageFeedback(
            finding_id=finding.id,
            project_id=project_id or "unknown",
            workspace_id=workspace_id,
            analyst_id=analyst.id,
            decision=decision_enum,
            reason=reason,
            evidence=evidence,
            ai_prediction=ai_pred,
            ai_confidence=ai_suggestion["confidence"],
            ai_reasoning=ai_suggestion["reasoning"],
            ai_was_correct=ai_was_correct,
            feedback_weight=weight,
        )
        db.add(feedback)
        await db.commit()
        await db.refresh(feedback)
        await db.refresh(finding)

        logger.info("triage_submitted finding=%s decision=%s ai_pred=%s ai_correct=%s analyst=%s", finding_id, decision, ai_pred, ai_was_correct, analyst.id)
        return feedback

    @staticmethod
    async def list_feedback(
        db: AsyncSession,
        project_id: Optional[str] = None,
        finding_id: Optional[str] = None,
        workspace_id: Optional[str] = None,
        limit: int = 50,
        offset: int = 0,
    ) -> Tuple[List[TriageFeedback], int]:
        """List triage feedback with filters."""
        base_filters = []
        if project_id:
            base_filters.append(TriageFeedback.project_id == project_id)
        if finding_id:
            base_filters.append(TriageFeedback.finding_id == finding_id)
        if workspace_id:
            base_filters.append(TriageFeedback.workspace_id == workspace_id)

        count_q = select(func.count()).select_from(TriageFeedback)
        if base_filters:
            count_q = count_q.where(and_(*base_filters))
        total_res = await db.execute(count_q)
        total = total_res.scalar() or 0

        q = select(TriageFeedback)
        if base_filters:
            q = q.where(and_(*base_filters))
        q = q.order_by(TriageFeedback.created_at.desc()).limit(min(limit, 100)).offset(max(0, offset))
        result = await db.execute(q)
        items = list(result.scalars().all())
        return items, total

    @staticmethod
    async def get_finding_history(
        db: AsyncSession,
        finding_id: str,
    ) -> List[TriageFeedback]:
        """Get triage history for a single finding."""
        result = await db.execute(
            select(TriageFeedback).where(TriageFeedback.finding_id == finding_id).order_by(TriageFeedback.created_at.asc())
        )
        return list(result.scalars().all())
