"""RedPulse - Scope Management Endpoints.

Handles manual scope rule addition and retrieval for engagements.
"""

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_current_user, get_db
from app.db.models import Engagement, Project, ScopeRule, User


router = APIRouter(tags=["scope"])


@router.post(
    "/{engagement_id}/scope",
    status_code=status.HTTP_201_CREATED,
)
async def add_scope_rule(
    engagement_id: str,
    rule_data: dict,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> dict:
    """Add a manual include/exclude scope rule for an engagement.

    Rule data format:
    {
        "target": "example.com",
        "is_include": true/false,
    }
    """
    # Verify engagement belongs to user's project
    result = await db.execute(
        select(Engagement).where(
            Engagement.id == engagement_id,
            Engagement.project.has(Project.owner_id == current_user.id),
        )
    )
    engagement = result.scalar_one_or_none()

    if not engagement:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Engagement not found",
        )

    target = rule_data.get("target", "")
    is_include = rule_data.get("is_include", True)

    if not target:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Target is required for scope rule",
        )

    # Check if rule already exists
    result = await db.execute(
        select(ScopeRule).where(
            ScopeRule.engagement_id == engagement.id,
            ScopeRule.pattern == target,
        )
    )
    existing = result.scalar_one_or_none()

    if existing:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Scope rule already exists",
        )

    # Map frontend fields to DB model
    from app.db.models import RuleType, RuleSource

    rule = ScopeRule(
        engagement_id=engagement.id,
        pattern=target,
        rule_type=RuleType.INCLUDE if is_include else RuleType.EXCLUDE,
        source=RuleSource.USER_DEFINED,
    )

    db.add(rule)
    await db.commit()
    await db.refresh(rule)

    # Return in frontend-expected format
    return {
        "id": rule.id,
        "engagement_id": rule.engagement_id,
        "target": rule.pattern,
        "is_include": rule.rule_type == RuleType.INCLUDE,
        "source": rule.source.value if hasattr(rule.source, "value") else str(rule.source),
        "created_at": rule.created_at.isoformat() if rule.created_at else None,
    }


@router.get(
    "/{engagement_id}/scope",
)
async def list_scope_rules(
    engagement_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> list[dict]:
    """List all scope rules for an engagement."""
    # Verify engagement ownership
    result = await db.execute(
        select(Engagement).where(
            Engagement.id == engagement_id,
            Engagement.project.has(Project.owner_id == current_user.id),
        )
    )
    engagement = result.scalar_one_or_none()

    if not engagement:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Engagement not found",
        )

    result = await db.execute(
        select(ScopeRule).where(ScopeRule.engagement_id == engagement.id)
    )
    rules = result.scalars().all()

    from app.db.models import RuleType

    return [
        {
            "id": r.id,
            "engagement_id": r.engagement_id,
            "target": r.pattern,
            "is_include": r.rule_type == RuleType.INCLUDE,
            "source": r.source.value if hasattr(r.source, "value") else str(r.source),
            "created_at": r.created_at.isoformat() if r.created_at else None,
        }
        for r in rules
    ]
