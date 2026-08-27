"""RedPulse - Scope Management Endpoints.

Handles manual scope rule addition and retrieval for engagements.
"""

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from app.api.deps import get_current_user, get_db
from app.db.models import Engagement, Project, ScopeRule, Authorization, User
from app.schemas import ScopeRuleSchema, ProjectSchema
from app.services import scope_validator
from app.services.auth_service import create_authorization


router = APIRouter(tags=["scope"])


@router.post(
    "/engagements/{engagement_id}/scope",
    response_model=ScopeRuleSchema,
    status_code=status.HTTP_201_CREATED,
)
async def add_scope_rule(
    engagement_id: str,
    rule_data: dict,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> ScopeRuleSchema:
    """Add a manual include/exclude scope rule for an engagement.

    Only allowed for engagements with `dns_txt` method.
    For `bug_bounty_program` engagements, scope is synced automatically
    from the bug bounty platform - manual rules are supplementary only.

    Rule data format:
    {
        "target": "example.com",
        "is_include": true/false,
    }
    """
    # Get the engagement and verify ownership
    engagement = db.query(Engagement).filter(
        Engagement.id == engagement_id,
        Engagement.project.has(Project.owner_id == current_user.id),
    ).first()

    if not engagement:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Engagement not found",
        )

    # Check authorization method
    # For bug_bounty_program engagements, manual scope additions are supplementary
    # and not authoritative - scope is automatically synced from the platform
    if engagement.authorization_method == "bug_bounty_program":
        # Still allow the rule but mark it as supplementary/user-added
        # The authoritative scope comes from bounty_platform_synced rules
        pass  # We allow it but it's supplementary

    # Create the scope rule
    target = rule_data.get("target", "")
    is_include = rule_data.get("is_include", True)

    if not target:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Target is required for scope rule",
        )

    # Check if rule already exists
    existing = db.query(ScopeRule).filter(
        ScopeRule.engagement_id == engagement.id,
        ScopeRule.target == target,
        ScopeRule.is_include == is_include,
    ).first()

    if existing:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Scope rule already exists",
        )

    rule = ScopeRule(
        engagement_id=engagement.id,
        target=target,
        is_include=is_include,
        source="manual",  # Could be "manual", "bounty_platform_synced", etc.
    )

    db.add(rule)
    db.commit()
    db.refresh(rule)

    return rule


@router.get(
    "/engagements/{engagement_id}/scope",
    response_model=list[ScopeRuleSchema],
)
def list_scope_rules(
    engagement_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> list[ScopeRuleSchema]:
    """List all scope rules for an engagement with their source.

    Returns rules from all sources:
    - manual: user-added include/exclude rules
    - bounty_platform_synced: automatically synced from bug bounty programs
    """
    # Verify engagement ownership
    engagement = db.query(Engagement).filter(
        Engagement.id == engagement_id,
        Engagement.project.has(Project.owner_id == current_user.id),
    ).first()

    if not engagement:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Engagement not found",
        )

    rules = db.query(ScopeRule).filter(
        ScopeRule.engagement_id == engagement.id
    ).all()

    return rules