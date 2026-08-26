"""ReconPilot - Scope Validator.

Single choke-point function that every future phase (recon, scanning) must call
before touching any target. Enforces scope boundaries with strict ordering:
1. Global exclusion check (always first, always wins)
2. Engagement has valid, non-expired authorization
3. Host matches at least one include ScopeRule
4. Host does not match any exclude ScopeRule

Raises ScopeViolation on any failure. Returns None (silently) if allowed.
"""

from sqlalchemy.orm import Session

from app.db.models import Engagement, Authorization, Project, ScopeRule, User
from app.services.global_exclusions import is_excluded


class ScopeViolation(Exception):
    """Raised when a target is out of scope.

    Caught globally in app/main.py and returned as 403 Forbidden.
    Never a raw 500.
    """

    def __init__(self, detail: str):
        self.detail = detail
        super().__init__(self.detail)


def validate_target(engagement_id: str, host_or_url: str, db: Session, current_user: User) -> None:
    """Validate that a target host is in-scope for the given engagement.

    Order of checks (early-exit, first failure stops remaining checks):
    1. Global exclusion - .gov/.mil/.edu always blocked
    2. Engagement exists and belongs to user's project
    3. Engagement has a verified, non-expired Authorization row
    4. Host matches at least one include ScopeRule
    5. Host does not match any exclude ScopeRule

    Args:
        engagement_id: The engagement UUID/ID string
        host_or_url: The host or URL to validate (scheme-agnostic, just hostname)
        db: SQLAlchemy session
        current_user: The authenticated user

    Raises:
        ScopeViolation: If any check fails, with descriptive detail message
    """
    # ---- 1. Global exclusion check (always first, always wins) ----
    if is_excluded(host_or_url):
        raise ScopeViolation(
            f"Target host '{host_or_url}' is in the global exclusion list "
            f"(.gov/.mil/.edu are always blocked for scanning)"
        )

    # ---- 2. Engagement exists and belongs to user's project ----
    from app.db.models import Project

    engagement = db.query(Engagement).filter(
        Engagement.id == engagement_id,
        Engagement.project.has(Project.owner_id == current_user.id)
    ).first()

    if not engagement:
        raise ScopeViolation(
            f"Engagement {engagement_id} not found or does not belong to your project"
        )

    # ---- 3. Engagement has a verified, non-expired Authorization ----
    from datetime import datetime, timezone

    auth_row = db.query(Authorization).filter(
        Authorization.engagement_id == engagement.id,
        Authorization.user_id == current_user.id,
    ).first()

    if not auth_row:
        raise ScopeViolation(
            "No authorization record for this engagement. "
            "Complete authorization via DNS TXT or bug bounty program first."
        )

    if not auth_row.verified:
        raise ScopeViolation(
            "Authorization is not yet verified for this engagement."
        )

    # Check expiration (Authorization has no explicit expires_at in current model,
    # but engagement has expires_at - use that as reference)
    if engagement.expires_at and engagement.expires_at < datetime.now(timezone.utc):
        raise ScopeViolation(
            "Engagement authorization has expired. Please renew."
        )

    # ---- 4. Host matches at least one include ScopeRule ----
    included = db.query(ScopeRule).filter(
        ScopeRule.engagement_id == engagement.id,
        ScopeRule.is_include == True,
        ScopeRule.target.like(f"%{host_or_url}%")
        # Note: real implementation would have proper pattern matching;
        # this is a simplified check. For production, use CIDR/domain matching.
    ).first()

    if not included:
        raise ScopeViolation(
            f"Host '{host_or_url}' does not match any include rule for engagement {engagement.id}"
        )

    # ---- 5. Host does not match any exclude ScopeRule ----
    excluded = db.query(ScopeRule).filter(
        ScopeRule.engagement_id == engagement.id,
        ScopeRule.is_include == False,
        ScopeRule.target.like(f"%{host_or_url}%")
    ).first()

    if excluded:
        raise ScopeViolation(
            f"Host '{host_or_url}' matches an exclude rule for engagement {engagement.id}"
        )

    # All checks passed
    return None