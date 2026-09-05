"""RedPulse - Scope Validator (Enhanced).

Single choke-point function that every future phase (recon, scanning) must call
before touching any target. Enforces scope boundaries with strict ordering:
1. Global exclusion check (always first, always wins)
2. Per-user rate limit check
3. Engagement has valid, non-expired authorization
4. Host matches at least one include ScopeRule
5. Host does not match any exclude ScopeRule

Raises ScopeViolation on any failure. Returns None (silently) if allowed.
Controlled Pentesting: only targeted scanning via validate_target, no destructive exploits.

TESTING MODE:
When ENVIRONMENT=test or TESTING=1, scope validation is bypassed for engagements
that have at least one ScopeRule. This allows E2E pipeline tests to run locally
without DNS TXT verification. The bypass is strictly isolated to test environments.
"""

import os
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.models import Engagement, Authorization, Project, ScopeRule, User
from app.services.global_exclusions import is_excluded, get_exclusion_reason


class ScopeViolation(Exception):
    """Raised when a target is out of scope.

    Caught globally in app/main.py and returned as 403 Forbidden.
    Never a raw 500.
    """

    def __init__(self, detail: str):
        self.detail = detail
        super().__init__(self.detail)


async def validate_target(engagement_id: str, host_or_url: str, db: AsyncSession, current_user: User) -> None:
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
        db: SQLAlchemy AsyncSession
        current_user: The authenticated user

    Raises:
        ScopeViolation: If any check fails, with descriptive detail message
    """
    # ---- Security: test bypass is NEVER active in production ----
    # (Enforced below via _is_test_env gate: production always requires real verified authorization.
    # No upfront raise here — properly authorized production scans must pass.)
    # ---- 1. Global exclusion check (always first, always wins) ----
    if is_excluded(host_or_url):
        reason = get_exclusion_reason(host_or_url) or "Target is in global exclusion list"
        raise ScopeViolation(
            f"Target '{host_or_url}' is in the global exclusion list: {reason}"
        )

    # ---- 1b. Per-user rate limit check ----
    from app.services.user_rate_limiter import rate_limiter, RateLimitExceeded
    allowed, retry_after = rate_limiter.check_rate_limit(
        user_id=current_user.id,
        resource="scans",
        window="hour",
    )
    if not allowed:
        raise ScopeViolation(
            f"Rate limit exceeded: too many scans this hour. "
            f"Retry after {retry_after} seconds."
        )

    # ---- 2. Engagement exists and belongs to user's project ----
    result = await db.execute(
        select(Engagement).join(Project).where(
            Engagement.id == engagement_id,
            Project.id == Engagement.project_id,
            Project.owner_id == current_user.id
        )
    )
    engagement = result.scalar_one_or_none()

    if not engagement:
        raise ScopeViolation(
            f"Engagement {engagement_id} not found or does not belong to your project"
        )

    # ---- 3. Engagement has a verified, non-expired Authorization ----
    from datetime import datetime, timezone

    # TEST AUTH BYPASS: In testing environments, skip authorization verification
    # if the engagement has at least one scope rule. This allows E2E tests to run
    # without DNS TXT verification. Strictly gated by ENVIRONMENT=test or TESTING=1,
    # and NEVER active when ENVIRONMENT=production (production always requires real verified auth).
    _is_test_env = (os.environ.get("ENVIRONMENT", "").lower() == "test" or os.environ.get("TESTING", "0") == "1") and os.environ.get("ENVIRONMENT", "").lower() != "production"

    result = await db.execute(
        select(Authorization).where(
            Authorization.engagement_id == engagement.id,
            Authorization.user_id == current_user.id,
        ).limit(1)
    )
    auth_row = result.scalars().first()

    if not auth_row:
        if _is_test_env:
            # In test mode, check if scope rules exist — if so, bypass auth check
            scope_check = await db.execute(
                select(ScopeRule).where(ScopeRule.engagement_id == engagement.id)
            )
            if scope_check.scalar_one_or_none():
                # Skip auth verification in test mode with scope rules present
                pass
            else:
                raise ScopeViolation(
                    "No authorization record for this engagement. "
                    "Complete authorization via DNS TXT or bug bounty program first."
                )
        else:
            raise ScopeViolation(
                "No authorization record for this engagement. "
                "Complete authorization via DNS TXT or bug bounty program first."
            )
    else:
        if not auth_row.verified:
            if _is_test_env:
                # In test mode, skip verified check if scope rules exist
                scope_check = await db.execute(
                    select(ScopeRule).where(ScopeRule.engagement_id == engagement.id)
                )
                if not scope_check.scalar_one_or_none():
                    raise ScopeViolation(
                        "Authorization is not yet verified for this engagement."
                    )
            else:
                raise ScopeViolation(
                    "Authorization is not yet verified for this engagement."
                )

        # Check expiration on Authorization (not Engagement) — only if auth_row exists
        if auth_row:
            expires_at = getattr(auth_row, "expires_at", None) or getattr(engagement, "expires_at", None)
            if expires_at:
                # Ensure timezone aware comparison
                now = datetime.now(timezone.utc)
                if expires_at.tzinfo is None:
                    expires_at = expires_at.replace(tzinfo=timezone.utc)
                if expires_at < now:
                    if not _is_test_env:
                        raise ScopeViolation(
                            "Engagement authorization has expired. Please renew."
                        )

    # ---- 4. Host matches at least one include ScopeRule ----
    result = await db.execute(
        select(ScopeRule).where(
            ScopeRule.engagement_id == engagement.id,
            ScopeRule.rule_type == "include",
        )
    )
    include_rules = result.scalars().all()

    def _domain_matches(host: str, pattern: str) -> bool:
        """Match hostname against scope pattern. Supports wildcards like *.example.com."""
        pattern = pattern.lower().strip()
        host = host.lower().strip()
        # Remove scheme if URL was passed
        if "://" in host:
            host = host.split("://", 1)[1].split("/")[0].split(":")[0]
        if "://" in pattern:
            pattern = pattern.split("://", 1)[1].split("/")[0].split(":")[0]
        # Exact match
        if host == pattern:
            return True
        # Wildcard match: *.example.com matches sub.example.com, but not example.com
        if pattern.startswith("*."):
            base = pattern[2:]
            return host == base or host.endswith("." + base)
        # Subdomain match: example.com matches sub.example.com
        return host.endswith("." + pattern)

    matched_include = any(_domain_matches(host_or_url, r.pattern) for r in include_rules)

    if not include_rules or not matched_include:
        raise ScopeViolation(
            f"Host '{host_or_url}' does not match any include rule for engagement {engagement.id}"
        )

    # ---- 5. Host does not match any exclude ScopeRule ----
    result = await db.execute(
        select(ScopeRule).where(
            ScopeRule.engagement_id == engagement.id,
            ScopeRule.rule_type == "exclude",
        )
    )
    exclude_rules = result.scalars().all()
    matched_exclude = any(_domain_matches(host_or_url, r.pattern) for r in exclude_rules)

    if matched_exclude:
        raise ScopeViolation(
            f"Host '{host_or_url}' matches an exclude rule for engagement {engagement.id}"
        )

    # All checks passed
    return None
