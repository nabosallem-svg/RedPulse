"""ReconPilot - Authorization Endpoints.

Handles engagement authorization via two methods:
1. DNS TXT verification (for self-owned targets)
2. Bug bounty program verification (for verified programs)

Also implements global exclusion layer that blocks certain TLDs unconditionally.
"""

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_current_user, get_db
from app.db.models import Engagement, Authorization, User, Project
from app.schemas import EngagementSchema, AuthorizationSchema
from app.services import dns_verification, bounty_verification, global_exclusions


router = APIRouter(tags=["authorization"])


@router.post(
    "/{engagement_id}/authorization",
    response_model=AuthorizationSchema,
    status_code=status.HTTP_201_CREATED,
)
async def create_authorization_request(
    engagement_id: str,
    data: dict,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> AuthorizationSchema:
    """
    Request authorization for an engagement.
    
    Two supported methods:
    - `dns_txt`: For self-owned targets - generates token, instructions for DNS TXT record
    - `bug_bounty_program`: For verified bug bounty programs - requires connected account
    
    Global exclusion layer runs first - certain TLDs are always blocked.
    """
    method = data.get("method", "")
    target_domain = data.get("target_domain", "")

    # 1. Global exclusion check - only if target_domain provided (bounty may not have it)
    if target_domain and global_exclusions.is_excluded(target_domain):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Target domain .gov/.mil/.edu are always blocked for scanning",
        )
    
    # 2. Get the engagement and verify ownership
    result = await db.execute(select(Engagement).where(Engagement.id == engagement_id))
    engagement = result.scalar_one_or_none()
    if not engagement:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Engagement not found",
        )
    
    # Verify engagement belongs to user's project
    result = await db.execute(select(Project).where(Project.id == engagement.project_id, Project.owner_id == current_user.id))
    project = result.scalar_one_or_none()
    if not project:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Engagement does not belong to your project",
        )
    
    # For dns_txt, target_domain is required
    if method == "dns_txt" and not target_domain:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="target_domain is required",
        )
    
    # 3. Method-specific handling
    if method == "dns_txt":
        return await _handle_dns_txt_verification(db, engagement, current_user, target_domain)
    elif method == "bug_bounty_program":
        return await _handle_bug_bounty_verification(db, engagement, current_user, data)
    else:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Unsupported authorization method: {method}. Supported: dns_txt, bug_bounty_program",
        )


async def _handle_dns_txt_verification(
    db: AsyncSession, engagement: Engagement, current_user: User, target_domain: str
) -> AuthorizationSchema:
    """Handle DNS TXT verification method."""
    from app.services import dns_verification
    
    # Generate verification token
    token = dns_verification.generate_verification_token()
    
    # Create or get existing authorization row
    result = await db.execute(select(Authorization).where(Authorization.engagement_id == engagement.id, Authorization.user_id == current_user.id, Authorization.target_domain == target_domain))
    auth_row = result.scalar_one_or_none()
    
    if not auth_row:
        # Need project_id for FK
        auth_row = Authorization(
            engagement_id=engagement.id,
            project_id=engagement.project_id,
            user_id=current_user.id,
            target_domain=target_domain,
            method="dns_txt",
            verification_token=token,
            verified=False,
        )
        db.add(auth_row)
    else:
        # Update existing token
        auth_row.verification_token = token
        auth_row.verified_at = None  # Reset verification
    
    await db.commit()
    await db.refresh(auth_row)
    
    # Instructions for the user
    instructions = (
        f"Add TXT record: `reconpilot-verify={token}` "
        f"to your DNS for domain `{target_domain}`"
    )
    
    return AuthorizationSchema(
        id=auth_row.id,
        engagement_id=engagement.id,
        user_id=current_user.id,
        target_domain=target_domain,
        method="dns_txt",
        verification_token=token,
        verified=auth_row.verified,
        verified_at=auth_row.verified_at,
        expires_at=auth_row.expires_at,
        instructions=instructions,
    )


async def _handle_bug_bounty_verification(
    db: AsyncSession, engagement: Engagement, current_user: User, data: dict
) -> AuthorizationSchema:
    """Handle bug bounty program verification method."""
    from app.services import bounty_verification
    
    bounty_platform = data.get("bounty_platform", "")
    bounty_program_handle = data.get("bounty_program_handle", "")
    
    if not bounty_platform or not bounty_program_handle:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="bounty_platform and bounty_program_handle are required",
        )

    # Validate platform is supported first
    if bounty_platform not in ("hackerone", "bugcrowd"):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Unsupported authorization method: {bounty_platform}. Supported: dns_txt, bug_bounty_program",
        )
    # Check platform connection exists for user
    from app.db.models import PlatformConnection
    result = await db.execute(select(PlatformConnection).where(PlatformConnection.user_id == current_user.id, PlatformConnection.platform == bounty_platform))
    conn = result.scalar_one_or_none()
    if not conn:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="No platform connection found for this bounty platform",
        )

    # Check eligibility and attempt verification
    eligibility, message = bounty_verification.check_authorization_eligibility(
        db, engagement.id, current_user.id
    )
    
    if not eligibility:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=message,
        )
    
    # Attempt bounty program verification
    success, verification_message = bounty_verification.verify_bug_bounty_program(
        db, current_user.id, engagement.id, bounty_platform, bounty_program_handle
    )
    
    if not success:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=verification_message,
        )
    
    # Authorization was successful - update engagement status
    engagement.status = "authorized"
    
    await db.commit()
    await db.refresh(engagement)
    
    # Create authorization row
    auth_row = Authorization(
        engagement_id=engagement.id,
        project_id=engagement.project_id,
        user_id=current_user.id,
        target_domain=data.get("target_domain", ""),
        method="bug_bounty_program",
        verified=True,
        bounty_platform=bounty_platform,
        bounty_program_handle=bounty_program_handle,
    )
    db.add(auth_row)
    await db.commit()
    await db.refresh(auth_row)
    
    return AuthorizationSchema(
        id=auth_row.id,
        engagement_id=engagement.id,
        user_id=current_user.id,
        target_domain=auth_row.target_domain,
        method="bug_bounty_program",
        verified=auth_row.verified,
        verified_at=auth_row.verified_at,
        expires_at=auth_row.expires_at,
        bounty_platform=bounty_platform,
        bounty_program_handle=bounty_program_handle,
    )