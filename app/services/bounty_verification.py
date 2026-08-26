"""ReconPilot - Bug Bounty Program Verification.

Verifies engagement authorization against officially recognized bug bounty
programs (HackerOne, Bugcrowd, etc.) by calling the platform's API using
the user's connected credentials.

The whole point is verifying against the platform's own data, not trusting
whatever the user types. If the platform API doesn't expose scope programmatically
for a given program, that program simply isn't supported via this method yet.

Flow:
1. User connects their HackerOne/Bugcrowd account (stored in PlatformConnection)
2. Authorization request includes method, bounty_platform, and bounty_program_handle
3. This function calls the platform's API to:
   a) Confirm the user has an active account on that program
   b) The program is currently accepting reports
   c) Pull the program's official in-scope and out-of-scope assets
4. Writes those as ScopeRule rows with source="bounty_platform_synced"
5. Sets verified=True, Engagement.status="authorized", expires_at = 7 days
6. If API call fails or user not associated → reject with clear error
"""

from sqlalchemy.orm import Session

from app.db.models import User, Engagement, ScopeRule, PlatformConnection
from app.db.models import Authorization, EngagementStatus
from app.services.global_exclusions import is_excluded


def get_user_platform_connection(db: Session, user_id: str, platform: str) -> PlatformConnection | None:
    """Get a user's platform connection for the specified platform."""
    return db.query(PlatformConnection).filter(
        PlatformConnection.user_id == user_id,
        PlatformConnection.platform == platform
    ).first()


def verify_bug_bounty_program(db: Session, user_id: str, engagement_id: str, 
                              bounty_platform: str, bounty_program_handle: str) -> tuple[bool, str]:
    """
    Verify an engagement against a bug bounty program.
    
    This is the core verification function for the bug_bounty_program method.
    It:
    1. Checks the user has a connected account on the specified platform
    2. Calls the platform's API to verify the program and get official scope
    3. Writes ScopeRule rows from the API response
    4. Marks the engagement as authorized
    
    Returns:
        (success: bool, message: str)
    """
    # Check global exclusions first
    # Note: In a full implementation, we'd need the target_domain here
    # For now, we skip global exclusion check at this level and let
    # the endpoint handle it
    
    # Get the user's platform connection
    connection = get_user_platform_connection(db, user_id, bounty_platform)
    if not connection:
        return False, f"User not connected to {bounty_platform} account"
    
    # TODO: Implement actual platform API calls
    # This is a placeholder - real implementation would call:
    # - HackerOne API: /programs/{handle}
    # - Bugcrowd API: /programs/{handle}
    # 
    # The API response should include:
    # - Program name and description
    # - List of in-scope assets
    # - List of out-of-scope assets
    # - Whether the program is currently active/accepting reports
    
    # Since we don't have real API integration yet, we reject with a clear error
    # indicating that platform API integration is pending
    return False, f"Bug bounty program verification not yet implemented for {bounty_platform}. API integration pending."


def check_authorization_eligibility(db: Session, engagement_id: str, user_id: str) -> tuple[bool, str]:
    """
    Check if an engagement is eligible for authorization verification.
    
    Performs preliminary checks before attempting verification.
    """
    # Get the engagement
    from app.db.models import Engagement
    engagement = db.query(Engagement).filter(Engagement.id == engagement_id).first()
    if not engagement:
        return False, "Engagement not found"
    
    # Check if engagement is already authorized
    if engagement.verified:
        return False, "Engagement already authorized"
    
    # Check if engagement belongs to a project owned by the user
    from app.db.models import Project
    project = db.query(Project).filter(
        Project.id == engagement.project_id,
        Project.owner_id == user_id
    ).first()
    if not project:
        return False, "Engagement does not belong to your project"
    
    return True, "Engagement eligible for verification"