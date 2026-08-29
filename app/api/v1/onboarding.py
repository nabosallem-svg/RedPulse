"""REDPULSE - Onboarding Progress API."""
from __future__ import annotations

from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_current_user, get_db
from app.db.models import User
from app.services.onboarding_service import get_onboarding_progress

router = APIRouter(tags=["onboarding"])


@router.get("/onboarding/progress")
async def onboarding_progress(
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Get personalized onboarding progress for the current user (no mock data).

    Derives each step from live DB: project count, engagement verified, scope rules, etc.
    Frontend wizard at /onboarding polls this.
    """
    data = await get_onboarding_progress(db, current_user)
    return {"success": True, "data": data}


@router.get("/onboarding/steps")
async def onboarding_steps():
    """Static onboarding steps definition (public, no auth) — mirrors docs/ONBOARDING.md."""
    from app.services.onboarding_service import STEPS
    return {"success": True, "data": STEPS}
