"""RedPulse - Billing & Credits API Endpoints.

Subscription management, credit tracking, and plan limits.
"""
from __future__ import annotations

import logging

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_current_user, get_db
from app.db.models import User, Workspace, Subscription, CreditBalance
from app.services.workspace_service import WorkspaceService
from app.services.billing_service import BillingService
from app.schemas import APIResponse

logger = logging.getLogger(__name__)
router = APIRouter(tags=["billing"])


@router.get("/{workspace_id}/subscription")
async def get_subscription(
    workspace_id: str,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> APIResponse:
    """Get workspace subscription details."""
    has_access, _ = await WorkspaceService.check_workspace_access(
        db, workspace_id, current_user.id, "billing:read",
    )
    if not has_access:
        raise HTTPException(status_code=403, detail="Access denied")

    subscription = await BillingService.get_subscription(db, workspace_id)
    if not subscription:
        raise HTTPException(status_code=404, detail="No subscription found")

    limits = BillingService.get_plan_limits(subscription.plan)

    return APIResponse(
        success=True,
        data={
            "id": subscription.id,
            "plan": subscription.plan.value,
            "status": subscription.status.value,
            "limits": limits,
            "credits": {
                "monthly": subscription.monthly_credits,
                "used": subscription.credits_used_this_period,
                "remaining": subscription.monthly_credits - subscription.credits_used_this_period,
            },
            "current_period_start": subscription.current_period_start.isoformat() if subscription.current_period_start else None,
            "current_period_end": subscription.current_period_end.isoformat() if subscription.current_period_end else None,
            "cancel_at_period_end": subscription.cancel_at_period_end,
        },
    )


@router.get("/{workspace_id}/credits")
async def get_credits(
    workspace_id: str,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> APIResponse:
    """Get credit balance and usage summary."""
    has_access, _ = await WorkspaceService.check_workspace_access(
        db, workspace_id, current_user.id, "billing:read",
    )
    if not has_access:
        raise HTTPException(status_code=403, detail="Access denied")

    usage = await BillingService.get_credit_usage(db, workspace_id)

    return APIResponse(success=True, data=usage)


@router.get("/{workspace_id}/plans")
async def list_plans(
    workspace_id: str,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> APIResponse:
    """List available subscription plans with pricing."""
    from app.db.models import SubscriptionPlan

    plans = {}
    for plan in SubscriptionPlan:
        limits = BillingService.get_plan_limits(plan)
        plans[plan.value] = {
            "name": plan.value,
            "price_monthly": limits["price_monthly"],
            "max_projects": limits["max_projects"],
            "max_scans_per_day": limits["max_scans_per_day"],
            "max_assets_per_project": limits["max_assets_per_project"],
            "monthly_credits": limits["monthly_credits"],
        }

    return APIResponse(success=True, data=plans)


@router.get("/{workspace_id}/credit-costs")
async def get_credit_costs(
    workspace_id: str,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> APIResponse:
    """Get credit costs for each operation type."""
    from app.services.billing_service import CREDIT_COSTS

    return APIResponse(
        success=True,
        data={
            "operations": CREDIT_COSTS,
            "description": "Credits consumed per operation",
        },
    )
