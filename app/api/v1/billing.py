"""RedPulse - Billing & Credits API Endpoints.

Subscription management, credit tracking, and plan limits.
Stripe Checkout + Webhook for real payments (test mode).
"""
from __future__ import annotations

import logging

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_current_user, get_db
from app.db.models import User, Workspace, Subscription, CreditBalance, SubscriptionPlan
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
    """List available subscription plans with pricing and metadata."""
    plans = {}
    for plan in SubscriptionPlan:
        metadata = BillingService.get_plan_metadata(plan)
        limits = BillingService.get_plan_limits(plan)
        plans[plan.value] = {
            "id": plan.value,
            "name": metadata["name"],
            "slug": metadata["slug"],
            "price": metadata["price"],
            "currency": metadata["currency"],
            "billing_interval": metadata["billing_interval"],
            "billing": metadata["billing"],
            "description": metadata["description"],
            "features": metadata["features"],
            "limits": limits,
            "active": True,
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


@router.post("/{workspace_id}/checkout")
async def create_checkout_session(
    workspace_id: str,
    data: dict,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> APIResponse:
    """Create Stripe Checkout Session for subscription (real Stripe test mode).

    Body: {plan: "hunter" | "pro" | "team" | "enterprise", success_url?: string, cancel_url?: string}
    Requires billing:manage (admin). Returns {session_id, url} to redirect.
    Enterprise plan uses "Contact Sales" instead of checkout.
    """
    has_access, _ = await WorkspaceService.check_workspace_access(
        db, workspace_id, current_user.id, "billing:manage",
    )
    if not has_access:
        raise HTTPException(status_code=403, detail="Access denied - billing:manage required (admin)")

    plan_str = (data.get("plan") or "").lower().strip()
    if not plan_str:
        raise HTTPException(status_code=400, detail="plan is required: hunter, pro, team, enterprise")

    try:
        plan = SubscriptionPlan(plan_str)
    except ValueError:
        raise HTTPException(status_code=400, detail=f"Invalid plan {plan_str}. Must be hunter, pro, team, enterprise")

    # Fetch workspace
    result = await db.execute(select(Workspace).where(Workspace.id == workspace_id))
    workspace = result.scalar_one_or_none()
    if not workspace:
        raise HTTPException(status_code=404, detail="Workspace not found")

    # Enterprise plan: Contact Sales instead of checkout
    if plan == SubscriptionPlan.ENTERPRISE:
        pricing = BillingService.get_plan_metadata(plan)
        raise HTTPException(
            status_code=400,
            detail={
                "enterprise": True,
                "message": "Enterprise plan requires custom pricing — please Contact Sales",
                "starting_price_usd": pricing["price"],
                "description": pricing["description"],
            },
        )

    if plan == SubscriptionPlan.FREE:
        raise HTTPException(status_code=400, detail="FREE plan does not require checkout")

    success_url = data.get("success_url")
    cancel_url = data.get("cancel_url")

    from app.services import stripe_service

    try:
        session = await stripe_service.create_checkout_session(
            db, workspace, plan, current_user.email, success_url=success_url, cancel_url=cancel_url
        )
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        logger.exception("checkout session failed")
        raise HTTPException(status_code=500, detail=f"Checkout failed: {e}")

    return APIResponse(success=True, data=session)


@router.post("/webhook")
async def stripe_webhook(
    request: Request,
    db: AsyncSession = Depends(get_db),
) -> dict:
    """Stripe webhook endpoint (no auth - verified via stripe signature).

    Handles: checkout.session.completed, invoice.payment_succeeded/failed,
    customer.subscription.deleted/updated. Updates Subscription in DB automatically.

    Configure in Stripe Dashboard: endpoint URL = https://<api>/api/v1/billing/webhook
    Test with: stripe trigger checkout.session.completed, stripe trigger invoice.payment_succeeded
    Or via our POST with JSON body in test mode when STRIPE_WEBHOOK_SECRET empty.
    """
    # Stripe needs raw body for signature verification
    payload = await request.body()
    sig_header = request.headers.get("stripe-signature", "") or request.headers.get("Stripe-Signature", "")

    from app.services import stripe_service

    try:
        event = stripe_service.verify_webhook_signature(payload, sig_header)
    except ValueError as e:
        logger.warning("webhook signature failed: %s", e)
        raise HTTPException(status_code=400, detail=str(e))

    # Dispatch to handler which updates DB
    try:
        result = await stripe_service.handle_webhook_event(db, event)
    except Exception as e:
        logger.exception("webhook handling failed for %s", event.get("type"))
        # Return 200 to prevent Stripe retry storm, but log error
        return {"received": True, "type": event.get("type"), "error": str(e), "status": "logged"}

    return {"received": True, "type": event.get("type"), **result}
