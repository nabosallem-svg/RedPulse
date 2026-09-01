"""RedPulse - Billing & Credits Service.

Stripe integration for subscriptions and credits management.
"""
from __future__ import annotations

import logging
from datetime import datetime, timezone, timedelta
from typing import Optional, Tuple, Dict, Any

from sqlalchemy import select, and_
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.models import (
    Subscription, SubscriptionPlan, SubscriptionStatus,
    CreditBalance, CreditTransaction, CreditType,
    Workspace,
)

logger = logging.getLogger(__name__)

# Plan migration map for existing subscriptions
# Maps old plan values (from before this update) to new SubscriptionPlan enum values
PLAN_MIGRATION_MAP: dict[str, SubscriptionPlan] = {
    # Old plan values -> new plan values
    "free": SubscriptionPlan.FREE,
    "professional": SubscriptionPlan.PRO,
    "pro": SubscriptionPlan.PRO,
    "business": SubscriptionPlan.BUSINESS,
    "team": SubscriptionPlan.TEAM,
    "enterprise": SubscriptionPlan.ENTERPRISE,
    "enterprise_old": SubscriptionPlan.ENTERPRISE,
}


def migrate_subscription_plan(plan_value: str) -> SubscriptionPlan:
    """Map an old plan value to the new SubscriptionPlan enum.

    This ensures backward compatibility with existing subscriptions.
    """
    return PLAN_MIGRATION_MAP.get(plan_value.lower().strip(), SubscriptionPlan.FREE)


@staticmethod
def get_subscription_plan_from_subscription(sub: Subscription) -> SubscriptionPlan:
    """Get the effective SubscriptionPlan for a subscription, handling migration.

    This is used when reading subscription data to ensure old plan values
    are properly mapped to new enum values.
    """
    return migrate_subscription_plan(sub.plan)


# Official pricing (source of truth — never read from frontend)
PRICES: Dict[SubscriptionPlan, int] = {
    SubscriptionPlan.FREE: 0,
    SubscriptionPlan.BUSINESS: 49,
    SubscriptionPlan.PRO: 149,
    SubscriptionPlan.TEAM: 399,
    SubscriptionPlan.ENTERPRISE: 900,
}


# Plan definitions with limits and metadata
# Centralized source of truth — backend is the source of truth for plan pricing
PLAN_ENTITLEMENT_MATRIX: Dict[SubscriptionPlan, dict] = {
    # {plan: {features: [...], limits: {...}, description: ..., target_user: ...}}
    SubscriptionPlan.FREE: {
        "features": [
            "1 project experience",
            "5 scans/day max",
            "100 assets/project",
            "1 monitoring schedule",
            "100 monthly credits",
            "Basic report export",
        ],
        "limits": {
            "max_projects": 1,
            "max_scans_per_day": 5,
            "max_assets_per_project": 100,
            "max_monitoring_schedules": 1,
            "monthly_credits": 100,
            "price_monthly": 0,
        },
        "description": "Individual / getting started — not for commercial use",
        "target_user": "Individual / getting started",
    },
    SubscriptionPlan.BUSINESS: {
        "features": [
            "3 projects",
            "50 scans/day",
            "1,000 assets/project",
            "10 monitoring schedules",
            "2,000 monthly credits",
            "Priority support",
            "Basic automation",
        ],
        "limits": {
            "max_projects": 3,
            "max_scans_per_day": 50,
            "max_assets_per_project": 1000,
            "max_monitoring_schedules": 10,
            "monthly_credits": 2000,
            "price_monthly": 49,
        },
        "description": "Individual Bug Bounty Researchers — Recon, Asset Discovery, Scanning, Findings, Reports",
        "target_user": "Individual Bug Bounty Researchers",
    },
    SubscriptionPlan.PRO: {
        "features": [
            "10 projects",
            "150 scans/day",
            "5,000 assets/project",
            "30 monitoring schedules",
            "5,000 monthly credits",
            "Advanced AI analysis",
            "Custom reports",
            "Automation at scale",
        ],
        "limits": {
            "max_projects": 10,
            "max_scans_per_day": 150,
            "max_assets_per_project": 5000,
            "max_monitoring_schedules": 30,
            "monthly_credits": 5000,
            "price_monthly": 149,
        },
        "description": "Professional pentesters / freelancers — Advanced features, client projects",
        "target_user": "Professional Pentesters / Freelancers",
    },
    SubscriptionPlan.TEAM: {
        "features": [
            "25 projects",
            "300 scans/day",
            "10,000 assets/project",
            "100 monitoring schedules",
            "15,000 monthly credits",
            "Team dashboard",
            "Collaborative findings",
            "Priority support",
            "Shared workspace organization",
        ],
        "limits": {
            "max_projects": 25,
            "max_scans_per_day": 300,
            "max_assets_per_project": 10000,
            "max_monitoring_schedules": 100,
            "monthly_credits": 15000,
            "price_monthly": 399,
        },
        "description": "Small Security Teams — Multiple users, shared projects, client/project organization",
        "target_user": "Small Security Teams",
    },
    SubscriptionPlan.ENTERPRISE: {
        "features": [
            "Unlimited projects",
            "Unlimited scans/day",
            "Unlimited assets/project",
            "Unlimited monitoring schedules",
            "50,000 monthly credits",
            "Dedicated account manager",
            "Custom integrations (if available)",
            "SLA guarantee",
            "On-premise option",
            "Advanced analytics",
            "Custom reporting",
        ],
        "limits": {
            "max_projects": -1,  # Unlimited
            "max_scans_per_day": -1,
            "max_assets_per_project": -1,
            "max_monitoring_schedules": -1,
            "monthly_credits": 50000,
            "price_monthly": 900,
        },
        "description": "Security companies / larger teams — Custom requirements",
        "target_user": "Security Companies / Larger Teams",
        "custom": True,
    },
}


# Backward-compatible shorthand for limits only (used by existing code)
PLAN_LIMITS: Dict[SubscriptionPlan, dict] = {
    plan: metadata["limits"] for plan, metadata in PLAN_ENTITLEMENT_MATRIX.items()
}


# Human-readable plan display info
# Note: price/currency come from PLAN_METADATA/central config; this provides derived display info
PLAN_DISPLAY: Dict[SubscriptionPlan, dict] = {
    plan: {
        "name": metadata.get("target_user", plan.value.title()),
        "description": metadata.get("description", ""),
        "target_user": metadata.get("target_user", plan.value.title()),
        "features": metadata.get("features", []),
        "is_custom": metadata.get("custom", False),
        "limits_summary": ", ".join(
            f"{k}: {v}" if v != -1 else "unlimited"
            for k, v in metadata.get("limits", {}).items()
        ),
    }
    for plan, metadata in PLAN_ENTITLEMENT_MATRIX.items()
}


# Credit costs per operation (unchanged)
CREDIT_COSTS: dict[str, int] = {
    "scan_quick": 5,
    "scan_standard": 10,
    "scan_deep": 25,
    "recon_subfinder": 2,
    "recon_httpx": 1,
    "recon_nmap": 3,
    "report_export_json": 1,
    "report_export_html": 2,
    "report_export_pdf": 5,
    "ai_analysis": 10,
    "monitoring_cycle": 5,
}


class BillingService:
    """Service for subscription and credits management."""

    @staticmethod
    async def get_subscription(
        db: AsyncSession,
        workspace_id: str,
    ) -> Optional[Subscription]:
        """Get workspace subscription."""
        result = await db.execute(
            select(Subscription).where(Subscription.workspace_id == workspace_id)
        )
        return result.scalar_one_or_none()

    @staticmethod
    async def create_free_subscription(
        db: AsyncSession,
        workspace_id: str,
    ) -> Subscription:
        """Create a free subscription for a new workspace."""
        limits = PLAN_LIMITS[SubscriptionPlan.FREE]
        subscription = Subscription(
            workspace_id=workspace_id,
            plan=SubscriptionPlan.FREE,
            status=SubscriptionStatus.ACTIVE,
            max_projects=limits["max_projects"],
            max_scans_per_day=limits["max_scans_per_day"],
            max_assets_per_project=limits["max_assets_per_project"],
            max_monitoring_schedules=limits["max_monitoring_schedules"],
            monthly_credits=limits["monthly_credits"],
        )
        db.add(subscription)
        await db.commit()
        await db.refresh(subscription)
        return subscription

    @staticmethod
    async def check_plan_limit(
        db: AsyncSession,
        workspace_id: str,
        resource: str,
        current_count: int,
    ) -> Tuple[bool, str]:
        """Check if workspace has reached a plan limit.

        Returns:
            Tuple of (allowed: bool, message: str)
        """
        subscription = await BillingService.get_subscription(db, workspace_id)
        if not subscription:
            return False, "No subscription found"

        limit_attr = f"max_{resource}"
        limit = getattr(subscription, limit_attr, None)
        if limit is None:
            return False, f"Unknown resource: {resource}"

        # -1 means unlimited
        if limit == -1:
            return True, "Unlimited"

        if current_count >= limit:
            return False, (
                f"Plan limit reached: {resource} limit is {limit} "
                f"(current: {current_count}). Upgrade your plan for more."
            )

        return True, f"Within limit ({current_count}/{limit})"

    @staticmethod
    async def get_or_create_credit_balance(
        db: AsyncSession,
        workspace_id: str,
        user_id: str,
    ) -> CreditBalance:
        """Get or create credit balance for a workspace user."""
        result = await db.execute(
            select(CreditBalance).where(
                CreditBalance.workspace_id == workspace_id,
                CreditBalance.user_id == user_id,
            )
        )
        balance = result.scalar_one_or_none()

        if not balance:
            balance = CreditBalance(
                workspace_id=workspace_id,
                user_id=user_id,
                balance=0,
            )
            db.add(balance)
            await db.commit()
            await db.refresh(balance)

        return balance

    @staticmethod
    async def consume_credits(
        db: AsyncSession,
        workspace_id: str,
        user_id: str,
        operation: str,
        reference_id: Optional[str] = None,
    ) -> Tuple[bool, str, int]:
        """Consume credits for an operation.

        Returns:
            Tuple of (success: bool, message: str, remaining: int)
        """
        cost = CREDIT_COSTS.get(operation)
        if cost is None:
            return False, f"Unknown operation: {operation}", 0

        balance = await BillingService.get_or_create_credit_balance(
            db, workspace_id, user_id,
        )

        if balance.balance < cost:
            return False, (
                f"Insufficient credits: need {cost}, have {balance.balance}. "
                f"Purchase more credits or upgrade your plan."
            ), balance.balance

        # Deduct credits
        balance.balance -= cost
        balance.total_consumed += cost

        # Record transaction
        transaction = CreditTransaction(
            balance_id=balance.id,
            workspace_id=workspace_id,
            user_id=user_id,
            credit_type=CreditType.CONSUMED,
            amount=-cost,
            description=f"Consumed for {operation}",
            reference_id=reference_id,
        )
        db.add(transaction)

        # Update subscription usage
        subscription = await BillingService.get_subscription(db, workspace_id)
        if subscription:
            subscription.credits_used_this_period += cost

        await db.commit()
        return True, f"Consumed {cost} credits for {operation}", balance.balance

    @staticmethod
    async def grant_credits(
        db: AsyncSession,
        workspace_id: str,
        user_id: str,
        amount: int,
        description: str = "Monthly credit grant",
    ) -> CreditBalance:
        """Grant credits (e.g., monthly plan allocation)."""
        balance = await BillingService.get_or_create_credit_balance(
            db, workspace_id, user_id,
        )

        balance.balance += amount
        balance.total_granted += amount

        transaction = CreditTransaction(
            balance_id=balance.id,
            workspace_id=workspace_id,
            user_id=user_id,
            credit_type=CreditType.GRANTED,
            amount=amount,
            description=description,
        )
        db.add(transaction)
        await db.commit()
        await db.refresh(balance)
        return balance

    @staticmethod
    async def get_credit_usage(
        db: AsyncSession,
        workspace_id: str,
    ) -> Dict[str, Any]:
        """Get credit usage summary for a workspace."""
        result = await db.execute(
            select(CreditBalance).where(
                CreditBalance.workspace_id == workspace_id,
            )
        )
        balances = result.scalars().all()

        total_balance = sum(b.balance for b in balances)
        total_consumed = sum(b.total_consumed for b in balances)

        # Get subscription for plan limits
        subscription = await BillingService.get_subscription(db, workspace_id)
        monthly_credits = subscription.monthly_credits if subscription else 0
        credits_used = subscription.credits_used_this_period if subscription else 0

        return {
            "total_balance": total_balance,
            "monthly_credits": monthly_credits,
            "credits_used_this_period": credits_used,
            "credits_remaining": monthly_credits - credits_used,
            "total_consumed_all_time": total_consumed,
        }

    @staticmethod
    async def get_usage_summary(
        db: AsyncSession,
        workspace_id: str,
    ) -> Dict[str, Any]:
        """Get comprehensive usage summary for all plan limits.

        Returns current usage vs limits for all tracked resources.
        """
        subscription = await BillingService.get_subscription(db, workspace_id)
        if not subscription:
            return {
                "workspace_id": workspace_id,
                "plan": subscription.plan.value if subscription else "none",
                "resources": {},
            }

        limits = PLAN_LIMITS.get(subscription.plan, PLAN_LIMITS[SubscriptionPlan.FREE])
        resources: Dict[str, dict] = {}

        # Track current counts from subscription
        resource_counts: Dict[str, int] = {
            "projects": 0,
            "scans_today": 0,
            "assets": 0,
            "monitoring_schedules": 0,
        }

        # In a real implementation, these would query the DB for actual counts
        # For now, we derive from subscription data and provide the structure
        resource_names = list(limits.keys())
        for resource in resource_names:
            limit = limits.get(resource, -1)
            # -1 means unlimited
            if limit == -1:
                resources[resource] = {
                    "current": "unlimited",
                    "limit": "unlimited",
                    "remaining": "unlimited",
                    "period": "billing cycle",
                    "over_limit": False,
                }
            else:
                # Current count would come from DB queries in production
                # Here we use subscription usage tracking as example
                current = getattr(subscription, f"current_{resource}", 0) if hasattr(subscription, f"current_{resource}") else 0
                resources[resource] = {
                    "current": current,
                    "limit": limit,
                    "remaining": max(0, limit - current),
                    "period": "billing cycle",
                    "over_limit": current >= limit,
                }

        return {
            "workspace_id": workspace_id,
            "plan": subscription.plan.value,
            "resources": resources,
        }

    @staticmethod
    async def reset_billing_period(
        db: AsyncSession,
        workspace_id: str,
    ) -> Optional[Subscription]:
        """Reset usage counters at the start of a new billing period.

        Should be called by a cron job or scheduler at period start.
        """
        subscription = await BillingService.get_subscription(db, workspace_id)
        if not subscription:
            return None

        subscription.credits_used_this_period = 0
        # Reset any other period-specific counters
        # e.g., current_scans_today, current_assets_this_period, etc.
        subscription.current_scans_today = 0
        subscription.current_assets_this_period = 0
        subscription.current_monitoring_schedules = 0

        subscription.updated_at = datetime.now(timezone.utc)
        db.add(subscription)
        await db.commit()
        await db.refresh(subscription)
        return subscription

    @staticmethod
    def check_resource_limit(
        plan: SubscriptionPlan,
        resource: str,
        current_count: int,
    ) -> dict:
        """Check if a resource count exceeds the plan limit.

        Returns a dict with enforcement info.
        """
        limits = PLAN_LIMITS.get(plan, PLAN_LIMITS[SubscriptionPlan.FREE])
        limit = limits.get(resource)

        if limit is None:
            return {
                "within_limit": True,
                "limit": None,
                "current": current_count,
                "message": "Unknown resource",
            }

        # -1 means unlimited
        if limit == -1:
            return {
                "within_limit": True,
                "limit": None,  # unlimited
                "current": current_count,
                "message": "Unlimited",
            }

        within_limit = current_count < limit
        remaining = max(0, limit - current_count)

        return {
            "within_limit": within_limit,
            "limit": limit,
            "current": current_count,
            "remaining": remaining,
            "over_limit": not within_limit,
            "message": (
                f"Within limit" if within_limit
                else f"Plan limit reached: {resource} limit is {limit} (current: {current_count})"
            ),
        }

    @staticmethod
    def get_plan_limits(plan: SubscriptionPlan) -> dict:
        """Get the limits for a given plan.

        Returns the limits dict for backward compatibility.
        Also returns billing info via the PLAN_METADATA.
        """
        return PLAN_LIMITS.get(plan, PLAN_LIMITS[SubscriptionPlan.FREE])

    @staticmethod
    def get_plan_metadata(plan: SubscriptionPlan) -> dict:
        """Get full plan metadata (name, price, features, limits, etc.)."""
        return PLAN_METADATA.get(plan, PLAN_METADATA[SubscriptionPlan.FREE])

    @staticmethod
    def get_plan_price(plan: SubscriptionPlan) -> int:
        """Get the monthly price in USD for a given plan."""
        return PLAN_METADATA.get(plan, PLAN_METADATA[SubscriptionPlan.FREE])["price"]

    @staticmethod
    def get_plan_billing(plan: SubscriptionPlan) -> str:
        """Get the billing type for a given plan: 'free', 'standard', or 'custom'."""
        return PLAN_METADATA.get(plan, PLAN_METADATA[SubscriptionPlan.FREE])["billing"]

    @staticmethod
    def get_credit_cost(operation: str) -> Optional[int]:
        """Get the credit cost for an operation."""
        return CREDIT_COSTS.get(operation)