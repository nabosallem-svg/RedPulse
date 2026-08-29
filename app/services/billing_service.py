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

# Plan definitions with limits
PLAN_LIMITS = {
    SubscriptionPlan.FREE: {
        "max_projects": 1,
        "max_scans_per_day": 5,
        "max_assets_per_project": 100,
        "max_monitoring_schedules": 1,
        "monthly_credits": 100,
        "price_monthly": 0,
    },
    SubscriptionPlan.PRO: {
        "max_projects": 10,
        "max_scans_per_day": 50,
        "max_assets_per_project": 1000,
        "max_monitoring_schedules": 10,
        "monthly_credits": 2000,
        "price_monthly": 49,
    },
    SubscriptionPlan.BUSINESS: {
        "max_projects": 50,
        "max_scans_per_day": 200,
        "max_assets_per_project": 5000,
        "max_monitoring_schedules": 50,
        "monthly_credits": 10000,
        "price_monthly": 199,
    },
    SubscriptionPlan.ENTERPRISE: {
        "max_projects": -1,  # Unlimited
        "max_scans_per_day": -1,
        "max_assets_per_project": -1,
        "max_monitoring_schedules": -1,
        "monthly_credits": 50000,
        "price_monthly": 999,
    },
}

# Credit costs per operation
CREDIT_COSTS = {
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
    def get_plan_limits(plan: SubscriptionPlan) -> dict:
        """Get the limits for a given plan."""
        return PLAN_LIMITS.get(plan, PLAN_LIMITS[SubscriptionPlan.FREE])

    @staticmethod
    def get_credit_cost(operation: str) -> Optional[int]:
        """Get the credit cost for an operation."""
        return CREDIT_COSTS.get(operation)
