"""Phase 9 SaaS Layer Tests.

Tests for:
- Workspace model and multi-tenancy isolation
- Workspace RBAC (Admin/Analyst/Viewer)
- Subscription/Billing (Stripe) and Credits
- Duplicate Prediction
"""
import pytest
import pytest_asyncio
from httpx import AsyncClient, ASGITransport
from unittest.mock import AsyncMock, patch, MagicMock
from sqlalchemy import select
from datetime import datetime, timedelta, timezone

from app.db.models import (
    Workspace, WorkspaceMember, WorkspaceRole,
    Subscription, SubscriptionPlan, SubscriptionStatus,
    CreditBalance, CreditTransaction, CreditType,
    DuplicatePrediction, Finding, FindingSeverity, FindingStatus,
    Project, User, Engagement, EngagementStatus,
)
from app.services.workspace_service import WorkspaceService, ROLE_PERMISSIONS
from app.services.billing_service import BillingService, PLAN_LIMITS, CREDIT_COSTS
from app.services.duplicate_predictor import DuplicatePredictor


# ==================== Workspace Model Tests ====================


class TestWorkspaceModel:
    """Test workspace model and multi-tenancy."""

    def test_workspace_role_enum(self):
        assert WorkspaceRole.ADMIN.value == "admin"
        assert WorkspaceRole.ANALYST.value == "analyst"
        assert WorkspaceRole.VIEWER.value == "viewer"

    def test_subscription_plan_enum(self):
        assert SubscriptionPlan.FREE.value == "free"
        assert SubscriptionPlan.PRO.value == "pro"
        assert SubscriptionPlan.BUSINESS.value == "business"
        assert SubscriptionPlan.ENTERPRISE.value == "enterprise"

    def test_subscription_status_enum(self):
        assert SubscriptionStatus.ACTIVE.value == "active"
        assert SubscriptionStatus.CANCELED.value == "canceled"

    def test_credit_type_enum(self):
        assert CreditType.GRANTED.value == "granted"
        assert CreditType.CONSUMED.value == "consumed"


# ==================== RBAC Tests ====================


class TestRBAC:
    """Test role-based access control."""

    def test_admin_has_all_permissions(self):
        admin_perms = ROLE_PERMISSIONS[WorkspaceRole.ADMIN]
        assert "billing:manage" in admin_perms
        assert "member:remove" in admin_perms
        assert "workspace:delete" in admin_perms
        assert "project:create" in admin_perms
        assert "scan:create" in admin_perms

    def test_analyst_can_scan_and_export(self):
        analyst_perms = ROLE_PERMISSIONS[WorkspaceRole.ANALYST]
        assert "scan:create" in analyst_perms
        assert "finding:export" in analyst_perms
        assert "report:export" in analyst_perms
        assert "billing:manage" not in analyst_perms
        assert "member:remove" not in analyst_perms

    def test_viewer_read_only(self):
        viewer_perms = ROLE_PERMISSIONS[WorkspaceRole.VIEWER]
        assert "project:read" in viewer_perms
        assert "finding:read" in viewer_perms
        assert "project:create" not in viewer_perms
        assert "scan:create" not in viewer_perms
        assert "finding:write" not in viewer_perms
        assert "report:export" not in viewer_perms

    def test_has_permission_check(self):
        assert WorkspaceService.has_permission(WorkspaceRole.ADMIN, "billing:manage") is True
        assert WorkspaceService.has_permission(WorkspaceRole.ANALYST, "billing:manage") is False
        assert WorkspaceService.has_permission(WorkspaceRole.VIEWER, "project:create") is False
        assert WorkspaceService.has_permission(WorkspaceRole.VIEWER, "project:read") is True


# ==================== Workspace Service Tests ====================


class TestWorkspaceService:
    """Test workspace service operations."""

    @pytest.mark.asyncio
    async def test_create_workspace(self, test_session):
        user = User(id="ws-owner-1", email="ws@test.com", hashed_password="hashed")
        test_session.add(user)
        await test_session.commit()

        workspace = await WorkspaceService.create_workspace(
            test_session, user, "Test Workspace", "test-ws", "Description",
        )
        assert workspace.name == "Test Workspace"
        assert workspace.slug == "test-ws"
        assert workspace.owner_id == "ws-owner-1"

        # Check owner was added as admin
        member = await WorkspaceService.get_workspace_member(
            test_session, workspace.id, "ws-owner-1",
        )
        assert member is not None
        assert member.role == WorkspaceRole.ADMIN

        # Check free subscription was created
        sub = await BillingService.get_subscription(test_session, workspace.id)
        assert sub is not None
        assert sub.plan == SubscriptionPlan.FREE

    @pytest.mark.asyncio
    async def test_check_workspace_access(self, test_session):
        user = User(id="access-user-1", email="access@test.com", hashed_password="hashed")
        test_session.add(user)
        await test_session.commit()

        workspace = await WorkspaceService.create_workspace(
            test_session, user, "Access Test", "access-test",
        )

        has_access, role = await WorkspaceService.check_workspace_access(
            test_session, workspace.id, "access-user-1", "project:create",
        )
        assert has_access is True
        assert role == WorkspaceRole.ADMIN

        # Non-member should not have access
        has_access, role = await WorkspaceService.check_workspace_access(
            test_session, workspace.id, "non-member-id", "project:create",
        )
        assert has_access is False
        assert role is None

    @pytest.mark.asyncio
    async def test_require_workspace_access_raises(self, test_session):
        with pytest.raises(PermissionError):
            await WorkspaceService.require_workspace_access(
                test_session, "fake-workspace", "any-user", "project:create",
            )

    @pytest.mark.asyncio
    async def test_invite_member(self, test_session):
        owner = User(id="inv-owner-1", email="owner@test.com", hashed_password="hashed")
        invitee = User(id="inv-member-1", email="invitee@test.com", hashed_password="hashed")
        test_session.add_all([owner, invitee])
        await test_session.commit()

        workspace = await WorkspaceService.create_workspace(
            test_session, owner, "Invite Test", "invite-test",
        )

        member = await WorkspaceService.invite_member(
            test_session, workspace.id, "inv-owner-1", "invitee@test.com", WorkspaceRole.ANALYST,
        )
        assert member.user_id == "inv-member-1"
        assert member.role == WorkspaceRole.ANALYST

    @pytest.mark.asyncio
    async def test_remove_member(self, test_session):
        owner = User(id="rm-owner-1", email="owner2@test.com", hashed_password="hashed")
        member_user = User(id="rm-member-1", email="member@test.com", hashed_password="hashed")
        test_session.add_all([owner, member_user])
        await test_session.commit()

        workspace = await WorkspaceService.create_workspace(
            test_session, owner, "Remove Test", "remove-test",
        )

        member = await WorkspaceService.invite_member(
            test_session, workspace.id, "rm-owner-1", "member@test.com", WorkspaceRole.VIEWER,
        )

        removed = await WorkspaceService.remove_member(
            test_session, workspace.id, "rm-owner-1", member.id,
        )
        assert removed is True

    @pytest.mark.asyncio
    async def test_cannot_remove_last_admin(self, test_session):
        owner = User(id="la-owner-1", email="lastadmin@test.com", hashed_password="hashed")
        test_session.add(owner)
        await test_session.commit()

        workspace = await WorkspaceService.create_workspace(
            test_session, owner, "Last Admin", "last-admin",
        )

        members = await test_session.execute(
            select(WorkspaceMember).where(WorkspaceMember.workspace_id == workspace.id)
        )
        admin_member = members.scalars().first()

        with pytest.raises(ValueError, match="last admin"):
            await WorkspaceService.remove_member(
                test_session, workspace.id, "la-owner-1", admin_member.id,
            )


# ==================== Billing Service Tests ====================


class TestBillingService:
    """Test billing and credits service."""

    def test_plan_limits_defined(self):
        assert SubscriptionPlan.FREE in PLAN_LIMITS
        assert SubscriptionPlan.PRO in PLAN_LIMITS
        assert SubscriptionPlan.BUSINESS in PLAN_LIMITS
        assert SubscriptionPlan.ENTERPRISE in PLAN_LIMITS

    def test_free_plan_limits(self):
        limits = PLAN_LIMITS[SubscriptionPlan.FREE]
        assert limits["max_projects"] == 1
        assert limits["max_scans_per_day"] == 5
        assert limits["price_monthly"] == 0
        assert limits["monthly_credits"] == 100

    def test_pro_plan_limits(self):
        limits = PLAN_LIMITS[SubscriptionPlan.PRO]
        assert limits["max_projects"] == 10
        assert limits["price_monthly"] == 49
        assert limits["monthly_credits"] == 2000

    def test_enterprise_unlimited(self):
        limits = PLAN_LIMITS[SubscriptionPlan.ENTERPRISE]
        assert limits["max_projects"] == -1  # Unlimited
        assert limits["price_monthly"] == 999

    def test_credit_costs_defined(self):
        assert "scan_quick" in CREDIT_COSTS
        assert "scan_standard" in CREDIT_COSTS
        assert "scan_deep" in CREDIT_COSTS
        assert "report_export_pdf" in CREDIT_COSTS
        assert "ai_analysis" in CREDIT_COSTS

    def test_credit_cost_values(self):
        assert CREDIT_COSTS["scan_quick"] < CREDIT_COSTS["scan_standard"]
        assert CREDIT_COSTS["scan_standard"] < CREDIT_COSTS["scan_deep"]
        assert CREDIT_COSTS["report_export_json"] < CREDIT_COSTS["report_export_pdf"]

    @pytest.mark.asyncio
    async def test_create_free_subscription(self, test_session):
        sub = await BillingService.create_free_subscription(test_session, "ws-billing-1")
        assert sub.plan == SubscriptionPlan.FREE
        assert sub.status == SubscriptionStatus.ACTIVE
        assert sub.monthly_credits == 100

    @pytest.mark.asyncio
    async def test_consume_credits_success(self, test_session):
        balance = CreditBalance(
            workspace_id="ws-credits-1",
            user_id="user-credits-1",
            balance=50,
        )
        test_session.add(balance)
        await test_session.commit()

        success, msg, remaining = await BillingService.consume_credits(
            test_session, "ws-credits-1", "user-credits-1", "scan_quick",
        )
        assert success is True
        assert remaining == 45  # 50 - 5

    @pytest.mark.asyncio
    async def test_consume_credits_insufficient(self, test_session):
        balance = CreditBalance(
            workspace_id="ws-credits-2",
            user_id="user-credits-2",
            balance=2,  # Less than scan_quick cost (5)
        )
        test_session.add(balance)
        await test_session.commit()

        success, msg, remaining = await BillingService.consume_credits(
            test_session, "ws-credits-2", "user-credits-2", "scan_quick",
        )
        assert success is False
        assert "Insufficient" in msg

    @pytest.mark.asyncio
    async def test_grant_credits(self, test_session):
        balance = await BillingService.grant_credits(
            test_session, "ws-grant-1", "user-grant-1", 200, "Test grant",
        )
        assert balance.balance == 200
        assert balance.total_granted == 200

    @pytest.mark.asyncio
    async def test_check_plan_limit(self, test_session):
        sub = await BillingService.create_free_subscription(test_session, "ws-limit-1")

        allowed, msg = await BillingService.check_plan_limit(
            test_session, "ws-limit-1", "projects", 0,
        )
        assert allowed is True

        allowed, msg = await BillingService.check_plan_limit(
            test_session, "ws-limit-1", "projects", 1,
        )
        assert allowed is False  # Free plan: max 1 project


# ==================== Duplicate Prediction Tests ====================


class TestDuplicatePrediction:
    """Test duplicate prediction service."""

    def test_fingerprint_computation(self):
        fp1 = DuplicatePredictor._compute_fingerprint("XSS in login", "cve-2024-1234", "/login")
        fp2 = DuplicatePredictor._compute_fingerprint("XSS in login", "cve-2024-1234", "/login")
        assert fp1 == fp2  # Deterministic

        fp3 = DuplicatePredictor._compute_fingerprint("Different title", "cve-2024-1234", "/login")
        assert fp1 != fp3  # Different input = different fingerprint

    @pytest.mark.asyncio
    async def test_predict_duplicates_no_finding(self, test_session):
        result = await DuplicatePredictor.predict_duplicates(
            test_session, "nonexistent-finding", "ws-dup-1",
        )
        assert result is None

    @pytest.mark.asyncio
    async def test_review_prediction(self, test_session):
        prediction = DuplicatePrediction(
            finding_id="finding-review-1",
            project_id="proj-review-1",
            workspace_id="ws-review-1",
            predicted_duplicate=True,
            confidence_score=0.7,
        )
        test_session.add(prediction)
        await test_session.commit()
        await test_session.refresh(prediction)

        reviewed = await DuplicatePredictor.review_prediction(
            test_session, prediction.id, True, "Confirmed duplicate",
        )
        assert reviewed.reviewed is True
        assert reviewed.is_duplicate is True
        assert reviewed.review_notes == "Confirmed duplicate"

    @pytest.mark.asyncio
    async def test_review_nonexistent_prediction(self, test_session):
        with pytest.raises(ValueError, match="not found"):
            await DuplicatePredictor.review_prediction(
                test_session, "nonexistent", False,
            )

    @pytest.mark.asyncio
    async def test_can_export_with_no_predictions(self, test_session):
        can_export, msg, unreviewed = await DuplicatePredictor.can_export_report(
            test_session, "proj-export-1", "ws-export-1",
        )
        assert can_export is True
        assert len(unreviewed) == 0

    def test_public_sources_defined(self):
        assert "hackerone" in DuplicatePredictor.PUBLIC_SOURCES
        assert "bugcrowd" in DuplicatePredictor.PUBLIC_SOURCES
        assert "cve" in DuplicatePredictor.PUBLIC_SOURCES


# ==================== API Import Tests ====================


class TestSaaSAPIImports:
    """Test that SaaS API endpoints can be imported and are registered."""

    def test_workspace_router_imports(self):
        from app.api.v1.workspaces import router
        assert router is not None
        assert len(router.routes) > 0

    def test_billing_router_imports(self):
        from app.api.v1.billing import router
        assert router is not None
        assert len(router.routes) > 0

    def test_duplicate_prediction_router_imports(self):
        from app.api.v1.duplicate_prediction import router
        assert router is not None
        assert len(router.routes) > 0

    def test_main_app_includes_saas_routers(self):
        from app.main import create_app
        app = create_app()
        from app.api.v1.workspaces import router as ws_router
        from app.api.v1.billing import router as bill_router
        assert len(ws_router.routes) > 0
        assert len(bill_router.routes) > 0


# ==================== Workspace Isolation Tests ====================


class TestWorkspaceIsolation:
    """Test that workspace data is properly isolated."""

    @pytest.mark.asyncio
    async def test_different_workspaces_isolated(self, test_session):
        user1 = User(id="iso-user-1", email="iso1@test.com", hashed_password="h")
        user2 = User(id="iso-user-2", email="iso2@test.com", hashed_password="h")
        test_session.add_all([user1, user2])
        await test_session.commit()

        ws1 = await WorkspaceService.create_workspace(
            test_session, user1, "WS1", "ws1",
        )
        ws2 = await WorkspaceService.create_workspace(
            test_session, user2, "WS2", "ws2",
        )

        # User1 cannot access WS2
        has_access, _ = await WorkspaceService.check_workspace_access(
            test_session, ws2.id, user1.id, "project:read",
        )
        assert has_access is False

        # User2 cannot access WS1
        has_access, _ = await WorkspaceService.check_workspace_access(
            test_session, ws1.id, user2.id, "project:read",
        )
        assert has_access is False

    @pytest.mark.asyncio
    async def test_viewer_cannot_write(self, test_session):
        owner = User(id="viewer-owner", email="vw-owner@test.com", hashed_password="h")
        viewer = User(id="viewer-user", email="vw-viewer@test.com", hashed_password="h")
        test_session.add_all([owner, viewer])
        await test_session.commit()

        ws = await WorkspaceService.create_workspace(
            test_session, owner, "Viewer Test", "viewer-test",
        )
        await WorkspaceService.invite_member(
            test_session, ws.id, owner.id, "vw-viewer@test.com", WorkspaceRole.VIEWER,
        )

        # Viewer cannot create projects
        has_access, _ = await WorkspaceService.check_workspace_access(
            test_session, ws.id, viewer.id, "project:create",
        )
        assert has_access is False

        # Viewer can read projects
        has_access, _ = await WorkspaceService.check_workspace_access(
            test_session, ws.id, viewer.id, "project:read",
        )
        assert has_access is True
