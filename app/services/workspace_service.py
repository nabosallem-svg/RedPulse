"""RedPulse - Workspace Service.

Multi-tenancy workspace management with RBAC (Admin/Analyst/Viewer).
Every data access goes through workspace isolation.
"""
from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Optional, Tuple, List

from sqlalchemy import select, and_
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.models import (
    Workspace, WorkspaceMember, WorkspaceRole,
    Project, User, Subscription, SubscriptionPlan,
)

logger = logging.getLogger(__name__)

# RBAC permissions matrix
ROLE_PERMISSIONS = {
    WorkspaceRole.ADMIN: {
        "workspace:read", "workspace:write", "workspace:delete",
        "member:read", "member:invite", "member:remove", "member:change_role",
        "project:read", "project:create", "project:delete",
        "scan:read", "scan:create", "scan:cancel",
        "finding:read", "finding:write", "finding:export",
        "report:read", "report:create", "report:export",
        "billing:read", "billing:manage",
        "monitoring:read", "monitoring:create", "monitoring:delete",
        "webhook:read", "webhook:create", "webhook:delete",
    },
    WorkspaceRole.ANALYST: {
        "workspace:read",
        "member:read",
        "project:read", "project:create",
        "scan:read", "scan:create", "scan:cancel",
        "finding:read", "finding:write", "finding:export",
        "report:read", "report:create", "report:export",
        "monitoring:read", "monitoring:create",
        "webhook:read", "webhook:create",
    },
    WorkspaceRole.VIEWER: {
        "workspace:read",
        "member:read",
        "project:read",
        "scan:read",
        "finding:read",
        "report:read",
        "monitoring:read",
        "webhook:read",
    },
}


class WorkspaceService:
    """Service for workspace management and RBAC enforcement."""

    @staticmethod
    def has_permission(role: WorkspaceRole, permission: str) -> bool:
        """Check if a role has a specific permission."""
        return permission in ROLE_PERMISSIONS.get(role, set())

    @staticmethod
    async def create_workspace(
        db: AsyncSession,
        owner: User,
        name: str,
        slug: str,
        description: Optional[str] = None,
    ) -> Workspace:
        """Create a new workspace with the owner as admin."""
        workspace = Workspace(
            name=name,
            slug=slug,
            description=description,
            owner_id=owner.id,
        )
        db.add(workspace)
        await db.flush()

        # Add owner as admin member
        member = WorkspaceMember(
            workspace_id=workspace.id,
            user_id=owner.id,
            role=WorkspaceRole.ADMIN,
        )
        db.add(member)

        # Create free subscription
        subscription = Subscription(
            workspace_id=workspace.id,
            plan=SubscriptionPlan.FREE,
            max_projects=1,
            max_scans_per_day=5,
            max_assets_per_project=100,
            monthly_credits=100,
        )
        db.add(subscription)

        await db.commit()
        await db.refresh(workspace)
        return workspace

    @staticmethod
    async def get_user_workspaces(
        db: AsyncSession,
        user_id: str,
    ) -> List[Workspace]:
        """Get all workspaces a user is a member of."""
        result = await db.execute(
            select(Workspace)
            .join(WorkspaceMember, WorkspaceMember.workspace_id == Workspace.id)
            .where(
                WorkspaceMember.user_id == user_id,
                Workspace.is_active == True,
            )
            .order_by(Workspace.created_at.desc())
        )
        return result.scalars().all()

    @staticmethod
    async def get_workspace_member(
        db: AsyncSession,
        workspace_id: str,
        user_id: str,
    ) -> Optional[WorkspaceMember]:
        """Get a user's membership in a workspace."""
        result = await db.execute(
            select(WorkspaceMember).where(
                WorkspaceMember.workspace_id == workspace_id,
                WorkspaceMember.user_id == user_id,
            )
        )
        return result.scalar_one_or_none()

    @staticmethod
    async def check_workspace_access(
        db: AsyncSession,
        workspace_id: str,
        user_id: str,
        permission: str,
    ) -> Tuple[bool, Optional[WorkspaceRole]]:
        """Check if a user has a specific permission in a workspace.

        Returns:
            Tuple of (has_access: bool, role: Optional[WorkspaceRole])
        """
        member = await WorkspaceService.get_workspace_member(db, workspace_id, user_id)
        if not member:
            return False, None

        if not WorkspaceService.has_permission(member.role, permission):
            return False, member.role

        return True, member.role

    @staticmethod
    async def require_workspace_access(
        db: AsyncSession,
        workspace_id: str,
        user_id: str,
        permission: str,
    ) -> WorkspaceRole:
        """Require a user to have a specific permission in a workspace.

        Raises PermissionError if access is denied.
        """
        has_access, role = await WorkspaceService.check_workspace_access(
            db, workspace_id, user_id, permission,
        )
        if not has_access:
            raise PermissionError(
                f"User {user_id} does not have '{permission}' permission "
                f"in workspace {workspace_id}"
            )
        return role

    @staticmethod
    async def invite_member(
        db: AsyncSession,
        workspace_id: str,
        inviter_id: str,
        invitee_email: str,
        role: WorkspaceRole,
    ) -> WorkspaceMember:
        """Invite a user to a workspace (or update their role)."""
        # Check inviter has permission
        await WorkspaceService.require_workspace_access(
            db, workspace_id, inviter_id, "member:invite",
        )

        # Find the invitee
        result = await db.execute(
            select(User).where(User.email == invitee_email)
        )
        invitee = result.scalar_one_or_none()
        if not invitee:
            raise ValueError(f"User with email {invitee_email} not found")

        # Check if already a member
        existing = await WorkspaceService.get_workspace_member(
            db, workspace_id, invitee.id,
        )
        if existing:
            # Update role
            existing.role = role
            await db.commit()
            await db.refresh(existing)
            return existing

        # Create new member
        member = WorkspaceMember(
            workspace_id=workspace_id,
            user_id=invitee.id,
            role=role,
            invited_by=inviter_id,
        )
        db.add(member)
        await db.commit()
        await db.refresh(member)
        return member

    @staticmethod
    async def remove_member(
        db: AsyncSession,
        workspace_id: str,
        remover_id: str,
        member_id: str,
    ) -> bool:
        """Remove a member from a workspace."""
        await WorkspaceService.require_workspace_access(
            db, workspace_id, remover_id, "member:remove",
        )

        result = await db.execute(
            select(WorkspaceMember).where(
                WorkspaceMember.id == member_id,
                WorkspaceMember.workspace_id == workspace_id,
            )
        )
        member = result.scalar_one_or_none()
        if not member:
            return False

        # Cannot remove the workspace owner
        if member.role == WorkspaceRole.ADMIN:
            # Check if this is the only admin
            admin_count = await db.execute(
                select(WorkspaceMember).where(
                    WorkspaceMember.workspace_id == workspace_id,
                    WorkspaceMember.role == WorkspaceRole.ADMIN,
                )
            )
            if len(admin_count.scalars().all()) <= 1:
                raise ValueError("Cannot remove the last admin from a workspace")

        await db.delete(member)
        await db.commit()
        return True

    @staticmethod
    async def get_workspace_projects(
        db: AsyncSession,
        workspace_id: str,
        user_id: str,
    ) -> List[Project]:
        """Get all projects in a workspace (with access check)."""
        await WorkspaceService.require_workspace_access(
            db, workspace_id, user_id, "project:read",
        )

        result = await db.execute(
            select(Project).where(
                Project.workspace_id == workspace_id,
            ).order_by(Project.created_at.desc())
        )
        return result.scalars().all()

    @staticmethod
    async def get_workspace_stats(
        db: AsyncSession,
        workspace_id: str,
    ) -> dict:
        """Get workspace statistics."""
        from sqlalchemy import func

        member_count = await db.execute(
            select(func.count()).select_from(WorkspaceMember).where(
                WorkspaceMember.workspace_id == workspace_id,
            )
        )
        project_count = await db.execute(
            select(func.count()).select_from(Project).where(
                Project.workspace_id == workspace_id,
            )
        )

        return {
            "member_count": member_count.scalar() or 0,
            "project_count": project_count.scalar() or 0,
        }
