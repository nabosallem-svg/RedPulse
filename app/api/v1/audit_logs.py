"""RedPulse - Audit Logs API.

Query and investigate the comprehensive audit trail.
Workspace RBAC enforced: requires workspace:read or project:read.
"""
from __future__ import annotations

import logging
from datetime import datetime
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Request, Query, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_current_user, get_db
from app.db.models import User
from app.services.workspace_service import WorkspaceService
from app.services.audit_service import AuditService

logger = logging.getLogger(__name__)
router = APIRouter(tags=["audit-logs"])


def _log_to_dict(log) -> dict:
    return {
        "id": log.id,
        "user_id": log.user_id,
        "api_key_id": log.api_key_id,
        "workspace_id": log.workspace_id,
        "project_id": log.project_id,
        "action": log.action,
        "resource_type": log.resource_type,
        "resource_id": log.resource_id,
        "details": log.details,
        "ip_address": log.ip_address,
        "user_agent": log.user_agent,
        "status": log.status,
        "created_at": log.created_at.isoformat() if log.created_at else None,
    }


@router.get("/workspaces/{workspace_id}/audit-logs")
async def list_workspace_audit_logs(
    workspace_id: str,
    action: Optional[str] = Query(default=None, description="Filter by action e.g. scan.create"),
    resource_type: Optional[str] = Query(default=None, description="Filter by resource_type e.g. scan, export"),
    resource_id: Optional[str] = Query(default=None),
    user_id: Optional[str] = Query(default=None, description="Filter by actor user id"),
    status: Optional[str] = Query(default=None, description="success or failure"),
    limit: int = Query(default=50, ge=1, le=100),
    offset: int = Query(default=0, ge=0),
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """List audit logs for a workspace with filters + pagination.

    Requires workspace:read permission (viewer+).
    """
    has_access, _ = await WorkspaceService.check_workspace_access(db, workspace_id, current_user.id, "workspace:read")
    if not has_access:
        raise HTTPException(status_code=404, detail="Workspace not found or access denied")

    logs, total = await AuditService.list_logs(
        db,
        workspace_id=workspace_id,
        action=action,
        resource_type=resource_type,
        user_id=user_id,
        status=status,
        limit=limit,
        offset=offset,
    )

    return {
        "success": True,
        "data": [_log_to_dict(l) for l in logs],
        "meta": {"total": total, "limit": limit, "offset": offset},
    }


@router.get("/workspaces/{workspace_id}/audit-logs/recent")
async def recent_activity(
    workspace_id: str,
    limit: int = Query(default=20, ge=1, le=100),
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Get recent activity feed for workspace dashboard."""
    has_access, _ = await WorkspaceService.check_workspace_access(db, workspace_id, current_user.id, "workspace:read")
    if not has_access:
        raise HTTPException(status_code=404, detail="Workspace not found or access denied")

    logs = await AuditService.get_recent_activity(db, workspace_id, limit)
    return {"success": True, "data": [_log_to_dict(l) for l in logs]}


@router.get("/audit-logs/my-activity")
async def my_activity(
    limit: int = Query(default=50, ge=1, le=100),
    offset: int = Query(default=0, ge=0),
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Get current user's own audit activity across all workspaces."""
    logs, total = await AuditService.list_logs(
        db, user_id=current_user.id, limit=limit, offset=offset
    )
    return {
        "success": True,
        "data": [_log_to_dict(l) for l in logs],
        "meta": {"total": total, "limit": limit, "offset": offset},
    }


@router.get("/audit-logs/resource/{resource_type}/{resource_id}")
async def resource_audit_trail(
    resource_type: str,
    resource_id: str,
    limit: int = Query(default=20, ge=1, le=100),
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Get audit trail for a specific resource (e.g. scan id, export id).

    Requires that current user has access to the resource's workspace/project
    - enforced by checking audit logs contain workspace_id and validating membership.
    If no logs found, returns empty list (not 404 to avoid info leak).
    """
    logs = await AuditService.get_logs_for_resource(db, resource_type, resource_id, limit)

    # Filter to only logs where user has workspace access (if logs have workspace_id)
    filtered = []
    for log in logs:
        if not log.workspace_id:
            # Global log: allow owner to see their own actions only
            if log.user_id == current_user.id:
                filtered.append(log)
            continue
        has_access, _ = await WorkspaceService.check_workspace_access(db, log.workspace_id, current_user.id, "workspace:read")
        if has_access:
            filtered.append(log)

    return {"success": True, "data": [_log_to_dict(l) for l in filtered]}
