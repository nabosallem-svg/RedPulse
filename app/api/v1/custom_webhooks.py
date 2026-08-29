"""RedPulse - Custom Webhooks API (Phase 10).

Workspace-level webhooks with HMAC signing, event filtering,
retry, and delivery history.
"""
from __future__ import annotations

import logging
from typing import Optional, List

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, Field
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_current_user, get_db
from app.db.models import User
from app.services.workspace_service import WorkspaceService
from app.services.custom_webhook_service import CustomWebhookService, ALLOWED_EVENTS
from app.services.audit_service import AuditService

logger = logging.getLogger(__name__)
router = APIRouter(tags=["custom-webhooks"])


class CustomWebhookCreateRequest(BaseModel):
    name: str = Field(..., max_length=255)
    url: str = Field(..., max_length=2000, description="https:// webhook URL")
    events: Optional[List[str]] = Field(default=None, description="Subscribed events; defaults to [scan.completed]")
    secret: Optional[str] = Field(default=None, max_length=255, description="HMAC secret; auto-generated if not provided")
    headers: Optional[dict] = Field(default=None, description="Custom headers")
    is_active: Optional[bool] = True


class CustomWebhookUpdateRequest(BaseModel):
    name: Optional[str] = Field(default=None, max_length=255)
    url: Optional[str] = Field(default=None, max_length=2000)
    events: Optional[List[str]] = None
    headers: Optional[dict] = None
    is_active: Optional[bool] = None
    secret: Optional[str] = Field(default=None, max_length=255)


def _to_dict(w, include_secret: bool = False) -> dict:
    d = {
        "id": w.id,
        "workspace_id": w.workspace_id,
        "user_id": w.user_id,
        "name": w.name,
        "url": w.url,
        "events": w.events,
        "is_active": w.is_active,
        "headers": w.headers,
        "last_triggered_at": w.last_triggered_at.isoformat() if w.last_triggered_at else None,
        "last_status": w.last_status,
        "failure_count": w.failure_count,
        "created_at": w.created_at.isoformat() if w.created_at else None,
        "updated_at": w.updated_at.isoformat() if w.updated_at else None,
    }
    if include_secret:
        d["secret"] = w.secret
    else:
        # Mask secret
        d["secret_masked"] = (w.secret[:4] + "***" if w.secret else None)
    return d


@router.post("/workspaces/{workspace_id}/webhooks", status_code=status.HTTP_201_CREATED)
async def create_custom_webhook(
    workspace_id: str,
    data: CustomWebhookCreateRequest,
    request: Request,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Create a custom webhook for a workspace. Requires webhook:manage permission."""
    has_access, _ = await WorkspaceService.check_workspace_access(db, workspace_id, current_user.id, "webhook:create")
    if not has_access:
        # Check if workspace exists but permission denied -> 403 else 404 semantics
        # For simplicity, return 404 if no access
        raise HTTPException(status_code=404, detail="Workspace not found or access denied")

    try:
        webhook = await CustomWebhookService.create_webhook(
            db, workspace_id, current_user.id,
            name=data.name, url=data.url, events=data.events,
            secret=data.secret, headers=data.headers,
        )
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

    try:
        await AuditService.log(
            db, action="webhook.create", resource_type="webhook", resource_id=webhook.id,
            user_id=current_user.id, workspace_id=workspace_id,
            details={"name": data.name, "url": data.url, "events": data.events},
            request=request,
        )
    except Exception:
        pass

    return {"success": True, "data": _to_dict(webhook, include_secret=True)}


@router.get("/workspaces/{workspace_id}/webhooks")
async def list_custom_webhooks(
    workspace_id: str,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """List custom webhooks for a workspace."""
    has_access, _ = await WorkspaceService.check_workspace_access(db, workspace_id, current_user.id, "webhook:read")
    if not has_access:
        raise HTTPException(status_code=404, detail="Workspace not found or access denied")

    webhooks = await CustomWebhookService.list_webhooks(db, workspace_id)
    return {"success": True, "data": [_to_dict(w) for w in webhooks]}


@router.get("/workspaces/{workspace_id}/webhooks/{webhook_id}")
async def get_custom_webhook(
    workspace_id: str,
    webhook_id: str,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Get a single custom webhook."""
    has_access, _ = await WorkspaceService.check_workspace_access(db, workspace_id, current_user.id, "webhook:read")
    if not has_access:
        raise HTTPException(status_code=404, detail="Workspace not found or access denied")

    webhook = await CustomWebhookService.get_webhook(db, webhook_id, workspace_id)
    if not webhook:
        raise HTTPException(status_code=404, detail="Webhook not found")

    return {"success": True, "data": _to_dict(webhook, include_secret=True)}


@router.patch("/workspaces/{workspace_id}/webhooks/{webhook_id}")
async def update_custom_webhook(
    workspace_id: str,
    webhook_id: str,
    data: CustomWebhookUpdateRequest,
    request: Request,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Update a custom webhook."""
    has_access, _ = await WorkspaceService.check_workspace_access(db, workspace_id, current_user.id, "webhook:create")
    if not has_access:
        raise HTTPException(status_code=404, detail="Workspace not found or access denied")

    updates = {k: v for k, v in data.model_dump(exclude_unset=True).items() if v is not None}
    if not updates:
        raise HTTPException(status_code=400, detail="No fields to update")

    try:
        webhook = await CustomWebhookService.update_webhook(db, webhook_id, workspace_id, updates)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

    if not webhook:
        raise HTTPException(status_code=404, detail="Webhook not found")

    try:
        await AuditService.log(
            db, action="webhook.update", resource_type="webhook", resource_id=webhook_id,
            user_id=current_user.id, workspace_id=workspace_id,
            details=updates, request=request,
        )
    except Exception:
        pass

    return {"success": True, "data": _to_dict(webhook, include_secret=True)}


@router.delete("/workspaces/{workspace_id}/webhooks/{webhook_id}")
async def delete_custom_webhook(
    workspace_id: str,
    webhook_id: str,
    request: Request,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Delete a custom webhook."""
    has_access, _ = await WorkspaceService.check_workspace_access(db, workspace_id, current_user.id, "webhook:create")
    if not has_access:
        raise HTTPException(status_code=404, detail="Workspace not found or access denied")

    ok = await CustomWebhookService.delete_webhook(db, webhook_id, workspace_id)
    if not ok:
        raise HTTPException(status_code=404, detail="Webhook not found")

    try:
        await AuditService.log(
            db, action="webhook.delete", resource_type="webhook", resource_id=webhook_id,
            user_id=current_user.id, workspace_id=workspace_id,
            request=request,
        )
    except Exception:
        pass

    return {"success": True, "data": {"deleted": True, "id": webhook_id}}


@router.post("/workspaces/{workspace_id}/webhooks/{webhook_id}/test")
async def test_custom_webhook(
    workspace_id: str,
    webhook_id: str,
    request: Request,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Send a test delivery to a webhook. Returns delivery result with HMAC signature."""
    has_access, _ = await WorkspaceService.check_workspace_access(db, workspace_id, current_user.id, "webhook:read")
    if not has_access:
        raise HTTPException(status_code=404, detail="Workspace not found or access denied")

    try:
        result = await CustomWebhookService.test_delivery(db, webhook_id, workspace_id)
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))

    try:
        await AuditService.log(
            db, action="webhook.test", resource_type="webhook", resource_id=webhook_id,
            user_id=current_user.id, workspace_id=workspace_id,
            details=result, request=request,
            status="success" if result.get("success") else "failure",
        )
    except Exception:
        pass

    return {"success": True, "data": result}


@router.get("/workspaces/{workspace_id}/webhooks/meta/events")
async def list_allowed_events(
    workspace_id: str,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """List allowed webhook events."""
    has_access, _ = await WorkspaceService.check_workspace_access(db, workspace_id, current_user.id, "webhook:read")
    if not has_access:
        raise HTTPException(status_code=404, detail="Workspace not found or access denied")
    return {"success": True, "data": {"events": sorted(list(ALLOWED_EVENTS)), "wildcard": "*"}}
