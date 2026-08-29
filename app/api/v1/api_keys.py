"""RedPulse - API Keys Management API.

JWT-authenticated endpoints for creating, listing, and revoking API keys.
Public API usage is via X-API-Key header on /api/v1/public/*.
"""
from __future__ import annotations

import logging
from typing import Optional, List

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, Field
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_current_user, get_db
from app.db.models import User
from app.services.api_key_service import ApiKeyService, ALLOWED_SCOPES
from app.services.audit_service import AuditService

logger = logging.getLogger(__name__)
router = APIRouter(tags=["api-keys"])


class ApiKeyCreateRequest(BaseModel):
    name: str = Field(..., max_length=255, description="Human-readable key name")
    scopes: Optional[List[str]] = Field(default=None, description="Scopes e.g. ['read', 'scan:create']")
    workspace_id: Optional[str] = Field(default=None, description="Optional workspace binding")
    expires_in_days: Optional[int] = Field(default=None, ge=1, le=365, description="Expiry in days")


class ApiKeyCreateResponse(BaseModel):
    id: str
    name: str
    prefix: str
    scopes: List[str]
    workspace_id: Optional[str] = None
    is_active: bool
    expires_at: Optional[str] = None
    created_at: Optional[str] = None
    # Plain key shown ONLY once
    api_key: str = Field(..., description="Full API key - store securely, shown only once!")


class ApiKeyResponse(BaseModel):
    id: str
    name: str
    prefix: str
    scopes: List[str]
    workspace_id: Optional[str] = None
    is_active: bool
    expires_at: Optional[str] = None
    last_used_at: Optional[str] = None
    created_at: Optional[str] = None


def _to_response(key, include_plain: Optional[str] = None) -> dict:
    base = {
        "id": key.id,
        "name": key.name,
        "prefix": key.prefix,
        "scopes": key.scopes,
        "workspace_id": key.workspace_id,
        "is_active": key.is_active,
        "expires_at": key.expires_at.isoformat() if key.expires_at else None,
        "created_at": key.created_at.isoformat() if key.created_at else None,
        "last_used_at": key.last_used_at.isoformat() if key.last_used_at else None,
    }
    if include_plain:
        base["api_key"] = include_plain
    return base


@router.post("", status_code=status.HTTP_201_CREATED)
async def create_api_key(
    data: ApiKeyCreateRequest,
    request: Request,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Create a new API key. The full key is returned only once - store it securely."""
    # Optional workspace validation if provided
    workspace_id = data.workspace_id
    if workspace_id:
        from app.services.workspace_service import WorkspaceService
        has_access, _ = await WorkspaceService.check_workspace_access(db, workspace_id, current_user.id, "workspace:read")
        if not has_access:
            raise HTTPException(status_code=404, detail="Workspace not found or access denied")

    try:
        api_key, plain = await ApiKeyService.create_api_key(
            db, current_user,
            name=data.name,
            scopes=data.scopes,
            workspace_id=workspace_id,
            expires_in_days=data.expires_in_days,
        )
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

    # Audit log
    try:
        await AuditService.log(
            db, action="api_key.create", resource_type="api_key", resource_id=api_key.id,
            user_id=current_user.id, workspace_id=workspace_id,
            details={"name": data.name, "scopes": data.scopes, "prefix": api_key.prefix},
            request=request, status="success",
        )
    except Exception:
        pass

    return {"success": True, "data": _to_response(api_key, include_plain=plain)}


@router.get("")
async def list_api_keys(
    workspace_id: Optional[str] = None,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """List your API keys (optionally filtered by workspace)."""
    keys = await ApiKeyService.list_api_keys(db, current_user.id, workspace_id)
    return {
        "success": True,
        "data": [_to_response(k) for k in keys],
    }


@router.get("/{key_id}")
async def get_api_key(
    key_id: str,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Get a single API key's metadata (prefix, scopes, etc.). Never returns the full key."""
    key = await ApiKeyService.get_api_key(db, key_id, current_user.id)
    if not key:
        raise HTTPException(status_code=404, detail="API key not found")
    return {"success": True, "data": _to_response(key)}


@router.post("/{key_id}/revoke")
async def revoke_api_key(
    key_id: str,
    request: Request,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Revoke an API key (deactivate). The key will no longer be valid."""
    key = await ApiKeyService.revoke_api_key(db, key_id, current_user.id)
    if not key:
        raise HTTPException(status_code=404, detail="API key not found")

    try:
        await AuditService.log(
            db, action="api_key.revoke", resource_type="api_key", resource_id=key_id,
            user_id=current_user.id, workspace_id=key.workspace_id,
            details={"prefix": key.prefix},
            request=request, status="success",
        )
    except Exception:
        pass

    return {"success": True, "data": _to_response(key)}


@router.post("/{key_id}/rotate")
async def rotate_api_key(
    key_id: str,
    request: Request,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Rotate an API key: generate a new token, invalidate the old one, return new token."""
    key, new_plain = await ApiKeyService.rotate_api_key(db, key_id, current_user.id)
    if not key or not new_plain:
        raise HTTPException(status_code=404, detail="API key not found")

    try:
        await AuditService.log(
            db, action="api_key.rotate", resource_type="api_key", resource_id=key_id,
            user_id=current_user.id, workspace_id=key.workspace_id,
            details={"prefix": key.prefix},
            request=request, status="success",
        )
    except Exception:
        pass

    return {"success": True, "data": _to_response(key, include_plain=new_plain)}


@router.delete("/{key_id}", status_code=status.HTTP_200_OK)
async def delete_api_key(
    key_id: str,
    request: Request,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Delete an API key permanently."""
    ok = await ApiKeyService.delete_api_key(db, key_id, current_user.id)
    if not ok:
        raise HTTPException(status_code=404, detail="API key not found")

    try:
        await AuditService.log(
            db, action="api_key.delete", resource_type="api_key", resource_id=key_id,
            user_id=current_user.id,
            details={"key_id": key_id},
            request=request, status="success",
        )
    except Exception:
        pass

    return {"success": True, "data": {"deleted": True, "id": key_id}}


@router.get("/meta/scopes")
async def list_scopes(
    current_user: User = Depends(get_current_user),
):
    """List all available scopes for API keys."""
    return {"success": True, "data": {"scopes": sorted(ALLOWED_SCOPES), "description": "Scopes define what the API key can do. admin grants all. write grants read + scan + export."}}
