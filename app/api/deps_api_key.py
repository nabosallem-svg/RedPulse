"""RedPulse - API Key Authentication Dependencies.

Provides FastAPI dependencies for authenticating via X-API-Key header
for Public API access. Supports both X-API-Key and Authorization: Bearer rp_...
"""
from __future__ import annotations

from typing import Optional

from fastapi import Depends, HTTPException, Request, status
from fastapi.security import APIKeyHeader
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_db
from app.db.models import ApiKey, User
from app.services.api_key_service import ApiKeyService

# Header scheme: X-API-Key (preferred) or Authorization fallback handled manually
api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)


async def get_api_key(
    request: Request,
    db: AsyncSession = Depends(get_db),
    x_api_key: Optional[str] = Depends(api_key_header),
) -> ApiKey:
    """Authenticate via API key.

    Checks:
    - X-API-Key header first
    - Fallback to Authorization: Bearer rp_...
    Validates hash, active status, expiration, updates last_used_at.

    Raises:
        HTTPException 401 if missing/invalid.
    """
    plain_key = x_api_key

    # Fallback: Authorization: Bearer rp_...
    if not plain_key:
        auth = request.headers.get("authorization") or request.headers.get("Authorization")
        if auth and auth.lower().startswith("bearer "):
            token = auth[7:].strip()
            if token.startswith("rp_"):
                plain_key = token

    if not plain_key:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="API key required: provide X-API-Key header or Authorization: Bearer rp_...",
        )

    api_key = await ApiKeyService.validate_api_key(db, plain_key)
    if not api_key:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired API key",
        )

    return api_key


async def get_api_key_user(
    api_key: ApiKey = Depends(get_api_key),
    db: AsyncSession = Depends(get_db),
) -> User:
    """Resolve User from validated ApiKey."""
    result = await db.execute(select(User).where(User.id == api_key.user_id))
    user = result.scalar_one_or_none()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User for API key not found",
        )
    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User account is disabled",
        )
    return user


def require_api_key_scope(required_scope: str):
    """Factory to create a scope-checking dependency."""
    async def _check(api_key: ApiKey = Depends(get_api_key)) -> ApiKey:
        if not ApiKeyService.has_scope(api_key, required_scope):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"API key missing required scope: {required_scope}. Key scopes: {api_key.scopes}",
            )
        return api_key
    return _check
