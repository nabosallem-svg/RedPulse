"""RedPulse - API Key Service.

Secure API key generation, hashing, validation, and scope checks
for Public API access.
"""
from __future__ import annotations

import hashlib
import secrets
import logging
from datetime import datetime, timezone, timedelta
from typing import Optional, List, Tuple

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.models import ApiKey, User

logger = logging.getLogger(__name__)

# Allowed scopes for API keys
ALLOWED_SCOPES = {
    "read",
    "write",
    "admin",
    "scan:create",
    "scan:read",
    "finding:read",
    "finding:export",
    "report:export",
    "report:read",
    "webhook:manage",
    "webhook:read",
    "project:read",
    "project:create",
}

# Scope hierarchy: admin > write > read
SCOPE_ALIASES = {
    "admin": ALLOWED_SCOPES,  # admin grants all
    "write": {"read", "write", "scan:create", "scan:read", "finding:read", "finding:export", "report:export", "report:read", "webhook:manage", "webhook:read", "project:read", "project:create"},
}


def _hash_key(plain_key: str) -> str:
    """SHA-256 hash of the plain API key."""
    return hashlib.sha256(plain_key.encode()).hexdigest()


def _generate_token() -> str:
    """Generate a secure random API key with rp_ prefix.

    Returns:
        Full plain token like rp_<random>
    """
    random_part = secrets.token_urlsafe(32)
    return f"rp_{random_part}"


class ApiKeyService:
    """Service for API key lifecycle management."""

    @staticmethod
    def hash_key(plain_key: str) -> str:
        """Public hash helper for validation / tests."""
        return _hash_key(plain_key)

    @staticmethod
    def generate_secret() -> str:
        """Generate a webhook HMAC secret."""
        return secrets.token_urlsafe(32)

    @staticmethod
    async def create_api_key(
        db: AsyncSession,
        user: User,
        name: str,
        scopes: Optional[List[str]] = None,
        workspace_id: Optional[str] = None,
        expires_in_days: Optional[int] = None,
    ) -> Tuple[ApiKey, str]:
        """Create a new API key.

        Args:
            db: Async session.
            user: Owner user.
            name: Human-readable name.
            scopes: List of scopes. Defaults to ["read"].
            workspace_id: Optional workspace binding.
            expires_in_days: Optional expiry in days.

        Returns:
            Tuple of (ApiKey DB record, plain_key string shown once).

        Raises:
            ValueError: If name empty or scopes invalid.
        """
        if not name or not name.strip():
            raise ValueError("API key name is required")

        scopes = scopes or ["read"]

        # Validate scopes
        invalid = [s for s in scopes if s not in ALLOWED_SCOPES]
        if invalid:
            raise ValueError(f"Invalid scopes: {invalid}. Allowed: {sorted(ALLOWED_SCOPES)}")

        plain_key = _generate_token()
        prefix = plain_key[:12]  # e.g. rp_XXXXXXXX
        key_hash = _hash_key(plain_key)

        expires_at = None
        if expires_in_days is not None:
            if expires_in_days <= 0:
                raise ValueError("expires_in_days must be positive")
            expires_at = datetime.now(timezone.utc) + timedelta(days=expires_in_days)

        api_key = ApiKey(
            user_id=user.id,
            workspace_id=workspace_id,
            name=name.strip(),
            prefix=prefix,
            key_hash=key_hash,
            scopes=scopes,
            expires_at=expires_at,
        )
        db.add(api_key)
        await db.commit()
        await db.refresh(api_key)

        logger.info("api_key_created key_id=%s user_id=%s prefix=%s scopes=%s", api_key.id, user.id, prefix, scopes)

        return api_key, plain_key

    @staticmethod
    async def list_api_keys(
        db: AsyncSession,
        user_id: str,
        workspace_id: Optional[str] = None,
    ) -> List[ApiKey]:
        """List API keys for a user (optionally filtered by workspace)."""
        query = select(ApiKey).where(ApiKey.user_id == user_id)
        if workspace_id is not None:
            query = query.where(ApiKey.workspace_id == workspace_id)
        query = query.order_by(ApiKey.created_at.desc())
        result = await db.execute(query)
        return list(result.scalars().all())

    @staticmethod
    async def get_api_key(
        db: AsyncSession,
        key_id: str,
        user_id: str,
    ) -> Optional[ApiKey]:
        """Get a single API key owned by user."""
        result = await db.execute(
            select(ApiKey).where(ApiKey.id == key_id, ApiKey.user_id == user_id)
        )
        return result.scalar_one_or_none()

    @staticmethod
    async def revoke_api_key(
        db: AsyncSession,
        key_id: str,
        user_id: str,
    ) -> Optional[ApiKey]:
        """Revoke (deactivate) an API key."""
        api_key = await ApiKeyService.get_api_key(db, key_id, user_id)
        if not api_key:
            return None
        if not api_key.is_active:
            return api_key
        api_key.is_active = False
        await db.commit()
        await db.refresh(api_key)
        logger.info("api_key_revoked key_id=%s user_id=%s", key_id, user_id)
        return api_key

    @staticmethod
    async def delete_api_key(
        db: AsyncSession,
        key_id: str,
        user_id: str,
    ) -> bool:
        """Delete an API key permanently."""
        api_key = await ApiKeyService.get_api_key(db, key_id, user_id)
        if not api_key:
            return False
        await db.delete(api_key)
        await db.commit()
        logger.info("api_key_deleted key_id=%s user_id=%s", key_id, user_id)
        return True

    @staticmethod
    async def validate_api_key(
        db: AsyncSession,
        plain_key: str,
    ) -> Optional[ApiKey]:
        """Validate a plain API key and return the DB record if valid.

        Checks:
        - Hash matches
        - is_active True
        - Not expired
        Updates last_used_at on success.

        Returns:
            ApiKey if valid, else None.
        """
        if not plain_key or not plain_key.startswith("rp_"):
            return None

        key_hash = _hash_key(plain_key)
        result = await db.execute(
            select(ApiKey).where(ApiKey.key_hash == key_hash)
        )
        api_key = result.scalar_one_or_none()
        if not api_key:
            return None

        if not api_key.is_active:
            logger.warning("api_key_inactive key_id=%s prefix=%s", api_key.id, api_key.prefix)
            return None

        if api_key.expires_at is not None:
            # Handle naive datetime from SQLite
            expires = api_key.expires_at
            if expires.tzinfo is None:
                expires = expires.replace(tzinfo=timezone.utc)
            if datetime.now(timezone.utc) > expires:
                logger.warning("api_key_expired key_id=%s prefix=%s", api_key.id, api_key.prefix)
                return None

        # Update last_used_at (fire-and-forget, don't block)
        try:
            api_key.last_used_at = datetime.now(timezone.utc)
            await db.commit()
            await db.refresh(api_key)
        except Exception:
            await db.rollback()

        return api_key

    @staticmethod
    def has_scope(api_key: ApiKey, required_scope: str) -> bool:
        """Check if an API key has a required scope.

        Logic:
        - Exact match in scopes
        - If key has 'admin', grant all
        - If key has 'write', grant all read-ish scopes
        - If key has 'read' and required is read-ish, grant
        """
        scopes = set(api_key.scopes or [])

        if required_scope in scopes:
            return True

        if "admin" in scopes:
            return True

        # write grants read-level scopes
        if "write" in scopes:
            write_grants = SCOPE_ALIASES.get("write", set())
            if required_scope in write_grants:
                return True

        # read grant? only read scopes
        if required_scope == "read" and "read" in scopes:
            return True

        return False

    @staticmethod
    async def rotate_api_key(
        db: AsyncSession,
        key_id: str,
        user_id: str,
    ) -> Tuple[Optional[ApiKey], Optional[str]]:
        """Rotate an API key: generate new token, update hash, keep metadata.

        Returns:
            Tuple of (updated ApiKey, new_plain_key) or (None, None) if not found.
        """
        api_key = await ApiKeyService.get_api_key(db, key_id, user_id)
        if not api_key:
            return None, None

        new_plain = _generate_token()
        new_prefix = new_plain[:12]
        new_hash = _hash_key(new_plain)

        api_key.prefix = new_prefix
        api_key.key_hash = new_hash
        api_key.is_active = True
        api_key.last_used_at = None

        await db.commit()
        await db.refresh(api_key)

        logger.info("api_key_rotated key_id=%s user_id=%s", key_id, user_id)
        return api_key, new_plain
