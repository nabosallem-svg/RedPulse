"""RedPulse - Idempotency Key Service.

Handles idempotency keys for webhook events and checkout sessions
to ensure safe retry and duplicate-event handling.
"""
from __future__ import annotations

import json
import hashlib
from typing import Optional, Tuple, Dict, Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.models import IdempotencyKey


async def is_duplicate_event(db: AsyncSession, event_id: str) -> bool:
    """Check if an event ID has already been processed.

    Returns True if the event was already processed (duplicate).
    """
    result = await db.execute(
        select(IdempotencyKey).where(IdempotencyKey.event_id == event_id)
    )
    return result.scalar_one_or_none() is not None


async def mark_event_processed(db: AsyncSession, event_id: str, workspace_id: Optional[str] = None, event_type: Optional[str] = None) -> None:
    """Mark an event ID as processed to prevent duplicate handling."""
    # Use a hash of the event_id + workspace_id as the key for uniqueness
    key_hash = hashlib.sha256(f"{event_id}:{workspace_id or ''}".encode()).hexdigest()[:16]
    
    # Check if already exists
    existing = await db.execute(
        select(IdempotencyKey).where(IdempotencyKey.event_id == event_id)
    )
    if existing.scalar_one_or_none() is not None:
        return  # Already marked
    
    key = IdempotencyKey(
        event_id=event_id,
        key_hash=key_hash,
        workspace_id=workspace_id,
        event_type=event_type,
    )
    db.add(key)
    await db.commit()


async def generate_checkout_idempotency_key(workspace_id: str, plan: str, user_id: str) -> str:
    """Generate a unique idempotency key for checkout sessions.

    Ensures that retrying a checkout doesn't create duplicate sessions.
    """
    composite = f"checkout:{workspace_id}:{plan}:{user_id}"
    return hashlib.sha256(composite.encode()).hexdigest()[:32]


idempotency_key = generate_checkout_idempotency_key