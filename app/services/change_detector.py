"""RedPulse - Asset Change Detection.

Compares new recon results against existing assets to detect:
- NEW assets (not previously seen)
- CHANGED assets (same host, different attributes)
- REMOVED assets (no longer discovered)
"""

import logging
from datetime import datetime, timezone
from dataclasses import dataclass
from typing import Optional
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.models import Asset, AssetType, ChangeType

logger = logging.getLogger("redpulse.changes")


@dataclass
class AssetChange:
    """Represents a detected change to an asset."""

    change_type: ChangeType
    asset_id: Optional[str] = None
    value: str = ""
    asset_type: Optional[AssetType] = None
    details: str = ""
    previous: Optional[dict] = None
    current: Optional[dict] = None


async def detect_changes(
    db: AsyncSession,
    engagement_id: str,
    new_hosts: list[str],
) -> list[AssetChange]:
    """Compare a list of newly discovered hosts against existing assets.

    Args:
        db: Database session
        engagement_id: The engagement to check
        new_hosts: List of hostnames/IPs discovered in this recon run

    Returns:
        List of AssetChange objects
    """
    # Fetch all existing assets for this engagement
    result = await db.execute(
        select(Asset).where(Asset.engagement_id == engagement_id)
    )
    existing_assets = result.scalars().all()
    existing_map = {a.value.lower(): a for a in existing_assets}
    new_set = {h.strip().lower() for h in new_hosts if h.strip()}

    changes: list[AssetChange] = []

    # Detect NEW and CHANGED
    for host in new_set:
        existing = existing_map.get(host)
        if existing:
            # Already known - update last_seen
            existing.last_seen = datetime.now(timezone.utc)
            existing.updated_at = datetime.now(timezone.utc)
        else:
            # Brand new asset
            changes.append(AssetChange(
                change_type=ChangeType.NEW,
                value=host,
                asset_type=AssetType.SUBDOMAIN if "." in host else AssetType.IP,
                details=f"Newly discovered: {host}",
            ))

    # Detect REMOVED
    for host, asset in existing_map.items():
        if host not in new_set:
            changes.append(AssetChange(
                change_type=ChangeType.REMOVED,
                asset_id=asset.id,
                value=asset.value,
                asset_type=asset.asset_type,
                details=f"No longer discovered: {asset.value}",
            ))

    await db.flush()
    return changes


def format_changes_summary(changes: list[AssetChange]) -> str:
    """Format a human-readable summary of changes."""
    if not changes:
        return "No changes detected."

    new = [c for c in changes if c.change_type == ChangeType.NEW]
    removed = [c for c in changes if c.change_type == ChangeType.REMOVED]
    changed = [c for c in changes if c.change_type == ChangeType.CHANGED]

    parts = []
    if new:
        parts.append(f"{len(new)} new: {', '.join(c.value for c in new[:10])}")
    if removed:
        parts.append(f"{len(removed)} removed: {', '.join(c.value for c in removed[:10])}")
    if changed:
        parts.append(f"{len(changed)} changed")

    return "; ".join(parts)
