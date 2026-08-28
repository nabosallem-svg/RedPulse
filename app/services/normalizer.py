"""RedPulse - Normalizer.

Normalizes raw tool output into Asset records.
Handles deduplication: multiple tools discovering the same asset
should update last_seen rather than creating duplicates.
"""

import logging
from datetime import datetime, timezone
from typing import Optional
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.models import Asset, AssetType, ReconTool, ReconJob

logger = logging.getLogger("redpulse.normalizer")


def _classify_asset(value: str) -> AssetType:
    """Classify a raw string into an AssetType."""
    value = value.strip().lower()
    if value.startswith("http://") or value.startswith("https://"):
        return AssetType.URL
    # IP detection
    parts = value.split(".")
    if len(parts) == 4 and all(p.isdigit() and 0 <= int(p) <= 255 for p in parts):
        return AssetType.IP
    # Subdomain detection: contains dots beyond base domain
    if "." in value:
        return AssetType.SUBDOMAIN
    return AssetType.DOMAIN


async def upsert_asset(
    db: AsyncSession,
    engagement_id: str,
    value: str,
    asset_type: AssetType,
    source_tool: ReconTool,
    source_job_id: Optional[str] = None,
    port: Optional[int] = None,
    protocol: Optional[str] = None,
    service_name: Optional[str] = None,
    technology: Optional[str] = None,
    http_status: Optional[int] = None,
    http_title: Optional[str] = None,
    ip_address: Optional[str] = None,
) -> Asset:
    """Insert or update an asset. Updates last_seen if already exists.

    Dedup key: engagement_id + value + asset_type.
    """
    result = await db.execute(
        select(Asset).where(
            Asset.engagement_id == engagement_id,
            Asset.value == value,
            Asset.asset_type == asset_type,
        )
    )
    existing = result.scalar_one_or_none()
    now = datetime.now(timezone.utc)

    if existing:
        existing.last_seen = now
        existing.updated_at = now
        # Merge: only update fields that have new data
        if port and not existing.port:
            existing.port = port
        if protocol:
            existing.protocol = protocol
        if service_name:
            existing.service_name = service_name
        if technology and not existing.technology:
            existing.technology = technology
        if http_status:
            existing.http_status = http_status
        if http_title:
            existing.http_title = http_title
        if ip_address:
            existing.ip_address = ip_address
        # Track all sources
        if existing.source_tool != source_tool:
            existing.source_tool = source_tool  # last writer wins
        await db.flush()
        return existing

    asset = Asset(
        engagement_id=engagement_id,
        asset_type=asset_type,
        value=value,
        port=port,
        protocol=protocol,
        service_name=service_name,
        technology=technology,
        http_status=http_status,
        http_title=http_title,
        ip_address=ip_address,
        source_tool=source_tool,
        source_job_id=source_job_id,
        first_seen=now,
        last_seen=now,
    )
    db.add(asset)
    await db.flush()
    return asset


async def normalize_subfinder_results(
    db: AsyncSession,
    engagement_id: str,
    job_id: str,
    subdomains: list[str],
) -> list[Asset]:
    """Normalize subfinder results into Asset records."""
    assets = []
    for sub in subdomains:
        sub = sub.strip().lower()
        if not sub:
            continue
        asset = await upsert_asset(
            db=db,
            engagement_id=engagement_id,
            value=sub,
            asset_type=_classify_asset(sub),
            source_tool=ReconTool.SUBFINDER,
            source_job_id=job_id,
        )
        assets.append(asset)
    await db.commit()
    return assets


async def normalize_httpx_results(
    db: AsyncSession,
    engagement_id: str,
    job_id: str,
    httpx_records: list[dict],
) -> list[Asset]:
    """Normalize httpx results into Asset records."""
    assets = []
    for rec in httpx_records:
        host = rec.get("host", "").strip().lower()
        if not host:
            continue
        tech = ", ".join(rec.get("technologies", [])) if rec.get("technologies") else None
        asset = await upsert_asset(
            db=db,
            engagement_id=engagement_id,
            value=host,
            asset_type=_classify_asset(host),
            source_tool=ReconTool.HTTPX,
            source_job_id=job_id,
            port=rec.get("port"),
            protocol=rec.get("protocol"),
            http_status=rec.get("status_code"),
            http_title=rec.get("title"),
            ip_address=rec.get("ip"),
            technology=tech,
            service_name=rec.get("webserver"),
        )
        assets.append(asset)
    await db.commit()
    return assets


async def normalize_nmap_results(
    db: AsyncSession,
    engagement_id: str,
    job_id: str,
    nmap_records: list[dict],
) -> list[Asset]:
    """Normalize nmap results into Asset records."""
    assets = []
    for rec in nmap_records:
        host = rec.get("host", "").strip().lower()
        if not host:
            continue
        svc = f"{rec.get('product', '')} {rec.get('version', '')}".strip() or rec.get("service", "")
        asset = await upsert_asset(
            db=db,
            engagement_id=engagement_id,
            value=host,
            asset_type=_classify_asset(host),
            source_tool=ReconTool.NMAP,
            source_job_id=job_id,
            port=rec.get("port"),
            protocol=rec.get("protocol"),
            service_name=svc,
            ip_address=rec.get("ip"),
        )
        assets.append(asset)
    await db.commit()
    return assets
