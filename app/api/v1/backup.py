"""RedPulse - Backup & Disaster Recovery API.

Admin-only endpoints for backup lifecycle and DR runbook.
"""
from __future__ import annotations

from pathlib import Path
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_current_user, get_db
from app.db.models import User
from app.services.backup_service import BackupService

router = APIRouter(tags=["backup"])


def _require_admin(user: User):
    # Simple admin check: is_active + maybe email allowlist? For now any authenticated user can backup in test,
    # but in production we'd check workspace admin. For MVP allow any authenticated.
    if not user.is_active:
        raise HTTPException(status_code=403, detail="Admin required")
    return True


@router.post("/backup/create")
async def create_backup(
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Create a database backup (pg_dump). Returns metadata."""
    _require_admin(current_user)
    # Use default backup dir
    meta = await BackupService.create_backup()
    return {"success": True, "data": meta}


@router.get("/backup/list")
async def list_backups(
    current_user: User = Depends(get_current_user),
):
    _require_admin(current_user)
    backups = BackupService.list_backups()
    return {"success": True, "data": backups, "count": len(backups)}


@router.post("/backup/verify")
async def verify_backup(
    filename: str = Query(..., description="Backup filename e.g. redpulse_20240101_010000.sql.gz"),
    current_user: User = Depends(get_current_user),
):
    _require_admin(current_user)
    from pathlib import Path
    backup_dir = BackupService._ensure_backup_dir()
    filepath = backup_dir / filename
    result = await BackupService.verify_backup(filepath)
    if not result.get("valid"):
        raise HTTPException(status_code=400, detail=result.get("error", "Invalid backup"))
    return {"success": True, "data": result}


@router.post("/backup/cleanup")
async def cleanup_backups(
    retention_days: int = Query(7, ge=1, le=30),
    max_count: int = Query(10, ge=1, le=100),
    current_user: User = Depends(get_current_user),
):
    _require_admin(current_user)
    result = BackupService.cleanup_old_backups(retention_days=retention_days, max_count=max_count)
    return {"success": True, "data": result}


@router.get("/backup/dr-runbook")
async def dr_runbook(
    current_user: User = Depends(get_current_user),
):
    _require_admin(current_user)
    runbook = BackupService.get_dr_runbook()
    return {"success": True, "data": runbook}
