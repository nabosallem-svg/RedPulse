from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession
from typing import List, Optional

from app.api.deps import get_db, get_current_user
from app.services.recon_engine import ReconEngine


router = APIRouter(tags=["recon"])


@router.post("/start")
async def start_recon_job(
    engagement_id: str,
    target: str,
    db: AsyncSession = Depends(get_db),
    current_user = Depends(get_current_user),
) -> dict:
    """Start a reconnaissance job for an engagement.

    Validates the target through the scope engine, collects subnets,
    scans common ports, and sends a Telegram notification on completion.
    """
    engine = ReconEngine(db=db, current_user=current_user, engagement_id=engagement_id)
    result = await engine.run_recon_job(target=target)
    return result


@router.post("/collect-subnets", response_model=None)
async def collect_subnets_endpoint(
    engagement_id: str,
    target: str,
    db: AsyncSession = Depends(get_db),
    current_user = Depends(get_current_user),
) -> dict:
    """Collect subnets/subdomains for a target without port scanning.

    Useful for initial asset discovery before deeper scanning.
    """
    engine = ReconEngine(db=db, current_user=current_user, engagement_id=engagement_id)
    subnets = await engine.collect_subnets(target=target)
    return {"target": target, "subnets": subnets}


@router.post("/scan-ports", response_model=None)
async def scan_ports_endpoint(
    engagement_id: str,
    host: str,
    port_range: Optional[List[int]] = None,
    db: AsyncSession = Depends(get_db),
    current_user = Depends(get_current_user),
) -> dict:
    """Scan ports on a specific host.

    Scans the configured port range (or common ports) and returns
    open ports with banners.
    """
    engine = ReconEngine(db=db, current_user=current_user, engagement_id=engagement_id)
    open_ports = await engine.scan_ports(host=host, ports=port_range)
    return {"host": host, "open_ports": open_ports}


@router.post("/telegram-notify", response_model=None)
async def telegram_notify(
    message: str,
    db: AsyncSession = Depends(get_db),
    current_user = Depends(get_current_user),
) -> dict:
    """Send a notification via Telegram Bot API.

    Requires TELEGRAM_BOT_TOKEN and TELEGRAM_CHAT_ID in environment.
    """
    from app.core.config import settings

    token = settings.TELEGRAM_BOT_TOKEN
    chat_id = settings.TELEGRAM_CHAT_ID

    if not token or not chat_id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Telegram bot token or chat ID not configured",
        )

    engine = ReconEngine(db=db, current_user=current_user, engagement_id="")
    success = await engine.notify_telegram(message=message)
    return {"message": message, "sent": success}