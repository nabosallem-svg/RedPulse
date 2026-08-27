"""Optional Telegram notification plugin.

Controlled Pentesting: Telegram is only for alerts, never for control.
If TELEGRAM_BOT_TOKEN / TELEGRAM_CHAT_ID are not configured, the plugin is disabled (no-op).
"""

import logging
from typing import Optional

from app.core.config import settings

logger = logging.getLogger(__name__)


async def send_telegram_message(message: str) -> bool:
    """Send a Telegram message if configured, otherwise no-op.

    Returns True if sent, False if disabled or failed.
    """
    token = getattr(settings, "TELEGRAM_BOT_TOKEN", None)
    chat_id = getattr(settings, "TELEGRAM_CHAT_ID", None)

    if not token or not chat_id:
        logger.debug("Telegram plugin disabled: token or chat_id not configured")
        return False

    import httpx

    url = f"https://api.telegram.org/bot{token}/sendMessage"
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.post(url, json={"chat_id": chat_id, "text": message})
            resp.raise_for_status()
            logger.info(f"Telegram notification sent: {message[:80]}...")
            return True
    except Exception as e:
        logger.warning(f"Telegram plugin failed (non-critical): {e}")
        return False
