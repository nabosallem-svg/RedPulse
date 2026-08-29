"""RedPulse - Custom Webhook Service.

Workspace-level webhooks with HMAC signing, event filtering, and retry.
Distinct from project-level WebhookConfig alerts.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import logging
import secrets
from datetime import datetime, timezone
from typing import Optional, List, Dict, Any

import httpx
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.models import CustomWebhook, Workspace

logger = logging.getLogger(__name__)

ALLOWED_EVENTS = {
    "scan.started",
    "scan.completed",
    "scan.failed",
    "finding.created",
    "finding.critical",
    "finding.high",
    "export.created",
    "export.completed",
    "project.created",
    "api_key.created",
    "webhook.test",
    "audit.test",
}

# Valid event types for filtering
ALL_EVENTS_SENTINEL = "*"


class CustomWebhookService:
    """Service for custom webhook management and delivery."""

    @staticmethod
    def generate_secret() -> str:
        """Generate a webhook HMAC secret."""
        return secrets.token_urlsafe(32)

    @staticmethod
    def sign_payload(payload_json: str, secret: str) -> str:
        """Compute HMAC-SHA256 signature for payload."""
        return hmac.new(
            secret.encode(),
            payload_json.encode(),
            hashlib.sha256
        ).hexdigest()

    @staticmethod
    def verify_signature(payload_json: str, secret: str, signature: str) -> bool:
        """Verify HMAC signature."""
        expected = CustomWebhookService.sign_payload(payload_json, secret)
        return hmac.compare_digest(expected, signature)

    @staticmethod
    async def create_webhook(
        db: AsyncSession,
        workspace_id: str,
        user_id: str,
        name: str,
        url: str,
        events: Optional[List[str]] = None,
        secret: Optional[str] = None,
        headers: Optional[Dict[str, str]] = None,
    ) -> CustomWebhook:
        """Create a custom webhook.

        Raises:
            ValueError: If validation fails.
        """
        if not name or not name.strip():
            raise ValueError("Webhook name is required")
        if not url or not url.startswith(("http://", "https://")):
            raise ValueError("Webhook URL must start with http:// or https://")

        events = events or ["scan.completed"]
        # Validate events
        invalid = [e for e in events if e not in ALLOWED_EVENTS and e != ALL_EVENTS_SENTINEL]
        if invalid:
            raise ValueError(f"Invalid events: {invalid}. Allowed: {sorted(ALLOWED_EVENTS)}")

        if not secret:
            secret = CustomWebhookService.generate_secret()

        webhook = CustomWebhook(
            workspace_id=workspace_id,
            user_id=user_id,
            name=name.strip(),
            url=url.strip(),
            secret=secret,
            events=events,
            headers=headers,
        )
        db.add(webhook)
        await db.commit()
        await db.refresh(webhook)

        logger.info("custom_webhook_created id=%s workspace=%s url=%s events=%s", webhook.id, workspace_id, url, events)
        return webhook

    @staticmethod
    async def list_webhooks(
        db: AsyncSession,
        workspace_id: str,
    ) -> List[CustomWebhook]:
        """List webhooks for a workspace."""
        result = await db.execute(
            select(CustomWebhook)
            .where(CustomWebhook.workspace_id == workspace_id)
            .order_by(CustomWebhook.created_at.desc())
        )
        return list(result.scalars().all())

    @staticmethod
    async def get_webhook(
        db: AsyncSession,
        webhook_id: str,
        workspace_id: str,
    ) -> Optional[CustomWebhook]:
        """Get a webhook by id and workspace."""
        result = await db.execute(
            select(CustomWebhook).where(
                CustomWebhook.id == webhook_id,
                CustomWebhook.workspace_id == workspace_id,
            )
        )
        return result.scalar_one_or_none()

    @staticmethod
    async def update_webhook(
        db: AsyncSession,
        webhook_id: str,
        workspace_id: str,
        updates: Dict[str, Any],
    ) -> Optional[CustomWebhook]:
        """Update a webhook."""
        webhook = await CustomWebhookService.get_webhook(db, webhook_id, workspace_id)
        if not webhook:
            return None

        allowed_fields = {"name", "url", "events", "headers", "is_active", "secret"}
        for key, value in updates.items():
            if key not in allowed_fields:
                continue
            if key == "url" and value and not str(value).startswith(("http://", "https://")):
                raise ValueError("Webhook URL must start with http:// or https://")
            if key == "events" and value is not None:
                invalid = [e for e in value if e not in ALLOWED_EVENTS and e != ALL_EVENTS_SENTINEL]
                if invalid:
                    raise ValueError(f"Invalid events: {invalid}")
            setattr(webhook, key, value)

        await db.commit()
        await db.refresh(webhook)
        logger.info("custom_webhook_updated id=%s workspace=%s", webhook.id, workspace_id)
        return webhook

    @staticmethod
    async def delete_webhook(
        db: AsyncSession,
        webhook_id: str,
        workspace_id: str,
    ) -> bool:
        """Delete a webhook."""
        webhook = await CustomWebhookService.get_webhook(db, webhook_id, workspace_id)
        if not webhook:
            return False
        await db.delete(webhook)
        await db.commit()
        logger.info("custom_webhook_deleted id=%s workspace=%s", webhook_id, workspace_id)
        return True

    @staticmethod
    async def dispatch(
        db: AsyncSession,
        workspace_id: str,
        event: str,
        payload: Dict[str, Any],
        timeout: float = 10.0,
        max_retries: int = 3,
    ) -> List[Dict[str, Any]]:
        """Dispatch event to all matching webhooks in workspace.

        Args:
            db: Session.
            workspace_id: Target workspace.
            event: Event name like scan.completed.
            payload: JSON-serializable payload.
            timeout: HTTP timeout per attempt.
            max_retries: Max retries on failure (exponential backoff).

        Returns:
            List of delivery results dicts: {webhook_id, success, status_code, attempts, error}
        """
        if event not in ALLOWED_EVENTS:
            logger.warning("dispatch unknown event %s workspace=%s", event, workspace_id)
            # Allow unknown events for extensibility? Strict: return empty
            return []

        webhooks = await CustomWebhookService.list_webhooks(db, workspace_id)
        # Filter active + subscribed
        targets = [
            w for w in webhooks
            if w.is_active and (event in (w.events or []) or ALL_EVENTS_SENTINEL in (w.events or []))
        ]

        if not targets:
            logger.debug("no webhooks subscribed to %s workspace=%s", event, workspace_id)
            return []

        results = []
        # Prepare envelope
        envelope = {
            "event": event,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "workspace_id": workspace_id,
            "payload": payload,
        }
        payload_json = json.dumps(envelope, separators=(",", ":"), default=str)

        async with httpx.AsyncClient(timeout=timeout, follow_redirects=False) as client:
            for webhook in targets:
                result = await CustomWebhookService._deliver_single(
                    client, webhook, envelope, payload_json, max_retries
                )
                # Update webhook status in DB
                try:
                    webhook.last_triggered_at = datetime.now(timezone.utc)
                    webhook.last_status = "success" if result["success"] else "failed"
                    if not result["success"]:
                        webhook.failure_count = (webhook.failure_count or 0) + 1
                    else:
                        webhook.failure_count = 0
                    await db.commit()
                except Exception:
                    await db.rollback()

                results.append(result)

        logger.info("webhook_dispatch event=%s workspace=%s targets=%d succeeded=%d", event, workspace_id, len(targets), sum(1 for r in results if r["success"]))
        return results

    @staticmethod
    async def _deliver_single(
        client: httpx.AsyncClient,
        webhook: CustomWebhook,
        envelope: Dict[str, Any],
        payload_json: str,
        max_retries: int,
    ) -> Dict[str, Any]:
        """Deliver to a single webhook with retry and HMAC signing."""
        headers = {
            "Content-Type": "application/json",
            "X-RedPulse-Event": envelope["event"],
            "X-RedPulse-Timestamp": envelope["timestamp"],
            "User-Agent": "RedPulse-Webhooks/1.0",
        }
        # HMAC signature
        if webhook.secret:
            sig = CustomWebhookService.sign_payload(payload_json, webhook.secret)
            headers["X-RedPulse-Signature"] = f"sha256={sig}"

        # Custom headers from webhook config
        if webhook.headers:
            for k, v in webhook.headers.items():
                # Prevent overriding signature headers
                if k.lower() not in ("x-redpulse-signature", "x-redpulse-event"):
                    headers[k] = v

        attempts = 0
        last_error = None
        last_status = None

        for attempt in range(1, max_retries + 2):  # initial + retries
            attempts = attempt
            try:
                resp = await client.post(webhook.url, content=payload_json, headers=headers)
                last_status = resp.status_code
                if 200 <= resp.status_code < 300:
                    return {
                        "webhook_id": webhook.id,
                        "success": True,
                        "status_code": resp.status_code,
                        "attempts": attempts,
                        "error": None,
                    }
                else:
                    last_error = f"HTTP {resp.status_code}: {resp.text[:500]}"
                    logger.warning("webhook_delivery_failed attempt=%d webhook=%s status=%d", attempt, webhook.id, resp.status_code)
            except httpx.RequestError as e:
                last_error = str(e)[:1000]
                logger.warning("webhook_delivery_error attempt=%d webhook=%s error=%s", attempt, webhook.id, last_error)
            except Exception as e:
                last_error = str(e)[:1000]
                logger.warning("webhook_delivery_exception attempt=%d webhook=%s error=%s", attempt, webhook.id, last_error)

            # Backoff before retry (skip on last attempt)
            if attempt < max_retries + 1:
                # Simple exponential: 0.5s, 1s, 2s
                import asyncio
                await asyncio.sleep(min(0.5 * (2 ** (attempt - 1)), 5.0))

        return {
            "webhook_id": webhook.id,
            "success": False,
            "status_code": last_status,
            "attempts": attempts,
            "error": last_error,
        }

    @staticmethod
    async def test_delivery(
        db: AsyncSession,
        webhook_id: str,
        workspace_id: str,
    ) -> Dict[str, Any]:
        """Send a test payload to a webhook."""
        webhook = await CustomWebhookService.get_webhook(db, webhook_id, workspace_id)
        if not webhook:
            raise ValueError("Webhook not found")

        payload = {
            "test": True,
            "message": "RedPulse webhook test delivery",
            "webhook_id": webhook.id,
        }

        async with httpx.AsyncClient(timeout=10.0) as client:
            payload_json = json.dumps({
                "event": "webhook.test",
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "workspace_id": workspace_id,
                "payload": payload,
            }, separators=(",", ":"), default=str)

            result = await CustomWebhookService._deliver_single(
                client, webhook,
                {"event": "webhook.test", "timestamp": datetime.now(timezone.utc).isoformat(), "workspace_id": workspace_id, "payload": payload},
                payload_json,
                max_retries=1,
            )

            # Update tracking
            webhook.last_triggered_at = datetime.now(timezone.utc)
            webhook.last_status = "success" if result["success"] else "failed"
            await db.commit()

            return result
