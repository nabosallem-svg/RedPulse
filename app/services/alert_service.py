"""RedPulse - Alert Service.

Delivers alerts to Telegram, Discord, and custom webhook endpoints.
Filters alerts to only Critical/High severity to prevent notification fatigue.

Phase 7: Notifications & Monitoring
"""

import logging
from datetime import datetime, timezone
from typing import Optional, List, Dict, Any

import httpx
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.models import (
    WebhookConfig, Finding, FindingSeverity, Project, FindingStatus,
)

logger = logging.getLogger("redpulse.alerts")

# Severity ordering for comparison
_SEVERITY_ORDER = {
    "critical": 0,
    "high": 1,
    "medium": 2,
    "low": 3,
    "info": 4,
}


def _severity_meets_threshold(severity: str, min_severity: str) -> bool:
    """Check if a severity level meets the minimum threshold."""
    sev_val = _SEVERITY_ORDER.get(severity.lower(), 5)
    min_val = _SEVERITY_ORDER.get(min_severity.lower(), 5)
    return sev_val <= min_val


def _format_telegram_message(
    finding: Finding,
    project_name: str,
    change_type: str = "new_finding",
) -> str:
    """Format a Telegram message for a finding alert."""
    severity_emoji = {
        "critical": "🔴",
        "high": "🟠",
        "medium": "🟡",
        "low": "🟢",
        "info": "⚪",
    }

    emoji = severity_emoji.get(finding.severity.value, "⚪")
    status_label = change_type.replace("_", " ").title()

    lines = [
        f"{emoji} *RedPulse Alert — {status_label}*",
        "",
        f"*Project:* {project_name}",
        f"*Severity:* `{finding.severity.value.upper()}`",
        f"*Title:* {finding.title}",
    ]

    if finding.endpoint:
        lines.append(f"*Endpoint:* `{finding.endpoint}`")

    if finding.category:
        lines.append(f"*Category:* {finding.category}")

    if finding.triage_tags:
        lines.append(f"*Tags:* {', '.join(finding.triage_tags)}")

    if finding.poc_curl:
        # Truncate curl for Telegram message length limits
        curl_short = finding.poc_curl[:500]
        lines.append(f"\n*PoC:*\n`{curl_short}`")

    if finding.description:
        desc_short = finding.description[:300]
        lines.append(f"\n*Description:* {desc_short}")

    lines.append(f"\n_First seen: {finding.first_seen.isoformat() if finding.first_seen else 'N/A'}_")

    return "\n".join(lines)


def _format_discord_embed(
    finding: Finding,
    project_name: str,
    change_type: str = "new_finding",
) -> Dict[str, Any]:
    """Format a Discord embed for a finding alert."""
    severity_colors = {
        "critical": 0x7F1D1D,  # Dark red
        "high": 0xDC2626,      # Red
        "medium": 0xD97706,    # Orange
        "low": 0x16A34A,       # Green
        "info": 0x6B7280,      # Gray
    }

    color = severity_colors.get(finding.severity.value, 0x6B7280)
    status_label = change_type.replace("_", " ").title()

    embed = {
        "title": f"🔴 {finding.title}",
        "description": finding.description[:2000] if finding.description else "No description available.",
        "color": color,
        "fields": [
            {"name": "Project", "value": project_name, "inline": True},
            {"name": "Severity", "value": finding.severity.value.upper(), "inline": True},
            {"name": "Status", "value": status_label, "inline": True},
        ],
        "footer": {"text": "RedPulse Controlled Pentesting"},
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }

    if finding.endpoint:
        embed["fields"].append({"name": "Endpoint", "value": f"`{finding.endpoint}`", "inline": False})

    if finding.category:
        embed["fields"].append({"name": "Category", "value": finding.category, "inline": True})

    if finding.triage_tags:
        embed["fields"].append({
            "name": "Triage Tags",
            "value": ", ".join(finding.triage_tags),
            "inline": False,
        })

    if finding.poc_curl:
        embed["fields"].append({
            "name": "PoC (curl)",
            "value": f"```\n{finding.poc_curl[:1000]}\n```",
            "inline": False,
        })

    return embed


class AlertService:
    """Service for delivering alerts to external webhook endpoints.

    Filters alerts by severity threshold and routes to the appropriate
    format (Telegram, Discord, custom).

    Usage:
        service = AlertService(db)
        results = await service.send_finding_alert(finding, project_id)
    """

    def __init__(self, db: AsyncSession):
        self.db = db

    async def send_finding_alert(
        self,
        finding: Finding,
        project_id: str,
        change_type: str = "new_finding",
    ) -> List[Dict[str, Any]]:
        """Send alerts for a finding to all configured webhooks for the project.

        Only sends if the finding severity meets the webhook's minimum threshold.

        Args:
            finding: The Finding record
            project_id: The project UUID
            change_type: Type of change (new_finding, regression, reopened)

        Returns:
            List of delivery results [{webhook_id, success, error}]
        """
        # Only alert on Critical/High by default
        if not _severity_meets_threshold(finding.severity.value, "high"):
            logger.debug(
                f"Skipping alert for {finding.severity.value} finding: {finding.title}"
            )
            return []

        # Fetch project name
        project_result = await self.db.execute(
            select(Project).where(Project.id == project_id)
        )
        project = project_result.scalar_one_or_none()
        project_name = project.name if project else "Unknown Project"

        # Fetch all enabled webhooks for this project
        result = await self.db.execute(
            select(WebhookConfig).where(
                WebhookConfig.project_id == project_id,
                WebhookConfig.enabled == True,
            )
        )
        webhooks = list(result.scalars().all())

        if not webhooks:
            logger.debug(f"No enabled webhooks for project {project_id}")
            return []

        results = []
        for webhook in webhooks:
            # Check severity threshold
            if not _severity_meets_threshold(
                finding.severity.value, webhook.min_severity
            ):
                continue

            try:
                if webhook.webhook_type == "telegram":
                    await self._send_telegram(webhook, finding, project_name, change_type)
                elif webhook.webhook_type == "discord":
                    await self._send_discord(webhook, finding, project_name, change_type)
                else:
                    await self._send_custom(webhook, finding, project_name, change_type)

                results.append({"webhook_id": webhook.id, "success": True, "error": None})
                logger.info(
                    f"Alert sent to {webhook.webhook_type} webhook {webhook.id} "
                    f"for finding {finding.id}"
                )
            except Exception as e:
                results.append({"webhook_id": webhook.id, "success": False, "error": str(e)})
                logger.warning(
                    f"Failed to send alert to webhook {webhook.id}: {e}"
                )

        return results

    async def send_summary_alert(
        self,
        project_id: str,
        summary: Dict[str, Any],
    ) -> List[Dict[str, Any]]:
        """Send a summary alert (e.g. scan completed, monitoring cycle done).

        Args:
            project_id: The project UUID
            summary: Summary dict with keys: findings_count, critical_count,
                     high_count, scan_status, scan_type

        Returns:
            List of delivery results
        """
        # Fetch project name
        project_result = await self.db.execute(
            select(Project).where(Project.id == project_id)
        )
        project = project_result.scalar_one_or_none()
        project_name = project.name if project else "Unknown Project"

        # Fetch all enabled webhooks
        result = await self.db.execute(
            select(WebhookConfig).where(
                WebhookConfig.project_id == project_id,
                WebhookConfig.enabled == True,
            )
        )
        webhooks = list(result.scalars().all())

        results = []
        for webhook in webhooks:
            # Summary alerts only for Critical/High thresholds
            if not _severity_meets_threshold("high", webhook.min_severity):
                continue

            try:
                if webhook.webhook_type == "telegram":
                    msg = self._format_summary_telegram(project_name, summary)
                    await self._send_telegram_raw(webhook.url, msg)
                elif webhook.webhook_type == "discord":
                    embed = self._format_summary_discord(project_name, summary)
                    await self._send_discord_raw(webhook.url, embed)
                else:
                    payload = {"project_name": project_name, **summary}
                    await self._send_custom_raw(webhook.url, payload, webhook.headers)

                results.append({"webhook_id": webhook.id, "success": True, "error": None})
            except Exception as e:
                results.append({"webhook_id": webhook.id, "success": False, "error": str(e)})

        return results

    async def _send_telegram(
        self,
        webhook: WebhookConfig,
        finding: Finding,
        project_name: str,
        change_type: str,
    ) -> None:
        """Send a Telegram alert for a finding."""
        message = _format_telegram_message(finding, project_name, change_type)
        await self._send_telegram_raw(webhook.url, message)

    async def _send_telegram_raw(self, url: str, message: str) -> None:
        """Send a raw Telegram message via bot API."""
        # Telegram Bot API URL: https://api.telegram.org/bot<TOKEN>/sendMessage
        # The webhook.url should be the full bot API URL
        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.post(
                url,
                json={"text": message, "parse_mode": "Markdown"},
            )
            resp.raise_for_status()

    async def _send_discord(
        self,
        webhook: WebhookConfig,
        finding: Finding,
        project_name: str,
        change_type: str,
    ) -> None:
        """Send a Discord alert for a finding."""
        embed = _format_discord_embed(finding, project_name, change_type)
        await self._send_discord_raw(webhook.url, embed)

    async def _send_discord_raw(self, url: str, embed: Dict[str, Any]) -> None:
        """Send a raw Discord embed via webhook URL."""
        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.post(
                url,
                json={"embeds": [embed]},
            )
            resp.raise_for_status()

    async def _send_custom(
        self,
        webhook: WebhookConfig,
        finding: Finding,
        project_name: str,
        change_type: str,
    ) -> None:
        """Send a custom webhook alert for a finding."""
        payload = {
            "event": "finding_alert",
            "change_type": change_type,
            "project_name": project_name,
            "finding": {
                "id": finding.id,
                "title": finding.title,
                "severity": finding.severity.value if finding.severity else "unknown",
                "category": finding.category,
                "endpoint": finding.endpoint,
                "description": finding.description,
                "triage_tags": finding.triage_tags or [],
                "poc_curl": finding.poc_curl,
                "first_seen": finding.first_seen.isoformat() if finding.first_seen else None,
            },
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
        await self._send_custom_raw(webhook.url, payload, webhook.headers)

    async def _send_custom_raw(
        self, url: str, payload: dict, headers: Optional[dict] = None
    ) -> None:
        """Send a raw JSON payload to a custom webhook URL."""
        send_headers = {"Content-Type": "application/json"}
        if headers:
            send_headers.update(headers)

        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.post(url, json=payload, headers=send_headers)
            resp.raise_for_status()

    def _format_summary_telegram(
        self, project_name: str, summary: Dict[str, Any]
    ) -> str:
        """Format a summary alert for Telegram."""
        critical = summary.get("critical_count", 0)
        high = summary.get("high_count", 0)
        total = summary.get("findings_count", 0)
        status = summary.get("scan_status", "completed")
        scan_type = summary.get("scan_type", "scan")

        emoji = "🔴" if critical > 0 else ("🟠" if high > 0 else "🟢")

        lines = [
            f"{emoji} *RedPulse — Scan {status.title()}*",
            "",
            f"*Project:* {project_name}",
            f"*Scan Type:* {scan_type}",
            f"*Findings:* {total} total",
        ]

        if critical > 0:
            lines.append(f"  🔴 Critical: {critical}")
        if high > 0:
            lines.append(f"  🟠 High: {high}")

        lines.append(f"\n_Scan completed at {datetime.now(timezone.utc).isoformat()}_")

        return "\n".join(lines)

    def _format_summary_discord(
        self, project_name: str, summary: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Format a summary alert for Discord embed."""
        critical = summary.get("critical_count", 0)
        high = summary.get("high_count", 0)
        total = summary.get("findings_count", 0)
        status = summary.get("scan_status", "completed")
        scan_type = summary.get("scan_type", "scan")

        color = 0x7F1D1D if critical > 0 else (0xDC2626 if high > 0 else 0x16A34A)

        fields = [
            {"name": "Project", "value": project_name, "inline": True},
            {"name": "Scan Type", "value": scan_type, "inline": True},
            {"name": "Status", "value": status, "inline": True},
            {"name": "Total Findings", "value": str(total), "inline": True},
        ]

        if critical > 0:
            fields.append({"name": "Critical", "value": str(critical), "inline": True})
        if high > 0:
            fields.append({"name": "High", "value": str(high), "inline": True})

        return {
            "title": f"📊 RedPulse Scan {status.title()}",
            "color": color,
            "fields": fields,
            "footer": {"text": "RedPulse Controlled Pentesting"},
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
