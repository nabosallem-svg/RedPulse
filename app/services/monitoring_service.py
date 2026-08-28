"""RedPulse - Continuous Monitoring Service.

Manages scheduled scanning, change detection for new assets/scope,
and triggers alerts when changes are detected.

Phase 7: Notifications & Monitoring
"""

import logging
from datetime import datetime, timezone, timedelta
from typing import Optional, List, Dict, Any

from sqlalchemy import select, func, and_
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.models import (
    MonitoringSchedule, Asset, Finding, FindingSeverity, FindingStatus,
    ReconJob, VulnScanStatus, Project, ScopeRule, WebhookConfig, Engagement,
)
from app.services.alert_service import AlertService

logger = logging.getLogger("redpulse.monitoring")

# Frequency mapping to timedelta
_FREQUENCY_MAP = {
    "every_6h": timedelta(hours=6),
    "daily": timedelta(days=1),
    "weekly": timedelta(days=7),
    "monthly": timedelta(days=30),
}


class MonitoringService:
    """Service for continuous monitoring and change detection.

    Usage:
        service = MonitoringService(db)
        due = await service.get_due_schedules()
        for schedule in due:
            await service.execute_monitoring_cycle(schedule)
    """

    def __init__(self, db: AsyncSession):
        self.db = db
        self.alert_service = AlertService(db)

    async def get_due_schedules(self) -> List[MonitoringSchedule]:
        """Fetch monitoring schedules that are due for execution.

        Returns schedules where:
        - enabled = True
        - next_scan_at is NULL or <= now

        Returns:
            List of MonitoringSchedule records
        """
        now = datetime.now(timezone.utc)
        result = await self.db.execute(
            select(MonitoringSchedule).where(
                MonitoringSchedule.enabled == True,
                (MonitoringSchedule.next_scan_at <= now) |
                (MonitoringSchedule.next_scan_at.is_(None)),
            )
        )
        return list(result.scalars().all())

    async def execute_monitoring_cycle(
        self, schedule: MonitoringSchedule
    ) -> Dict[str, Any]:
        """Execute a monitoring cycle for a schedule.

        1. Discover new assets via recon
        2. Detect scope changes
        3. Run vulnerability scan on all in-scope assets
        4. Compare findings with previous scan
        5. Send alerts for new Critical/High findings

        Args:
            schedule: The MonitoringSchedule record

        Returns:
            Cycle result dict
        """
        project_id = schedule.project_id
        result = {
            "schedule_id": schedule.id,
            "project_id": project_id,
            "status": "running",
            "new_assets": 0,
            "removed_assets": 0,
            "new_findings": 0,
            "critical_alerts": 0,
            "high_alerts": 0,
            "errors": [],
        }

        try:
            # Mark as running
            schedule.last_scan_status = "running"
            await self.db.flush()

            # Step 1: Detect new/removed assets
            asset_changes = await self._detect_asset_changes(project_id, schedule)
            result["new_assets"] = asset_changes["new"]
            result["removed_assets"] = asset_changes["removed"]

            # Step 2: Detect scope changes
            scope_changes = await self._detect_scope_changes(project_id)

            # Step 3: Count findings before scan (for comparison)
            findings_before = await self._count_findings(project_id)

            # Step 4: For now, record the cycle completion
            # In production, this would trigger a background pipeline run
            now = datetime.now(timezone.utc)
            schedule.last_scan_at = now
            schedule.last_scan_status = "completed"
            schedule.consecutive_failures = 0

            # Calculate next scan time
            freq = _FREQUENCY_MAP.get(schedule.frequency, timedelta(days=1))
            schedule.next_scan_at = now + freq

            # Step 5: Count new findings
            findings_after = await self._count_findings(project_id)
            result["new_findings"] = max(0, findings_after - findings_before)

            # Step 6: Send alerts for new critical/high findings
            new_critical = await self._get_new_severity_count(
                project_id, FindingSeverity.CRITICAL
            )
            new_high = await self._get_new_severity_count(
                project_id, FindingSeverity.HIGH
            )

            if new_critical > 0 or new_high > 0:
                alert_results = await self.alert_service.send_summary_alert(
                    project_id,
                    {
                        "findings_count": result["new_findings"],
                        "critical_count": new_critical,
                        "high_count": new_high,
                        "scan_status": "completed",
                        "scan_type": schedule.name,
                    },
                )
                result["critical_alerts"] = new_critical
                result["high_alerts"] = new_high

            result["status"] = "completed"
            logger.info(
                f"Monitoring cycle completed for project {project_id}: "
                f"new_assets={result['new_assets']}, new_findings={result['new_findings']}"
            )

        except Exception as e:
            schedule.last_scan_status = "failed"
            schedule.consecutive_failures += 1
            result["status"] = "failed"
            result["errors"].append(str(e))
            logger.error(f"Monitoring cycle failed for project {project_id}: {e}")

            # Alert on repeated failures
            if schedule.consecutive_failures >= 3:
                await self._send_failure_alert(schedule, str(e))

        await self.db.flush()
        return result

    async def detect_changes(
        self, project_id: str
    ) -> List[Dict[str, Any]]:
        """Detect all changes for a project since the last monitoring cycle.

        Checks for:
        - New assets discovered
        - Removed assets
        - New scope rules added
        - Findings that are regressions (were resolved, now active again)

        Returns:
            List of change dicts
        """
        changes = []

        # New assets (last_seen > last_scan or first_seen recently)
        schedule = await self._get_schedule_for_project(project_id)
        cutoff = schedule.last_scan_at if schedule and schedule.last_scan_at else (
            datetime.now(timezone.utc) - timedelta(days=7)
        )

        # New assets
        new_assets_result = await self.db.execute(
            select(Asset).where(
                Asset.engagement_id.in_(
                    select(Engagement.id).where(Engagement.project_id == project_id)
                ),
                Asset.first_seen > cutoff,
            )
        )
        new_assets = list(new_assets_result.scalars().all())
        for asset in new_assets:
            changes.append({
                "type": "new_asset",
                "asset_id": asset.id,
                "description": f"New {asset.asset_type.value if asset.asset_type else 'asset'} discovered: {asset.value}",
                "severity": "info",
                "detected_at": asset.first_seen.isoformat() if asset.first_seen else None,
            })

        # New findings (critical/high)
        new_findings_result = await self.db.execute(
            select(Finding).where(
                Finding.project_id == project_id,
                Finding.status == FindingStatus.NEW,
                Finding.severity.in_(["critical", "high"]),
                Finding.created_at > cutoff,
            )
        )
        new_findings = list(new_findings_result.scalars().all())
        for finding in new_findings:
            changes.append({
                "type": "new_finding",
                "finding_id": finding.id,
                "description": f"New {finding.severity.value} finding: {finding.title}",
                "severity": finding.severity.value,
                "detected_at": finding.created_at.isoformat() if finding.created_at else None,
            })

        # Reopened findings
        reopened_result = await self.db.execute(
            select(Finding).where(
                Finding.project_id == project_id,
                Finding.status == FindingStatus.REOPENED,
                Finding.updated_at > cutoff,
            )
        )
        reopened = list(reopened_result.scalars().all())
        for finding in reopened:
            changes.append({
                "type": "regression",
                "finding_id": finding.id,
                "description": f"Finding reopened (regression): {finding.title}",
                "severity": finding.severity.value,
                "detected_at": finding.updated_at.isoformat() if finding.updated_at else None,
            })

        return changes

    async def _detect_asset_changes(
        self, project_id: str, schedule: MonitoringSchedule
    ) -> Dict[str, int]:
        """Detect new and removed assets since last scan."""
        cutoff = schedule.last_scan_at or (
            datetime.now(timezone.utc) - timedelta(days=7)
        )

        # New assets
        new_result = await self.db.execute(
            select(func.count(Asset.id)).where(
                Asset.engagement_id.in_(
                    select(Engagement.id).where(Engagement.project_id == project_id)
                ),
                Asset.first_seen > cutoff,
            )
        )
        new_count = new_result.scalar() or 0

        # Removed assets (last_seen before cutoff, but were previously active)
        removed_result = await self.db.execute(
            select(func.count(Asset.id)).where(
                Asset.engagement_id.in_(
                    select(Engagement.id).where(Engagement.project_id == project_id)
                ),
                Asset.last_seen < cutoff,
            )
        )
        removed_count = removed_result.scalar() or 0

        return {"new": new_count, "removed": removed_count}

    async def _detect_scope_changes(self, project_id: str) -> List[Dict[str, Any]]:
        """Detect new scope rules added since last scan."""
        # This would compare current scope rules with previous state
        # For now, return empty (placeholder for full implementation)
        return []

    async def _count_findings(self, project_id: str) -> int:
        """Count total active findings for a project."""
        result = await self.db.execute(
            select(func.count(Finding.id)).where(
                Finding.project_id == project_id,
                Finding.status != FindingStatus.RESOLVED,
            )
        )
        return result.scalar() or 0

    async def _get_new_severity_count(
        self, project_id: str, severity: FindingSeverity
    ) -> int:
        """Count findings of a specific severity created in the last hour."""
        cutoff = datetime.now(timezone.utc) - timedelta(hours=1)
        result = await self.db.execute(
            select(func.count(Finding.id)).where(
                Finding.project_id == project_id,
                Finding.severity == severity,
                Finding.created_at > cutoff,
            )
        )
        return result.scalar() or 0

    async def _get_schedule_for_project(
        self, project_id: str
    ) -> Optional[MonitoringSchedule]:
        """Get the first monitoring schedule for a project."""
        result = await self.db.execute(
            select(MonitoringSchedule).where(
                MonitoringSchedule.project_id == project_id,
                MonitoringSchedule.enabled == True,
            ).limit(1)
        )
        return result.scalar_one_or_none()

    async def _send_failure_alert(
        self, schedule: MonitoringSchedule, error: str
    ) -> None:
        """Send an alert when monitoring fails repeatedly."""
        try:
            await self.alert_service.send_summary_alert(
                schedule.project_id,
                {
                    "findings_count": 0,
                    "critical_count": 0,
                    "high_count": 0,
                    "scan_status": "failed",
                    "scan_type": f"{schedule.name} (FAILED {schedule.consecutive_failures}x)",
                    "error": error[:500],
                },
            )
        except Exception as e:
            logger.warning(f"Failed to send failure alert: {e}")

    async def create_schedule(
        self,
        project_id: str,
        user_id: str,
        name: str = "Continuous Monitoring",
        frequency: str = "daily",
        profile: str = "standard",
        targets: Optional[List[str]] = None,
    ) -> MonitoringSchedule:
        """Create a new monitoring schedule.

        Args:
            project_id: The project UUID
            user_id: The user UUID who owns this schedule
            name: Human-readable name
            frequency: How often to scan (every_6h, daily, weekly, monthly)
            profile: Scan depth (quick, standard, deep)
            targets: Optional list of specific targets to scan

        Returns:
            The created MonitoringSchedule record
        """
        schedule = MonitoringSchedule(
            project_id=project_id,
            user_id=user_id,
            name=name,
            frequency=frequency,
            profile=profile,
            targets=targets,
            enabled=True,
            next_scan_at=datetime.now(timezone.utc),  # Due immediately
        )
        self.db.add(schedule)
        await self.db.flush()
        await self.db.refresh(schedule)
        logger.info(f"Created monitoring schedule {schedule.id} for project {project_id}")
        return schedule

    async def toggle_schedule(
        self, schedule_id: str, enabled: bool
    ) -> Optional[MonitoringSchedule]:
        """Enable or disable a monitoring schedule."""
        result = await self.db.execute(
            select(MonitoringSchedule).where(MonitoringSchedule.id == schedule_id)
        )
        schedule = result.scalar_one_or_none()
        if schedule:
            schedule.enabled = enabled
            if enabled:
                schedule.next_scan_at = datetime.now(timezone.utc)
                schedule.consecutive_failures = 0
            await self.db.flush()
        return schedule
