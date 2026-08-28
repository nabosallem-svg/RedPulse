"""RedPulse - Webhooks API Routes.

CRUD endpoints for webhook configurations and monitoring triggers.

Phase 7: Notifications & Monitoring
"""

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from typing import List, Optional

from app.api.deps import get_current_user, get_db, require_project_access
from app.db.models import (
    User, WebhookConfig, MonitoringSchedule, Project, FindingSeverity,
)
from app.schemas import (
    WebhookConfigCreate, WebhookConfigUpdate, WebhookConfigDB,
    MonitoringScheduleCreate, MonitoringScheduleUpdate, MonitoringScheduleDB,
    MonitoringCycleResult,
)

router = APIRouter(tags=["webhooks"])


# --- Webhook CRUD ---


@router.post(
    "/projects/{project_id}/webhooks",
    response_model=WebhookConfigDB,
    status_code=status.HTTP_201_CREATED,
)
async def create_webhook(
    project_id: str,
    data: WebhookConfigCreate,
    current_user: User = Depends(require_project_access),
    db: AsyncSession = Depends(get_db),
):
    """Create a webhook configuration for a project."""
    webhook = WebhookConfig(
        project_id=project_id,
        user_id=current_user.id,
        name=data.name,
        webhook_type=data.webhook_type,
        url=data.url,
        min_severity=data.min_severity or "high",
        enabled=data.enabled if data.enabled is not None else True,
        headers=data.headers,
    )
    db.add(webhook)
    await db.commit()
    await db.refresh(webhook)
    return webhook


@router.get(
    "/projects/{project_id}/webhooks",
    response_model=List[WebhookConfigDB],
)
async def list_webhooks(
    project_id: str,
    current_user: User = Depends(require_project_access),
    db: AsyncSession = Depends(get_db),
):
    """List all webhook configurations for a project."""
    result = await db.execute(
        select(WebhookConfig).where(WebhookConfig.project_id == project_id)
    )
    return list(result.scalars().all())


@router.get(
    "/projects/{project_id}/webhooks/{webhook_id}",
    response_model=WebhookConfigDB,
)
async def get_webhook(
    project_id: str,
    webhook_id: str,
    current_user: User = Depends(require_project_access),
    db: AsyncSession = Depends(get_db),
):
    """Get a specific webhook configuration."""
    result = await db.execute(
        select(WebhookConfig).where(
            WebhookConfig.id == webhook_id,
            WebhookConfig.project_id == project_id,
        )
    )
    webhook = result.scalar_one_or_none()
    if not webhook:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Webhook not found",
        )
    return webhook


@router.patch(
    "/projects/{project_id}/webhooks/{webhook_id}",
    response_model=WebhookConfigDB,
)
async def update_webhook(
    project_id: str,
    webhook_id: str,
    data: WebhookConfigUpdate,
    current_user: User = Depends(require_project_access),
    db: AsyncSession = Depends(get_db),
):
    """Update a webhook configuration."""
    result = await db.execute(
        select(WebhookConfig).where(
            WebhookConfig.id == webhook_id,
            WebhookConfig.project_id == project_id,
        )
    )
    webhook = result.scalar_one_or_none()
    if not webhook:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Webhook not found",
        )

    update_data = data.model_dump(exclude_unset=True)
    for field, value in update_data.items():
        setattr(webhook, field, value)

    await db.commit()
    await db.refresh(webhook)
    return webhook


@router.delete(
    "/projects/{project_id}/webhooks/{webhook_id}",
    status_code=status.HTTP_204_NO_CONTENT,
)
async def delete_webhook(
    project_id: str,
    webhook_id: str,
    current_user: User = Depends(require_project_access),
    db: AsyncSession = Depends(get_db),
):
    """Delete a webhook configuration."""
    result = await db.execute(
        select(WebhookConfig).where(
            WebhookConfig.id == webhook_id,
            WebhookConfig.project_id == project_id,
        )
    )
    webhook = result.scalar_one_or_none()
    if not webhook:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Webhook not found",
        )
    await db.delete(webhook)
    await db.commit()


@router.post(
    "/projects/{project_id}/webhooks/{webhook_id}/test",
    response_model=dict,
)
async def test_webhook(
    project_id: str,
    webhook_id: str,
    current_user: User = Depends(require_project_access),
    db: AsyncSession = Depends(get_db),
):
    """Send a test alert to a webhook to verify connectivity."""
    result = await db.execute(
        select(WebhookConfig).where(
            WebhookConfig.id == webhook_id,
            WebhookConfig.project_id == project_id,
        )
    )
    webhook = result.scalar_one_or_none()
    if not webhook:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Webhook not found",
        )

    from app.services.alert_service import AlertService
    from app.db.models import Finding, FindingStatus

    alert_service = AlertService(db)

    # Create a temporary test finding for the alert
    test_finding = Finding(
        engagement_id="test",
        project_id=project_id,
        user_id=current_user.id,
        title="RedPulse Webhook Test Alert",
        severity=FindingSeverity.HIGH,
        confidence=100,
        category="test",
        description="This is a test alert from RedPulse to verify webhook connectivity.",
        endpoint="https://example.com/test",
        fingerprint="test_webhook_" + webhook_id[:16],
        status=FindingStatus.NEW,
    )

    try:
        results = await alert_service.send_finding_alert(
            test_finding, project_id, change_type="webhook_test"
        )
        success = any(r.get("success") for r in results)
        return {
            "webhook_id": webhook_id,
            "success": success,
            "results": results,
            "message": "Test alert sent successfully" if success else "Failed to send test alert",
        }
    except Exception as e:
        return {
            "webhook_id": webhook_id,
            "success": False,
            "results": [],
            "message": f"Error: {str(e)}",
        }


# --- Monitoring Schedules ---


@router.post(
    "/projects/{project_id}/monitoring/schedules",
    response_model=MonitoringScheduleDB,
    status_code=status.HTTP_201_CREATED,
)
async def create_monitoring_schedule(
    project_id: str,
    data: MonitoringScheduleCreate,
    current_user: User = Depends(require_project_access),
    db: AsyncSession = Depends(get_db),
):
    """Create a monitoring schedule for a project."""
    from app.services.monitoring_service import MonitoringService

    service = MonitoringService(db)
    schedule = await service.create_schedule(
        project_id=project_id,
        user_id=current_user.id,
        name=data.name or "Continuous Monitoring",
        frequency=data.frequency or "daily",
        profile=data.profile or "standard",
        targets=data.targets,
    )
    await db.commit()
    await db.refresh(schedule)
    return schedule


@router.get(
    "/projects/{project_id}/monitoring/schedules",
    response_model=List[MonitoringScheduleDB],
)
async def list_monitoring_schedules(
    project_id: str,
    current_user: User = Depends(require_project_access),
    db: AsyncSession = Depends(get_db),
):
    """List monitoring schedules for a project."""
    result = await db.execute(
        select(MonitoringSchedule).where(
            MonitoringSchedule.project_id == project_id,
        )
    )
    return list(result.scalars().all())


@router.patch(
    "/projects/{project_id}/monitoring/schedules/{schedule_id}",
    response_model=MonitoringScheduleDB,
)
async def update_monitoring_schedule(
    project_id: str,
    schedule_id: str,
    data: MonitoringScheduleUpdate,
    current_user: User = Depends(require_project_access),
    db: AsyncSession = Depends(get_db),
):
    """Update a monitoring schedule."""
    result = await db.execute(
        select(MonitoringSchedule).where(
            MonitoringSchedule.id == schedule_id,
            MonitoringSchedule.project_id == project_id,
        )
    )
    schedule = result.scalar_one_or_none()
    if not schedule:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Monitoring schedule not found",
        )

    update_data = data.model_dump(exclude_unset=True)
    for field, value in update_data.items():
        setattr(schedule, field, value)

    await db.commit()
    await db.refresh(schedule)
    return schedule


@router.post(
    "/projects/{project_id}/monitoring/schedules/{schedule_id}/toggle",
    response_model=MonitoringScheduleDB,
)
async def toggle_monitoring_schedule(
    project_id: str,
    schedule_id: str,
    enabled: bool = True,
    current_user: User = Depends(require_project_access),
    db: AsyncSession = Depends(get_db),
):
    """Enable or disable a monitoring schedule."""
    from app.services.monitoring_service import MonitoringService

    service = MonitoringService(db)
    schedule = await service.toggle_schedule(schedule_id, enabled)
    if not schedule:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Monitoring schedule not found",
        )
    await db.commit()
    await db.refresh(schedule)
    return schedule


@router.post(
    "/projects/{project_id}/monitoring/schedules/{schedule_id}/run",
    response_model=MonitoringCycleResult,
)
async def run_monitoring_cycle(
    project_id: str,
    schedule_id: str,
    current_user: User = Depends(require_project_access),
    db: AsyncSession = Depends(get_db),
):
    """Manually trigger a monitoring cycle for a schedule."""
    result = await db.execute(
        select(MonitoringSchedule).where(
            MonitoringSchedule.id == schedule_id,
            MonitoringSchedule.project_id == project_id,
        )
    )
    schedule = result.scalar_one_or_none()
    if not schedule:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Monitoring schedule not found",
        )

    from app.services.monitoring_service import MonitoringService

    service = MonitoringService(db)
    cycle_result = await service.execute_monitoring_cycle(schedule)
    await db.commit()
    return cycle_result


@router.get(
    "/projects/{project_id}/monitoring/changes",
    response_model=List[dict],
)
async def detect_changes(
    project_id: str,
    current_user: User = Depends(require_project_access),
    db: AsyncSession = Depends(get_db),
):
    """Detect changes for a project (new assets, findings, regressions)."""
    from app.services.monitoring_service import MonitoringService

    service = MonitoringService(db)
    changes = await service.detect_changes(project_id)
    return changes
