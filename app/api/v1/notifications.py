"""ReconPilot - Notifications API Routes.

Notification abstraction and delivery.
"""

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from typing import List, Optional

from app.schemas.notifications import (
    NotificationBase, NotificationCreate, NotificationDB, NotificationCategory
)
from app.models import Project, Notification
from app.core.security import require_project_access
from app.config import get_settings
from app.core.logging import structured_log

router = APIRouter(prefix="/{project_id}/notifications", tags=["notifications"])


@router.post("", response_model=NotificationDB, status_code=status.HTTP_201_CREATED)
async def create_notification(
    notification_data: NotificationCreate,
    project_id: str,
    current_user: User = Depends(require_project_access),
    db: AsyncSession = ...,
):
    """Create a new notification."""
    # Verify project exists and user has access
    project = await db.get(Project, project_id)
    if not project:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Project not found",
        )
    
    # Valid categories
    valid_categories = [
        "NEW_ASSET", "IMPORTANT_CHANGE", "HIGH_FINDING",
        "CRITICAL_FINDING", "SCAN_FAILED", "SCAN_COMPLETED", "REGRESSION"
    ]
    
    if notification_data.category not in valid_categories:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid category. Must be one of: {', '.join(valid_categories)}",
        )
    
    # Create the notification
    notification = Notification(
        category=notification_data.category,
        title=notification_data.title,
        message=notification_data.message,
        project_id=project_id,
        user_id=current_user.id,
    )
    
    db.add(notification)
    await db.commit()
    await db.refresh(notification)
    
    # Log the action
    await structured_log(
        event="notification_created",
        project_id=project_id,
        notification_id=notification.id,
        user_id=current_user.id,
        level="INFO",
    )
    
    return notification


@router.get("", response_model=List[NotificationDB])
async def list_notifications(
    project_id: str,
    current_user: User = Depends(require_project_access),
    db: AsyncSession = ...,
    category: Optional[str] = None,
    is_read: Optional[bool] = None,
):
    """List notifications for a project."""
    # Verify project exists and user has access
    project = await db.get(Project, project_id)
    if not project:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Project not found",
        )
    
    query = select(Notification).filter(Notification.project_id == project_id)
    
    if category:
        query = query.filter(Notification.category == category)
    
    if is_read is not None:
        query = query.filter(Notification.is_read == is_read)
    
    # Order by created_at descending
    query = query.order_by(Notification.created_at.desc())
    
    result = await db.execute(query)
    notifications = result.scalars().all()
    
    return notifications


@router.post("/mark-read", response_model=dict)
async def mark_notification_read(
    notification_ids: List[str],
    project_id: str,
    current_user: User = Depends(require_project_access),
    db: AsyncSession = ...,
):
    """Mark notifications as read."""
    # Verify project exists and user has access
    project = await db.get(Project, project_id)
    if not project:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Project not found",
        )
    
    # Mark each notification as read
    for notification_id in notification_ids:
        result = await db.execute(
            select(Notification).filter(
                Notification.id == notification_id,
                Notification.project_id == project_id,
            )
        )
        notification = result.scalar_one_or_none()
        
        if notification:
            notification.is_read = True
    
    await db.commit()
    
    return {
        "project_id": project_id,
        "marked_read": len(notification_ids),
        "status": "success",
    }