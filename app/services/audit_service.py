"""RedPulse - Audit Logging Service.

Comprehensive immutable audit trail for every sensitive operation.
Captures actor, resource, timing, IP, and context.
"""
from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Optional, List, Dict, Any

from fastapi import Request
from sqlalchemy import select, and_, func, desc
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.models import AuditLog

logger = logging.getLogger(__name__)

# Allowed actions (open set but define common ones for validation)
ALLOWED_ACTIONS = {
    "scan.create",
    "scan.start",
    "scan.complete",
    "scan.fail",
    "scan.cancel",
    "export.create",
    "export.json",
    "export.csv",
    "export.html",
    "export.pdf",
    "api_key.create",
    "api_key.revoke",
    "api_key.delete",
    "api_key.rotate",
    "api_key.use",
    "webhook.create",
    "webhook.update",
    "webhook.delete",
    "webhook.dispatch",
    "webhook.test",
    "workspace.create",
    "workspace.invite",
    "workspace.remove_member",
    "finding.export",
    "report.generate",
    "report.export",
    "auth.login",
    "auth.signup",
    "engagement.create",
    "authorization.verify",
    "scope.update",
}


def _extract_request_meta(request: Optional[Request]) -> tuple[Optional[str], Optional[str]]:
    """Extract IP and User-Agent from FastAPI Request."""
    if request is None:
        return None, None
    # X-Forwarded-For handling (Vercel, proxies)
    xff = request.headers.get("x-forwarded-for")
    if xff:
        ip = xff.split(",")[0].strip()
    else:
        ip = request.client.host if request.client else None
    ua = request.headers.get("user-agent")
    if ua and len(ua) > 500:
        ua = ua[:500]
    return ip, ua


class AuditService:
    """Service for creating and querying audit logs."""

    @staticmethod
    async def log(
        db: AsyncSession,
        action: str,
        resource_type: str,
        user_id: Optional[str] = None,
        api_key_id: Optional[str] = None,
        workspace_id: Optional[str] = None,
        project_id: Optional[str] = None,
        resource_id: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None,
        request: Optional[Request] = None,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None,
        status: str = "success",
    ) -> AuditLog:
        """Create an audit log entry.

        Args:
            db: Async session.
            action: Dot-notation action e.g. scan.create, export.json.
            resource_type: Resource type e.g. scan, export, api_key.
            user_id: Actor user id.
            api_key_id: If actor was API key.
            workspace_id: Scope workspace.
            project_id: Scope project.
            resource_id: Target resource id.
            details: Extra JSON context (target, format, counts, etc.).
            request: FastAPI Request for IP/UA extraction.
            ip_address: Override IP if not using request.
            user_agent: Override UA if not using request.
            status: success or failure.

        Returns:
            Created AuditLog.
        """
        # Extract from request if not explicitly provided
        if request is not None and ip_address is None and user_agent is None:
            ip_address, user_agent = _extract_request_meta(request)

        # Sanitize details: never log secrets
        if details:
            # Remove sensitive keys if present
            sanitized = {}
            for k, v in details.items():
                kl = k.lower()
                if any(secret in kl for secret in ("password", "secret", "token", "key", "api_key")):
                    sanitized[k] = "***REDACTED***"
                else:
                    # Truncate large values
                    if isinstance(v, str) and len(v) > 2000:
                        sanitized[k] = v[:2000] + "...truncated"
                    else:
                        sanitized[k] = v
            details = sanitized

        entry = AuditLog(
            user_id=user_id,
            api_key_id=api_key_id,
            workspace_id=workspace_id,
            project_id=project_id,
            action=action,
            resource_type=resource_type,
            resource_id=resource_id,
            details=details,
            ip_address=ip_address,
            user_agent=user_agent,
            status=status,
        )
        db.add(entry)
        await db.commit()
        await db.refresh(entry)

        logger.info(
            "audit_log action=%s resource=%s:%s user=%s workspace=%s status=%s ip=%s",
            action, resource_type, resource_id or "-", user_id or api_key_id or "system", workspace_id or "-", status, ip_address or "-"
        )
        return entry

    @staticmethod
    async def log_scan(
        db: AsyncSession,
        scan_id: str,
        project_id: str,
        workspace_id: Optional[str],
        user_id: Optional[str],
        target: str,
        tool: Optional[str] = None,
        profile: Optional[str] = None,
        request: Optional[Request] = None,
        api_key_id: Optional[str] = None,
        status: str = "success",
    ) -> AuditLog:
        """Convenience: log a scan operation."""
        return await AuditService.log(
            db=db,
            action="scan.create" if status == "success" else "scan.fail",
            resource_type="scan",
            resource_id=scan_id,
            user_id=user_id,
            api_key_id=api_key_id,
            workspace_id=workspace_id,
            project_id=project_id,
            details={"target": target, "tool": tool, "profile": profile},
            request=request,
            status=status,
        )

    @staticmethod
    async def log_export(
        db: AsyncSession,
        project_id: str,
        workspace_id: Optional[str],
        user_id: Optional[str],
        export_format: str,
        count: Optional[int] = None,
        request: Optional[Request] = None,
        api_key_id: Optional[str] = None,
        status: str = "success",
    ) -> AuditLog:
        """Convenience: log an export operation."""
        action = f"export.{export_format.lower()}" if export_format else "export.create"
        return await AuditService.log(
            db=db,
            action=action,
            resource_type="export",
            user_id=user_id,
            api_key_id=api_key_id,
            workspace_id=workspace_id,
            project_id=project_id,
            details={"format": export_format, "count": count},
            request=request,
            status=status,
        )

    @staticmethod
    async def list_logs(
        db: AsyncSession,
        workspace_id: Optional[str] = None,
        project_id: Optional[str] = None,
        user_id: Optional[str] = None,
        action: Optional[str] = None,
        resource_type: Optional[str] = None,
        status: Optional[str] = None,
        date_from: Optional[datetime] = None,
        date_to: Optional[datetime] = None,
        limit: int = 50,
        offset: int = 0,
    ) -> tuple[List[AuditLog], int]:
        """List audit logs with filtering and pagination.

        Returns:
            Tuple of (logs, total_count)
        """
        # Clamp limit
        limit = max(1, min(limit, 100))
        offset = max(0, offset)

        base_filters = []
        if workspace_id is not None:
            base_filters.append(AuditLog.workspace_id == workspace_id)
        if project_id is not None:
            base_filters.append(AuditLog.project_id == project_id)
        if user_id is not None:
            base_filters.append(AuditLog.user_id == user_id)
        if action is not None:
            base_filters.append(AuditLog.action == action)
        if resource_type is not None:
            base_filters.append(AuditLog.resource_type == resource_type)
        if status is not None:
            base_filters.append(AuditLog.status == status)
        if date_from is not None:
            base_filters.append(AuditLog.created_at >= date_from)
        if date_to is not None:
            base_filters.append(AuditLog.created_at <= date_to)

        # Total count
        count_q = select(func.count()).select_from(AuditLog)
        if base_filters:
            count_q = count_q.where(and_(*base_filters))
        total = await db.execute(count_q)
        total_count = total.scalar() or 0

        # Data query
        q = select(AuditLog)
        if base_filters:
            q = q.where(and_(*base_filters))
        q = q.order_by(desc(AuditLog.created_at)).limit(limit).offset(offset)
        result = await db.execute(q)
        logs = list(result.scalars().all())

        return logs, total_count

    @staticmethod
    async def get_logs_for_resource(
        db: AsyncSession,
        resource_type: str,
        resource_id: str,
        limit: int = 20,
    ) -> List[AuditLog]:
        """Get audit logs for a specific resource."""
        result = await db.execute(
            select(AuditLog)
            .where(
                AuditLog.resource_type == resource_type,
                AuditLog.resource_id == resource_id,
            )
            .order_by(desc(AuditLog.created_at))
            .limit(limit)
        )
        return list(result.scalars().all())

    @staticmethod
    async def get_recent_activity(
        db: AsyncSession,
        workspace_id: str,
        limit: int = 20,
    ) -> List[AuditLog]:
        """Get recent activity for a workspace dashboard."""
        return (await AuditService.list_logs(db, workspace_id=workspace_id, limit=limit))[0]
