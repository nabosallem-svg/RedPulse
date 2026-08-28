"""RedPulse - Recon Worker.

Executes recon jobs asynchronously. Validates scope before every tool execution.
Architecture:

API -> ReconWorker.run() -> Tool Adapter -> Normalizer -> Database

In production (Vercel), runs synchronously within the request.
In standalone mode, can be driven by a background task queue.
"""

import asyncio
import logging
from datetime import datetime, timezone
from typing import Optional

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.models import (
    ReconJob, ReconJobStatus, ReconResult, ReconTool, Asset,
)
from app.services.scope_validator import validate_target, ScopeViolation
from app.services.tools import SubfinderAdapter, HttpxAdapter, NmapAdapter, ToolResult
from app.services.normalizer import (
    normalize_subfinder_results,
    normalize_httpx_results,
    normalize_nmap_results,
)
from app.services.change_detector import detect_changes, format_changes_summary

logger = logging.getLogger("redpulse.worker")


class ReconWorker:
    """Executes recon jobs with scope enforcement."""

    def __init__(self):
        self.adapters = {
            ReconTool.SUBFINDER: SubfinderAdapter(),
            ReconTool.HTTPX: HttpxAdapter(),
            ReconTool.NMAP: NmapAdapter(),
        }

    async def run_job(
        self,
        job_id: str,
        db: AsyncSession,
        user,
    ) -> ReconJob:
        """Execute a recon job end-to-end.

        1. Load job from DB
        2. Validate scope for target
        3. Run tool adapter
        4. Normalize results
        5. Detect changes
        6. Store results
        7. Update job status

        Args:
            job_id: ReconJob ID
            db: AsyncSession (will be committed throughout)
            user: Current authenticated user

        Returns:
            Updated ReconJob
        """
        result = await db.execute(
            select(ReconJob).where(ReconJob.id == job_id)
        )
        job = result.scalar_one_or_none()
        if not job:
            raise ValueError(f"Job {job_id} not found")

        # Mark as running
        job.status = ReconJobStatus.RUNNING
        job.started_at = datetime.now(timezone.utc)
        await db.commit()

        try:
            # 1. SCOPE VALIDATION - mandatory before any tool execution
            await validate_target(
                engagement_id=job.engagement_id,
                host_or_url=job.target,
                db=db,
                current_user=user,
            )

            # 2. Run tool adapter
            adapter = self.adapters.get(job.tool)
            if not adapter:
                raise ValueError(f"No adapter for tool: {job.tool}")

            tool_result: ToolResult = await adapter.discover(job.target)

            # 3. Store raw result
            raw_result = ReconResult(
                recon_job_id=job.id,
                tool=job.tool,
                raw_output=tool_result.raw_output[:10000] if tool_result.raw_output else None,
                parsed_data={"data": tool_result.data[:100], "error": tool_result.error},
            )
            db.add(raw_result)
            await db.flush()

            if not tool_result.success:
                job.status = ReconJobStatus.FAILED
                job.error_message = tool_result.error
                job.completed_at = datetime.now(timezone.utc)
                await db.commit()
                return job

            # 4. Normalize results into Assets
            if job.tool == ReconTool.SUBFINDER:
                assets = await normalize_subfinder_results(
                    db, job.engagement_id, job.id, tool_result.data
                )
            elif job.tool == ReconTool.HTTPX:
                assets = await normalize_httpx_results(
                    db, job.engagement_id, job.id, tool_result.data
                )
            elif job.tool == ReconTool.NMAP:
                assets = await normalize_nmap_results(
                    db, job.engagement_id, job.id, tool_result.data
                )
            else:
                assets = []

            # 5. Detect changes
            new_hosts = []
            if tool_result.data:
                if isinstance(tool_result.data[0], str):
                    new_hosts = tool_result.data
                elif isinstance(tool_result.data[0], dict):
                    new_hosts = [d.get("host", "") for d in tool_result.data if d.get("host")]

            changes = await detect_changes(db, job.engagement_id, new_hosts)

            # 6. Update job
            job.status = ReconJobStatus.COMPLETED
            job.completed_at = datetime.now(timezone.utc)
            job.result_summary = {
                "assets_found": len(assets),
                "changes": format_changes_summary(changes),
                "tool_version": tool_result.version,
                "duration_seconds": round(tool_result.duration_seconds, 2),
            }

            await db.commit()
            logger.info(f"Job {job.id} completed: {len(assets)} assets, {len(changes)} changes")
            return job

        except ScopeViolation as e:
            job.status = ReconJobStatus.FAILED
            job.error_message = f"Scope violation: {e.detail}"
            job.completed_at = datetime.now(timezone.utc)
            await db.commit()
            logger.warning(f"Job {job.id} scope violation: {e.detail}")
            return job

        except Exception as e:
            job.status = ReconJobStatus.FAILED
            job.error_message = str(e)[:500]
            job.completed_at = datetime.now(timezone.utc)
            await db.commit()
            logger.error(f"Job {job.id} failed: {e}")
            return job

    async def check_availability(self) -> dict[str, bool]:
        """Check which tools are available on this system."""
        status = {}
        for tool, adapter in self.adapters.items():
            status[tool.value] = await adapter.is_available()
        return status


# Singleton
worker = ReconWorker()
