"""RedPulse - Pipeline Orchestrator.

Orchestrates the full recon-to-assessment pipeline:
  Engagement (Scoped) -> Recon -> Asset Normalization -> Nuclei Assessment -> Finding Ingestion

This is the core integration layer that connects Phase 2 (Recon) with Phase 3 (Assessment).

Phase 5: Supports authenticated scanning via auth_headers / auth_cookies passed
through the entire pipeline to VulnScanner and finding_ingester.
"""

import logging
from datetime import datetime, timezone
from typing import Optional, Dict

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.models import (
    ReconJob, ReconJobStatus, ReconTool, Asset, AssetType,
    VulnerabilityScan, VulnScanStatus, Finding,
    Engagement, Project, Authorization, ScopeRule,
)
from app.services.worker import ReconWorker
from app.services.finding_ingester import ingest_nuclei_findings_batch
from app.services.scope_validator import validate_target, ScopeViolation

logger = logging.getLogger("redpulse.pipeline")


class PipelineResult:
    """Result of a full pipeline execution."""

    def __init__(self):
        self.recon_jobs: list[ReconJob] = []
        self.assets_found: int = 0
        self.scan: Optional[VulnerabilityScan] = None
        self.findings: list[Finding] = []
        self.errors: list[str] = []
        self.status: str = "completed"

    def to_dict(self) -> dict:
        return {
            "engagement_id": self.recon_jobs[0].engagement_id if self.recon_jobs else None,
            "recon_jobs": [
                {
                    "id": j.id,
                    "tool": j.tool.value,
                    "status": j.status.value,
                    "target": j.target,
                    "result_summary": j.result_summary,
                }
                for j in self.recon_jobs
            ],
            "assets_found": self.assets_found,
            "scan_id": self.scan.id if self.scan else None,
            "findings_count": len(self.findings),
            "findings": [
                {
                    "id": f.id,
                    "title": f.title,
                    "severity": f.severity.value,
                    "status": f.status.value,
                    "asset_id": f.asset_id,
                    "fingerprint": f.fingerprint,
                    "triage_tags": f.triage_tags,
                    "category": f.category,
                }
                for f in self.findings
            ],
            "errors": self.errors,
            "status": self.status,
        }


class PipelineOrchestrator:
    """Orchestrates the full recon -> assessment -> ingestion pipeline.

    Usage:
        orchestrator = PipelineOrchestrator(db, user)
        result = await orchestrator.run(
            engagement_id="...",
            target="example.com",
            recon_tools=["subfinder", "httpx"],
            run_assessment=True,
            auth_headers={"Authorization": "Bearer ..."},
        )
    """

    def __init__(self, db: AsyncSession, user):
        self.db = db
        self.user = user
        self.worker = ReconWorker()

    async def run(
        self,
        engagement_id: str,
        target: str,
        recon_tools: list[str] = None,
        run_assessment: bool = True,
        template_path: Optional[str] = None,
        auth_headers: Optional[Dict[str, str]] = None,
        auth_cookies: Optional[str] = None,
    ) -> PipelineResult:
        """Execute the full pipeline.

        1. Validate scope for target
        2. Run recon jobs (subfinder -> httpx -> nmap)
        3. Collect discovered assets
        4. Run Nuclei assessment on in-scope assets (with optional auth)
        5. Ingest findings into DB with triage tags and PoC generation

        Args:
            engagement_id: The engagement UUID
            target: Root domain to scan
            recon_tools: List of tool names to run (default: ["subfinder"])
            run_assessment: Whether to run Nuclei after recon
            template_path: Optional custom Nuclei template path
            auth_headers: Optional HTTP headers for authenticated scanning
            auth_cookies: Optional cookie string for authenticated crawling

        Returns:
            PipelineResult with all jobs, assets, and findings
        """
        result = PipelineResult()

        # 1. Validate scope for target
        try:
            await validate_target(
                engagement_id=engagement_id,
                host_or_url=target,
                db=self.db,
                current_user=self.user,
            )
        except ScopeViolation as e:
            result.errors.append(f"Scope violation: {e.detail}")
            result.status = "failed"
            logger.error(f"Pipeline scope violation: {e.detail}")
            return result

        # 2. Run recon jobs
        if recon_tools is None:
            recon_tools = ["subfinder"]

        all_asset_values: list[str] = []

        for tool_name in recon_tools:
            try:
                tool_enum = ReconTool(tool_name)
            except ValueError:
                result.errors.append(f"Unknown tool: {tool_name}")
                continue

            # Create and execute recon job
            job = ReconJob(
                engagement_id=engagement_id,
                user_id=self.user.id,
                tool=tool_enum,
                target=target,
                status=ReconJobStatus.PENDING,
            )
            self.db.add(job)
            await self.db.commit()
            await self.db.refresh(job)

            try:
                job = await self.worker.run_job(job.id, self.db, self.user)
                result.recon_jobs.append(job)

                if job.status == ReconJobStatus.COMPLETED and job.result_summary:
                    assets_count = job.result_summary.get("assets_found", 0)
                    result.assets_found += assets_count

            except Exception as e:
                job.status = ReconJobStatus.FAILED
                job.error_message = str(e)[:500]
                job.completed_at = datetime.now(timezone.utc)
                await self.db.commit()
                result.errors.append(f"Recon job ({tool_name}) failed: {str(e)[:200]}")
                logger.error(f"Recon job {job.id} failed: {e}")
                # Continue to next tool — recon failure doesn't stop pipeline

        # 3. Collect all discovered assets for this engagement
        asset_result = await self.db.execute(
            select(Asset).where(Asset.engagement_id == engagement_id)
        )
        all_assets = asset_result.scalars().all()
        all_asset_values = [a.value for a in all_assets]
        result.assets_found = len(all_assets)

        if not all_assets:
            result.status = "completed"
            logger.info("Pipeline completed: no assets found, skipping assessment")
            return result

        # 4. Run Nuclei assessment
        if not run_assessment:
            result.status = "completed"
            return result

        # Filter to HTTP-capable assets (have http_status or port 80/443)
        scannable_assets = [
            a for a in all_assets
            if a.http_status is not None or a.port in (80, 443, 8080, 8443)
        ]

        # Also include all subdomains (Nuclei can probe them)
        if not scannable_assets:
            scannable_assets = [a for a in all_assets if a.asset_type in (AssetType.SUBDOMAIN, AssetType.DOMAIN)]

        if not scannable_assets:
            result.status = "completed"
            logger.info("Pipeline completed: no scannable assets found")
            return result

        # Create VulnerabilityScan record
        scan = VulnerabilityScan(
            engagement_id=engagement_id,
            user_id=self.user.id,
            status=VulnScanStatus.RUNNING,
            target=target,
            template_path=template_path,
            auth_headers=auth_headers,
            auth_cookies=auth_cookies,
            started_at=datetime.now(timezone.utc),
        )
        self.db.add(scan)
        await self.db.commit()
        await self.db.refresh(scan)
        result.scan = scan

        # Run Nuclei via VulnScanner
        try:
            from app.services.vuln_scanner import VulnScanner

            scanner = VulnScanner(
                db=self.db,
                current_user=self.user,
                engagement_id=engagement_id,
            )

            scan_targets = list({a.value for a in scannable_assets})
            raw_findings = await scanner.scan_targets(
                scan_targets, template_path, auth_headers, auth_cookies
            )

            # 5. Ingest findings with triage tags and PoC generation
            if raw_findings:
                # Get project_id from engagement
                eng_result = await self.db.execute(
                    select(Engagement).where(Engagement.id == engagement_id)
                )
                engagement = eng_result.scalar_one_or_none()
                project_id = engagement.project_id if engagement else None

                if project_id:
                    findings = await ingest_nuclei_findings_batch(
                        db=self.db,
                        engagement_id=engagement_id,
                        project_id=project_id,
                        user_id=self.user.id,
                        scan_id=scan.id,
                        raw_findings=raw_findings,
                        auth_headers=auth_headers,
                    )
                    result.findings = findings

            # Update scan status
            scan.status = VulnScanStatus.COMPLETED
            scan.completed_at = datetime.now(timezone.utc)
            scan.result_summary = {
                "targets_scanned": len(scan_targets),
                "findings_count": len(result.findings),
                "severity_breakdown": _severity_breakdown(result.findings),
                "triage_summary": _triage_summary(result.findings),
            }
            await self.db.commit()

        except Exception as e:
            scan.status = VulnScanStatus.FAILED
            scan.error_message = str(e)[:500]
            scan.completed_at = datetime.now(timezone.utc)
            await self.db.commit()
            result.errors.append(f"Assessment failed: {str(e)[:200]}")
            logger.error(f"Nuclei scan failed: {e}")

        result.status = "completed" if not result.errors else "completed_with_errors"
        return result


def _severity_breakdown(findings: list[Finding]) -> dict:
    """Count findings by severity."""
    breakdown = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for f in findings:
        sev = f.severity.value if hasattr(f.severity, "value") else str(f.severity)
        if sev in breakdown:
            breakdown[sev] += 1
    return breakdown


def _triage_summary(findings: list[Finding]) -> dict:
    """Summarize findings by triage tags for dashboard visibility."""
    tag_counts: dict[str, int] = {}
    high_sev_findings = 0
    for f in findings:
        sev = f.severity.value if hasattr(f.severity, "value") else str(f.severity)
        if sev in ("critical", "high"):
            high_sev_findings += 1
        if f.triage_tags:
            for tag in f.triage_tags:
                tag_counts[tag] = tag_counts.get(tag, 0) + 1
    return {
        "high_severity_count": high_sev_findings,
        "tag_breakdown": tag_counts,
    }
