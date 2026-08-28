"""RedPulse - Reporting Service.

Aggregates findings per project, filters by severity, and generates
exportable reports in JSON (HackerOne/Bugcrowd), CSV, and HTML/PDF formats.

Phase 6: Reporting & Evidence
"""

import csv
import io
import json
import logging
from datetime import datetime, timezone
from typing import Optional, List, Dict, Any

from sqlalchemy import select, func
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.models import (
    Finding, FindingSeverity, FindingStatus, Project, Engagement, Asset,
)

logger = logging.getLogger("redpulse.reporting")

# Severity ordering for sorting
_SEVERITY_ORDER = {
    FindingSeverity.CRITICAL: 0,
    FindingSeverity.HIGH: 1,
    FindingSeverity.MEDIUM: 2,
    FindingSeverity.LOW: 3,
    FindingSeverity.INFO: 4,
}


class ReportService:
    """Service for generating security assessment reports.

    Usage:
        service = ReportService(db)
        report = await service.generate_report(project_id, format="json")
    """

    def __init__(self, db: AsyncSession):
        self.db = db

    async def get_findings_for_project(
        self,
        project_id: str,
        engagement_id: Optional[str] = None,
        min_severity: Optional[FindingSeverity] = None,
        include_resolved: bool = False,
    ) -> List[Finding]:
        """Fetch findings for a project, optionally filtered by engagement and severity.

        Args:
            project_id: The project UUID
            engagement_id: Optional engagement filter
            min_severity: Minimum severity to include (e.g. FindingSeverity.HIGH)
            include_resolved: Whether to include resolved findings

        Returns:
            List of Finding records sorted by severity (critical first)
        """
        query = select(Finding).where(Finding.project_id == project_id)

        if engagement_id:
            query = query.where(Finding.engagement_id == engagement_id)

        if min_severity:
            severity_order = {
                FindingSeverity.CRITICAL: ["critical"],
                FindingSeverity.HIGH: ["critical", "high"],
                FindingSeverity.MEDIUM: ["critical", "high", "medium"],
                FindingSeverity.LOW: ["critical", "high", "medium", "low"],
                FindingSeverity.INFO: ["critical", "high", "medium", "low", "info"],
            }
            allowed = severity_order.get(min_severity, [])
            query = query.where(Finding.severity.in_(allowed))

        if not include_resolved:
            query = query.where(Finding.status != FindingStatus.RESOLVED)

        result = await self.db.execute(query)
        findings = list(result.scalars().all())

        # Sort by severity (critical first), then by created_at
        findings.sort(key=lambda f: (
            _SEVERITY_ORDER.get(f.severity, 5),
            f.created_at or datetime.min.replace(tzinfo=timezone.utc),
        ))

        return findings

    async def get_project_summary(self, project_id: str) -> Dict[str, Any]:
        """Get project-level summary with severity breakdown."""
        query = select(
            Finding.severity,
            func.count(Finding.id),
        ).where(
            Finding.project_id == project_id,
            Finding.status != FindingStatus.RESOLVED,
        ).group_by(Finding.severity)

        result = await self.db.execute(query)
        severity_counts = {row[0].value: row[1] for row in result.all()}

        total = sum(severity_counts.values())
        high_severe = severity_counts.get("critical", 0) + severity_counts.get("high", 0)

        return {
            "project_id": project_id,
            "total_findings": total,
            "severity_breakdown": severity_counts,
            "high_severity_count": high_severe,
            "has_critical_findings": severity_counts.get("critical", 0) > 0,
        }

    async def generate_report(
        self,
        project_id: str,
        engagement_id: Optional[str] = None,
        min_severity: FindingSeverity = FindingSeverity.HIGH,
        include_resolved: bool = False,
    ) -> Dict[str, Any]:
        """Generate a structured report dict from project findings.

        Returns a report dict suitable for any export format.
        """
        project_result = await self.db.execute(
            select(Project).where(Project.id == project_id)
        )
        project = project_result.scalar_one_or_none()

        findings = await self.get_findings_for_project(
            project_id, engagement_id, min_severity, include_resolved
        )

        project_name = project.name if project else "Unknown Project"

        # Build finding dicts for export
        finding_dicts = []
        for f in findings:
            finding_dicts.append(_finding_to_dict(f))

        # Build executive summary
        summary = _build_executive_summary(finding_dicts, project_name)

        return {
            "report_title": f"RedPulse Security Assessment — {project_name}",
            "project_id": project_id,
            "project_name": project_name,
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "engine": "RedPulse Controlled Pentesting Engine",
            "classification": "Confidential — Authorized Testing Only",
            "executive_summary": summary,
            "findings": finding_dicts,
            "findings_count": len(finding_dicts),
            "disclaimer": "All tests conducted within authorized scope via scope_validator. "
                          "Passive PoC only — no destructive exploitation.",
        }

    async def export_json(
        self,
        project_id: str,
        engagement_id: Optional[str] = None,
        min_severity: FindingSeverity = FindingSeverity.HIGH,
        platform: str = "hackerone",
    ) -> str:
        """Export findings as JSON compatible with HackerOne/Bugcrowd import.

        HackerOne expects: title, vulnerability_information, impact, severity_id, etc.
        Bugcrowd expects: title, vulnerability_details, priority, etc.

        Returns:
            JSON string
        """
        report = await self.generate_report(project_id, engagement_id, min_severity)

        if platform == "hackerone":
            return _format_hackerone_json(report)
        elif platform == "bugcrowd":
            return _format_bugcrowd_json(report)
        else:
            return json.dumps(report, indent=2, default=str)

    async def export_csv(
        self,
        project_id: str,
        engagement_id: Optional[str] = None,
        min_severity: FindingSeverity = FindingSeverity.HIGH,
    ) -> str:
        """Export findings as CSV with PoC, curl commands, and reproduction steps.

        Returns:
            CSV string
        """
        findings = await self.get_findings_for_project(project_id, engagement_id, min_severity)

        output = io.StringIO()
        writer = csv.writer(output)

        # Header
        writer.writerow([
            "ID", "Title", "Severity", "Category", "Status",
            "Endpoint", "Template ID", "Confidence",
            "Description", "Impact", "Remediation",
            "PoC curl", "Reproduction Steps",
            "Triage Tags", "Sensitive Params",
            "First Seen", "Last Seen",
        ])

        for f in findings:
            writer.writerow([
                f.id,
                f.title or "",
                f.severity.value if f.severity else "",
                f.category or "",
                f.status.value if f.status else "",
                f.endpoint or f.matched_at or "",
                f.template_id or "",
                f.confidence or 0,
                (f.description or "")[:500],
                (f.impact or "")[:500],
                (f.remediation or "")[:500],
                f.poc_curl or "",
                (f.poc_steps or "")[:1000],
                json.dumps(f.triage_tags) if f.triage_tags else "",
                json.dumps(f.sensitive_params) if f.sensitive_params else "",
                f.first_seen.isoformat() if f.first_seen else "",
                f.last_seen.isoformat() if f.last_seen else "",
            ])

        return output.getvalue()

    async def export_html(
        self,
        project_id: str,
        engagement_id: Optional[str] = None,
        min_severity: FindingSeverity = FindingSeverity.HIGH,
    ) -> str:
        """Export findings as a printable HTML report.

        Returns:
            HTML string
        """
        report = await self.generate_report(project_id, engagement_id, min_severity)

        # Map poc_curl/poc_steps into the poc format expected by reporting_engine
        enriched_findings = []
        for f in report["findings"]:
            ff = dict(f)
            poc_data = {}
            if f.get("poc_curl"):
                poc_data["request"] = f["poc_curl"]
            if f.get("evidence"):
                poc_data["response"] = f["evidence"][:2000]
            if poc_data:
                poc_data["is_passive"] = True
                ff["poc"] = poc_data
            # Also pass poc_steps as reproduction_steps for the engine
            if f.get("poc_steps"):
                ff["reproduction_steps"] = f["poc_steps"]
            enriched_findings.append(ff)

        try:
            from app.services.reporting_engine import build_report, render_report_html

            engine_report = build_report(
                project_name=report["project_name"],
                engagement_name="All Engagements" if not engagement_id else engagement_id,
                findings=enriched_findings,
                format="html",
                include_poc=True,
            )
            return render_report_html(engine_report)
        except Exception as e:
            logger.warning(f"Jinja2 HTML render failed, using fallback: {e}")
            return _render_fallback_html(report)


def _finding_to_dict(f: Finding) -> Dict[str, Any]:
    """Convert a Finding model to a report-friendly dict."""
    return {
        "id": f.id,
        "title": f.title or "Untitled Finding",
        "severity": f.severity.value if f.severity else "info",
        "confidence": f.confidence or 0,
        "category": f.category or "",
        "status": f.status.value if f.status else "new",
        "template_id": f.template_id or "",
        "host": f.endpoint or f.matched_at or "",
        "endpoint": f.endpoint or "",
        "matched_at": f.matched_at or "",
        "description": f.description or "",
        "evidence": f.evidence or "",
        "impact": f.impact or "",
        "remediation": f.remediation or "Follow OWASP remediation guidance for this category.",
        "poc_curl": f.poc_curl or "",
        "poc_steps": f.poc_steps or "",
        "triage_tags": f.triage_tags or [],
        "sensitive_params": f.sensitive_params or [],
        "fingerprint": f.fingerprint or "",
        "first_seen": f.first_seen.isoformat() if f.first_seen else "",
        "last_seen": f.last_seen.isoformat() if f.last_seen else "",
        "asset_id": f.asset_id or "",
        "scan_id": f.scan_id or "",
    }


def _build_executive_summary(findings: List[Dict[str, Any]], project_name: str) -> Dict[str, Any]:
    """Build executive summary from finding dicts."""
    if not findings:
        return {
            "total": 0,
            "by_severity": {},
            "high_severity_count": 0,
            "summary": f"No findings for {project_name}. Target appears secure within tested scope.",
        }

    by_severity: Dict[str, int] = {}
    for f in findings:
        sev = f.get("severity", "info").upper()
        by_severity[sev] = by_severity.get(sev, 0) + 1

    total = len(findings)
    high_sev = by_severity.get("CRITICAL", 0) + by_severity.get("HIGH", 0)

    summary = f"Assessment of {project_name} identified {total} findings. "
    summary += f"{high_sev} classified as high/critical severity. "
    severity_parts = [f"{k}: {v}" for k, v in sorted(by_severity.items())]
    summary += "Severity distribution — " + ", ".join(severity_parts) + "."

    return {
        "total": total,
        "by_severity": by_severity,
        "high_severity_count": high_sev,
        "summary": summary,
    }


def _format_hackerone_json(report: Dict[str, Any]) -> str:
    """Format report as HackerOne-compatible JSON.

    HackerOne report submission format:
    - title: Vulnerability title
    - vulnerability_information: Detailed description + PoC
    - impact: Impact statement
    - severity_rating: CVSS-like severity
    """
    h1_findings = []
    for f in report["findings"]:
        vuln_info_parts = [
            f"## Vulnerability\n{f.get('description', 'N/A')}",
            f"\n## Endpoint\n`{f.get('endpoint', 'N/A')}`",
            f"\n## Category\n{f.get('category', 'N/A')}",
        ]
        if f.get("poc_curl"):
            vuln_info_parts.append(f"\n## Proof of Concept (curl)\n```bash\n{f['poc_curl']}\n```")
        if f.get("poc_steps"):
            vuln_info_parts.append(f"\n## Reproduction Steps\n{f['poc_steps']}")
        if f.get("evidence"):
            vuln_info_parts.append(f"\n## Evidence\n```\n{f['evidence'][:2000]}\n```")
        if f.get("triage_tags"):
            vuln_info_parts.append(f"\n## Triage Tags\n{', '.join(f['triage_tags'])}")

        h1_findings.append({
            "title": f.get("title", "Security Finding"),
            "vulnerability_information": "\n".join(vuln_info_parts),
            "impact": f.get("impact", "See severity classification."),
            "severity_rating": f.get("severity", "medium").lower(),
            "weakness": f.get("category", "Unknown"),
            "affected_url": f.get("endpoint", ""),
        })

    return json.dumps({
        "report_title": report["report_title"],
        "project_id": report["project_id"],
        "generated_at": report["generated_at"],
        "classification": report["classification"],
        "executive_summary": report["executive_summary"],
        "findings": h1_findings,
        "findings_count": report["findings_count"],
    }, indent=2, default=str)


def _format_bugcrowd_json(report: Dict[str, Any]) -> str:
    """Format report as Bugcrowd-compatible JSON.

    Bugcrowd submission format:
    - title: Vulnerability title
    - vulnerability_details: Detailed description + PoC
    - priority: P1-P5 mapping
    - severity: Critical/High/Medium/Low
    """
    _priority_map = {
        "critical": "P1",
        "high": "P2",
        "medium": "P3",
        "low": "P4",
        "info": "P5",
    }

    bc_findings = []
    for f in report["findings"]:
        details_parts = [
            f"## Description\n{f.get('description', 'N/A')}",
            f"\n## Endpoint\n`{f.get('endpoint', 'N/A')}`",
            f"\n## Category\n{f.get('category', 'N/A')}",
        ]
        if f.get("poc_curl"):
            details_parts.append(f"\n## PoC (curl)\n```\n{f['poc_curl']}\n```")
        if f.get("poc_steps"):
            details_parts.append(f"\n## Steps to Reproduce\n{f['poc_steps']}")
        if f.get("evidence"):
            details_parts.append(f"\n## Evidence\n```\n{f['evidence'][:2000]}\n```")

        sev = f.get("severity", "medium").lower()
        bc_findings.append({
            "title": f.get("title", "Security Finding"),
            "vulnerability_details": "\n".join(details_parts),
            "priority": _priority_map.get(sev, "P3"),
            "severity": sev.capitalize(),
            "weakness": f.get("category", "Unknown"),
            "affected_url": f.get("endpoint", ""),
        })

    return json.dumps({
        "report_title": report["report_title"],
        "project_id": report["project_id"],
        "generated_at": report["generated_at"],
        "executive_summary": report["executive_summary"],
        "findings": bc_findings,
        "findings_count": report["findings_count"],
    }, indent=2, default=str)


def _render_fallback_html(report: Dict[str, Any]) -> str:
    """Minimal HTML fallback when Jinja2 is not available."""
    html_parts = [
        "<!DOCTYPE html><html><head><meta charset='utf-8'>",
        "<style>",
        "body{font-family:Helvetica,Arial,sans-serif;color:#1a1a1a;margin:40px;line-height:1.5}",
        "h1{color:#0f2a44;border-bottom:2px solid #0f2a44;padding-bottom:6px}",
        "h2{color:#1e3a5f;margin-top:24px}",
        ".badge{display:inline-block;padding:2px 8px;border-radius:10px;color:white;font-size:11px;font-weight:bold}",
        ".badge-CRITICAL{background:#7f1d1d}.badge-HIGH{background:#dc2626}",
        ".badge-MEDIUM{background:#d97706}.badge-LOW{background:#16a34a}.badge-INFO{background:#6b7280}",
        ".finding{border:1px solid #ddd;padding:16px;margin:16px 0;border-radius:6px;background:#fafafa}",
        ".poc{background:#111827;color:#e5e7eb;padding:10px;font-family:monospace;font-size:11px;white-space:pre-wrap;border-radius:4px}",
        ".classification{display:inline-block;padding:6px 12px;background:#b91c1c;color:white;font-size:11px;letter-spacing:1px;border-radius:3px}",
        ".footer{margin-top:40px;font-size:10px;color:#888;border-top:1px solid #ddd;padding-top:10px}",
        "</style></head><body>",
        f"<h1>{report.get('report_title', 'Security Report')}</h1>",
        f"<p><span class='classification'>{report.get('classification', 'Confidential')}</span></p>",
        f"<p><strong>Project:</strong> {report.get('project_name', '')} | "
        f"<strong>Generated:</strong> {report.get('generated_at', '')}</p>",
    ]

    # Executive summary
    summary = report.get("executive_summary", {})
    html_parts.append("<h2>Executive Summary</h2>")
    html_parts.append(f"<p>{summary.get('summary', '')}</p>")
    by_sev = summary.get("by_severity", {})
    if by_sev:
        html_parts.append("<table border='1' cellpadding='6' cellspacing='0'>")
        html_parts.append("<tr><th>Severity</th><th>Count</th></tr>")
        for sev, cnt in by_sev.items():
            html_parts.append(f"<tr><td><span class='badge badge-{sev}'>{sev}</span></td><td>{cnt}</td></tr>")
        html_parts.append("</table>")

    # Findings
    html_parts.append("<h2>Detailed Findings</h2>")
    for idx, f in enumerate(report.get("findings", []), 1):
        sev = f.get("severity", "info").upper()
        html_parts.append(f"<div class='finding'>")
        html_parts.append(f"<h3>{idx}. {f.get('title', 'Untitled')} "
                         f"<span class='badge badge-{sev}'>{sev}</span></h3>")
        html_parts.append(f"<p><strong>Endpoint:</strong> <code>{f.get('endpoint', '')}</code></p>")
        html_parts.append(f"<p><strong>Category:</strong> {f.get('category', '')}</p>")
        if f.get("description"):
            html_parts.append(f"<p><strong>Description:</strong> {f.get('description')}</p>")
        html_parts.append(f"<p><strong>Impact:</strong> {f.get('impact', '')}</p>")
        html_parts.append(f"<p><strong>Remediation:</strong> {f.get('remediation', '')}</p>")
        if f.get("poc_curl"):
            html_parts.append(f"<p><strong>PoC curl:</strong></p>")
            html_parts.append(f"<pre class='poc'>{f['poc_curl']}</pre>")
        if f.get("poc_steps"):
            html_parts.append(f"<p><strong>Reproduction Steps:</strong></p>")
            html_parts.append(f"<pre>{f['poc_steps']}</pre>")
        html_parts.append("</div>")

    html_parts.append(f"<div class='footer'>{report.get('disclaimer', '')}</div>")
    html_parts.append("</body></html>")

    return "\n".join(html_parts)
