"""RedPulse - Developer Integration Mocks (GitHub Issues / Jira Tickets).

Service layer for dispatching finding webhooks. No real external calls without
credentials - returns mock success payloads for testing and logs dispatch.
"""

import logging
import hashlib
import datetime
from typing import Dict, Any, Literal

logger = logging.getLogger(__name__)

Target = Literal["github", "jira"]


def _mock_url(target: Target, finding_id: str) -> str:
    h = hashlib.sha256(finding_id.encode()).hexdigest()[:8]
    if target == "github":
        return f"https://github.com/RedPulse/repo/issues/{h}"
    return f"https://RedPulse.atlassian.net/browse/SEC-{h.upper()}"


def create_github_issue(finding: Dict[str, Any], repo: str = "RedPulse/security-findings") -> Dict[str, Any]:
    """Mock GitHub Issue creation."""
    finding_id = finding.get("id") or finding.get("fingerprint") or "unknown"
    title = finding.get("title") or finding.get("template_id") or "Security Finding"
    body = f"""**Severity:** {finding.get('severity','unknown')}  **CVSS:** {finding.get('cvss_score','-')}
**Host:** {finding.get('host','-')}
**Evidence:** {finding.get('evidence','-')[:500]}
**Fingerprint:** {finding.get('fingerprint','-')}
**Compliance:** {finding.get('compliance',{})}
"""
    url = _mock_url("github", finding_id)
    logger.info(f"[MOCK] GitHub issue for {finding_id} -> {url} (repo {repo})")
    return {
        "target": "github",
        "repo": repo,
        "issue_url": url,
        "issue_id": finding_id,
        "title": f"[RedPulse] {title}",
        "body": body,
        "state": "open",
        "created_at": datetime.datetime.now(datetime.timezone.utc).isoformat().replace("+00:00", "Z"),
        "mock": True,
    }


def create_jira_ticket(finding: Dict[str, Any], project: str = "SEC") -> Dict[str, Any]:
    """Mock Jira Ticket creation."""
    finding_id = finding.get("id") or finding.get("fingerprint") or "unknown"
    title = finding.get("title") or finding.get("template_id") or "Security Finding"
    desc = f"Severity {finding.get('severity')} - Host {finding.get('host')} - Evidence {str(finding.get('evidence',''))[:500]}"
    url = _mock_url("jira", finding_id)
    logger.info(f"[MOCK] Jira ticket for {finding_id} -> {url} (project {project})")
    return {
        "target": "jira",
        "project": project,
        "ticket_url": url,
        "ticket_id": finding_id,
        "summary": f"[RedPulse] {title}",
        "description": desc,
        "status": "To Do",
        "created_at": datetime.datetime.now(datetime.timezone.utc).isoformat().replace("+00:00", "Z"),
        "mock": True,
    }


def dispatch_finding_webhook(finding: Dict[str, Any], target: Target, **kwargs) -> Dict[str, Any]:
    """Dispatch finding to target integration (mock)."""
    if target == "github":
        return create_github_issue(finding, repo=kwargs.get("repo", "RedPulse/security-findings"))
    elif target == "jira":
        return create_jira_ticket(finding, project=kwargs.get("project", "SEC"))
    else:
        raise ValueError(f"Unsupported target: {target}. Use github|jira")
