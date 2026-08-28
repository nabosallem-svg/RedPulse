"""RedPulse - Finding Export to GitHub/Jira.

POST /api/v1/projects/{project_id}/findings/{finding_id}/export-ticket
"""

from typing import Literal
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_current_user, get_db
from app.db.models import User
from app.services.integrations import dispatch_finding_webhook
from app.services.remediation_snippets import get_snippet
from app.services.compliance import map_finding_compliance

router = APIRouter(tags=["integrations"])


class ExportTicketRequest(BaseModel):
    target: Literal["github", "jira"] = Field(..., description="github or jira")
    repo: str = Field("RedPulse/security-findings", description="GitHub repo or Jira project key")
    tech_stack: str = Field("python-fastapi", description="Tech stack for remediation snippet")


@router.post("/{finding_id}/export-ticket")
async def export_finding_ticket(
    finding_id: str,
    data: ExportTicketRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Export a finding to GitHub Issue or Jira Ticket (mock).

    Note: In production, this should verify finding ownership via project.
    The finding_id is used to identify the finding type for demo purposes.
    """
    if data.target not in ("github", "jira"):
        raise HTTPException(status_code=400, detail="target must be github or jira")

    # Derive template from finding_id for demo (real implementation queries Finding table)
    template = "sqli" if "sqli" in finding_id.lower() else ("xss" if "xss" in finding_id.lower() else ("cors" if "cors" in finding_id.lower() else "idor"))
    finding = {
        "id": finding_id,
        "fingerprint": finding_id,
        "template_id": template,
        "severity": "HIGH",
        "host": "example.com",
        "evidence": f"Finding {finding_id}",
        "compliance": map_finding_compliance({"template_id": template}),
    }

    snippet = get_snippet(template, data.tech_stack)
    finding["remediation_snippet"] = snippet

    try:
        result = dispatch_finding_webhook(finding, data.target, repo=data.repo, project=data.repo)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

    return {
        "success": True,
        "data": {
            "finding_id": finding_id,
            "target": data.target,
            "ticket": result,
            "remediation_snippet": snippet,
            "compliance": finding["compliance"],
        },
    }
