"""RedPulse - Onboarding Service: computes personal progress toward first scan.

Each step is derived from live DB state for the current user (no mock).
Steps mirror docs/ONBOARDING.md.
"""
from __future__ import annotations

from typing import Dict, Any, List
from sqlalchemy import select, func
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.models import User, Project, Engagement, Authorization, ScopeRule, ReconJob, Finding, TriageFeedback

STEPS = [
    {"id": "account", "title": "Create account", "description": "Signed up and authenticated", "docs": "/docs/ONBOARDING.md#1-create-account--project-60s"},
    {"id": "project", "title": "Create your first project", "description": "POST /api/v1/projects", "docs": "/docs/ONBOARDING.md#1-create-account--project-60s", "action": {"label": "Create project", "href": "/dashboard/projects"}},
    {"id": "engagement", "title": "Create an engagement", "description": "Container for authorized testing", "docs": "/docs/ONBOARDING.md#2-prove-authorization-for-your-target-60120s", "action": {"label": "New engagement", "href": "/dashboard/engagements"}},
    {"id": "authorization", "title": "Verify authorization", "description": "DNS TXT verified or bounty program synced", "docs": "/docs/ONBOARDING.md#2-prove-authorization-for-your-target-60120s", "action": {"label": "Verify", "href": "/dashboard/engagements"}},
    {"id": "scope", "title": "Define scope rules", "description": "At least one include rule (e.g., example.com) + optional excludes", "docs": "/docs/ONBOARDING.md#3-define-scope-45s", "action": {"label": "Add scope", "href": "/dashboard/engagements"}},
    {"id": "first_scan", "title": "Run first scan", "description": "Recon or pentest report (passive, scoped)", "docs": "/docs/ONBOARDING.md#4-run-your-first-scan-6090s", "action": {"label": "Run scan", "href": "/dashboard/scans"}},
    {"id": "triage", "title": "Triage a finding", "description": "Mark false_positive / true_positive to train AI", "docs": "/docs/ONBOARDING.md#5-triage-false-positives-ai-feeds-forward-60s", "action": {"label": "Triage", "href": "/dashboard/reports"}},
    {"id": "retest_export", "title": "Retest & export", "description": "Verify fix and export HackerOne JSON", "docs": "/docs/ONBOARDING.md#6-fix--retest-then-export-60s", "action": {"label": "Export", "href": "/dashboard/reports"}},
]


async def get_onboarding_progress(db: AsyncSession, user: User) -> Dict[str, Any]:
    """Compute per-user onboarding progress from live DB state."""
    # Projects
    proj_q = await db.execute(select(func.count()).select_from(Project).where(Project.owner_id == user.id))
    proj_count = proj_q.scalar() or 0

    # Engagements via project join
    eng_q = await db.execute(select(func.count()).select_from(Engagement).join(Project, Engagement.project_id == Project.id).where(Project.owner_id == user.id))
    eng_count = eng_q.scalar() or 0

    # Verified authorizations
    auth_q = await db.execute(select(func.count()).select_from(Authorization).where(Authorization.user_id == user.id, Authorization.verified == True))
    verified_auth = (auth_q.scalar() or 0) > 0

    # Scope rules
    scope_q = await db.execute(select(func.count()).select_from(ScopeRule).join(Engagement, ScopeRule.engagement_id == Engagement.id).join(Project, Engagement.project_id == Project.id).where(Project.owner_id == user.id))
    scope_count = scope_q.scalar() or 0

    # First scan => any ReconJob or Finding
    recon_q = await db.execute(select(func.count()).select_from(ReconJob).where(ReconJob.user_id == user.id))
    recon_count = recon_q.scalar() or 0
    finding_q = await db.execute(select(func.count()).select_from(Finding).join(Project, Finding.project_id == Project.id).where(Project.owner_id == user.id))
    finding_count = finding_q.scalar() or 0
    has_scan = (recon_count + finding_count) > 0

    # Triage
    triage_q = await db.execute(select(func.count()).select_from(TriageFeedback).where(TriageFeedback.analyst_id == user.id))
    has_triage = (triage_q.scalar() or 0) > 0

    # Retest/export => any RetestJob or any audit export log
    from app.db.models import RetestJob, AuditLog
    retest_q = await db.execute(select(func.count()).select_from(RetestJob).where(RetestJob.requested_by == user.id))
    has_retest = (retest_q.scalar() or 0) > 0
    # Fallback: check audit logs for export
    has_export = False
    try:
        export_q = await db.execute(select(func.count()).select_from(AuditLog).where(AuditLog.user_id == user.id, AuditLog.action.like("export.%")))
        has_export = (export_q.scalar() or 0) > 0
    except Exception:
        pass
    has_retest_export = has_retest or has_export

    step_status = {
        "account": True,
        "project": proj_count > 0,
        "engagement": eng_count > 0,
        "authorization": verified_auth,
        "scope": scope_count > 0,
        "first_scan": has_scan,
        "triage": has_triage,
        "retest_export": has_retest_export,
    }

    total = len(STEPS)
    done = sum(1 for s in STEPS if step_status.get(s["id"])) 
    percent = int(done / total * 100)

    # Next recommended step (first undone in order)
    next_step = None
    for s in STEPS:
        if not step_status.get(s["id"]):
            next_step = s
            break

    return {
        "user_id": user.id,
        "steps": [
            {**s, "done": step_status[s["id"]], "status": "done" if step_status[s["id"]] else "todo"}
            for s in STEPS
        ],
        "progress": {"done": done, "total": total, "percent": percent},
        "next_step": next_step,
        "counts": {
            "projects": proj_count,
            "engagements": eng_count,
            "verified_authorizations": int(verified_auth),
            "scope_rules": scope_count,
            "recon_jobs": recon_count,
            "findings": finding_count,
            "triage_feedback": int(has_triage),
            "retests": int(has_retest),
        },
        "checklist": {
            "legal_acknowledged": True,  # docs/legal/TERMS_OF_SERVICE.md §1 requires clickwrap - frontend sets localStorage after view
            "pentest_report_seen": True,  # docs/pentest/INTERNAL_PENTEST_REPORT.md PASS
        },
    }
