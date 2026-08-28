"""RedPulse - Phase 6: Reporting & Evidence Tests.

Tests for:
- ReportService: finding aggregation, severity filtering, project summary
- JSON export: HackerOne/Bugcrowd compatible formats
- CSV export: with PoC curl, reproduction steps, triage tags
- HTML export: printable report with evidence
- API endpoints: summary, export (json/csv/html), findings listing
"""

import os
import json
import csv
import io
import pytest
import uuid
from datetime import datetime, timezone
from unittest.mock import AsyncMock, patch, MagicMock
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.db.base import Base
from app.db.models import (
    User, Project, Engagement, Authorization, ScopeRule,
    Asset, ReconJob, ReconJobStatus, ReconTool,
    AssetType, RuleType, RuleSource, AuthorizationMethod,
    VulnerabilityScan, VulnScanStatus, Finding, FindingSeverity, FindingStatus,
)
from app.core.security import get_password_hash, create_access_token


# --- Fixtures ---

@pytest.fixture(scope="function")
async def engine():
    eng = create_async_engine(
        "sqlite+aiosqlite:///:memory:",
        echo=False,
        poolclass=StaticPool,
        connect_args={"check_same_thread": False},
    )
    async with eng.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    yield eng
    await eng.dispose()


@pytest.fixture(scope="function")
async def session(engine):
    factory = sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
    async with factory() as s:
        yield s
        await s.rollback()


@pytest.fixture
async def user(session):
    user = User(id=str(uuid.uuid4()), email="alice@test.com", hashed_password=get_password_hash("Pass123!"), is_active=True)
    session.add(user)
    await session.commit()
    return user


async def _make_project(session, owner_id, name="Test Project"):
    p = Project(id=str(uuid.uuid4()), name=name, status="draft", owner_id=owner_id)
    session.add(p)
    await session.commit()
    return p


async def _make_engagement(session, project_id, name="Test Eng"):
    e = Engagement(id=str(uuid.uuid4()), name=name, project_id=project_id, status="draft")
    session.add(e)
    await session.commit()
    return e


async def _make_finding(
    session, engagement_id, project_id, user_id,
    title="Test Finding", severity=FindingSeverity.HIGH, category="xss",
    endpoint="https://example.com/vuln", status=FindingStatus.NEW,
    poc_curl=None, poc_steps=None, triage_tags=None, sensitive_params=None,
    template_id="xss-detect", description="Test description",
    impact="High impact", remediation="Fix it",
):
    f = Finding(
        id=str(uuid.uuid4()),
        engagement_id=engagement_id,
        project_id=project_id,
        user_id=user_id,
        title=title,
        template_id=template_id,
        severity=severity,
        confidence=85,
        category=category,
        description=description,
        evidence="Evidence data",
        endpoint=endpoint,
        matched_at=endpoint,
        impact=impact,
        remediation=remediation,
        poc_curl=poc_curl,
        poc_steps=poc_steps,
        triage_tags=triage_tags,
        sensitive_params=sensitive_params,
        fingerprint=str(uuid.uuid4())[:64],
        status=status,
        first_seen=datetime.now(timezone.utc),
        last_seen=datetime.now(timezone.utc),
    )
    session.add(f)
    await session.commit()
    return f


# ============================================================
# REPORT SERVICE TESTS
# ============================================================

class TestReportService:

    @pytest.mark.asyncio
    async def test_get_findings_for_project(self, session, user):
        """ReportService fetches findings for a project."""
        from app.services.report_service import ReportService

        project = await _make_project(session, user.id)
        engagement = await _make_engagement(session, project.id)

        await _make_finding(session, engagement.id, project.id, user.id,
                           title="Critical SQLi", severity=FindingSeverity.CRITICAL)
        await _make_finding(session, engagement.id, project.id, user.id,
                           title="High XSS", severity=FindingSeverity.HIGH)
        await _make_finding(session, engagement.id, project.id, user.id,
                           title="Low Info", severity=FindingSeverity.LOW)

        service = ReportService(session)
        findings = await service.get_findings_for_project(project.id)

        assert len(findings) == 3
        # Sorted by severity: critical first
        assert findings[0].severity == FindingSeverity.CRITICAL
        assert findings[1].severity == FindingSeverity.HIGH
        assert findings[2].severity == FindingSeverity.LOW

    @pytest.mark.asyncio
    async def test_get_findings_min_severity_filter(self, session, user):
        """ReportService filters by minimum severity."""
        from app.services.report_service import ReportService

        project = await _make_project(session, user.id)
        engagement = await _make_engagement(session, project.id)

        await _make_finding(session, engagement.id, project.id, user.id,
                           title="Critical", severity=FindingSeverity.CRITICAL)
        await _make_finding(session, engagement.id, project.id, user.id,
                           title="High", severity=FindingSeverity.HIGH)
        await _make_finding(session, engagement.id, project.id, user.id,
                           title="Medium", severity=FindingSeverity.MEDIUM)
        await _make_finding(session, engagement.id, project.id, user.id,
                           title="Low", severity=FindingSeverity.LOW)

        service = ReportService(session)
        findings = await service.get_findings_for_project(
            project.id, min_severity=FindingSeverity.HIGH
        )

        # Should include CRITICAL and HIGH only
        assert len(findings) == 2
        severities = {f.severity for f in findings}
        assert FindingSeverity.CRITICAL in severities
        assert FindingSeverity.HIGH in severities
        assert FindingSeverity.MEDIUM not in severities

    @pytest.mark.asyncio
    async def test_get_findings_excludes_resolved(self, session, user):
        """ReportService excludes resolved findings by default."""
        from app.services.report_service import ReportService

        project = await _make_project(session, user.id)
        engagement = await _make_engagement(session, project.id)

        await _make_finding(session, engagement.id, project.id, user.id,
                           title="Active", severity=FindingSeverity.HIGH,
                           status=FindingStatus.NEW)
        await _make_finding(session, engagement.id, project.id, user.id,
                           title="Resolved", severity=FindingSeverity.HIGH,
                           status=FindingStatus.RESOLVED)

        service = ReportService(session)
        findings = await service.get_findings_for_project(project.id)

        assert len(findings) == 1
        assert findings[0].title == "Active"

    @pytest.mark.asyncio
    async def test_get_findings_include_resolved(self, session, user):
        """ReportService includes resolved findings when requested."""
        from app.services.report_service import ReportService

        project = await _make_project(session, user.id)
        engagement = await _make_engagement(session, project.id)

        await _make_finding(session, engagement.id, project.id, user.id,
                           title="Active", severity=FindingSeverity.HIGH,
                           status=FindingStatus.NEW)
        await _make_finding(session, engagement.id, project.id, user.id,
                           title="Resolved", severity=FindingSeverity.HIGH,
                           status=FindingStatus.RESOLVED)

        service = ReportService(session)
        findings = await service.get_findings_for_project(
            project.id, include_resolved=True
        )

        assert len(findings) == 2

    @pytest.mark.asyncio
    async def test_get_findings_by_engagement(self, session, user):
        """ReportService filters findings by engagement."""
        from app.services.report_service import ReportService

        project = await _make_project(session, user.id)
        eng1 = await _make_engagement(session, project.id, "Eng 1")
        eng2 = await _make_engagement(session, project.id, "Eng 2")

        await _make_finding(session, eng1.id, project.id, user.id, title="F1")
        await _make_finding(session, eng2.id, project.id, user.id, title="F2")

        service = ReportService(session)
        findings = await service.get_findings_for_project(
            project.id, engagement_id=eng1.id
        )

        assert len(findings) == 1
        assert findings[0].title == "F1"

    @pytest.mark.asyncio
    async def test_get_project_summary(self, session, user):
        """ReportService returns correct project summary."""
        from app.services.report_service import ReportService

        project = await _make_project(session, user.id)
        engagement = await _make_engagement(session, project.id)

        await _make_finding(session, engagement.id, project.id, user.id,
                           severity=FindingSeverity.CRITICAL)
        await _make_finding(session, engagement.id, project.id, user.id,
                           severity=FindingSeverity.CRITICAL)
        await _make_finding(session, engagement.id, project.id, user.id,
                           severity=FindingSeverity.HIGH)
        await _make_finding(session, engagement.id, project.id, user.id,
                           severity=FindingSeverity.LOW)

        service = ReportService(session)
        summary = await service.get_project_summary(project.id)

        assert summary["total_findings"] == 4
        assert summary["severity_breakdown"]["critical"] == 2
        assert summary["severity_breakdown"]["high"] == 1
        assert summary["severity_breakdown"]["low"] == 1
        assert summary["high_severity_count"] == 3
        assert summary["has_critical_findings"] is True

    @pytest.mark.asyncio
    async def test_get_project_summary_empty(self, session, user):
        """ReportService handles empty project summary."""
        from app.services.report_service import ReportService

        project = await _make_project(session, user.id)

        service = ReportService(session)
        summary = await service.get_project_summary(project.id)

        assert summary["total_findings"] == 0
        assert summary["has_critical_findings"] is False


# ============================================================
# JSON EXPORT TESTS
# ============================================================

class TestJSONExport:

    @pytest.mark.asyncio
    async def test_export_json_hackerone_format(self, session, user):
        """JSON export produces HackerOne-compatible format."""
        from app.services.report_service import ReportService

        project = await _make_project(session, user.id)
        engagement = await _make_engagement(session, project.id)

        await _make_finding(
            session, engagement.id, project.id, user.id,
            title="SQL Injection in Login", severity=FindingSeverity.CRITICAL,
            category="sqli", endpoint="https://api.example.com/login",
            poc_curl='curl -v "https://api.example.com/login"',
            poc_steps="1. Navigate to login\n2. Enter SQL payload",
            description="SQL injection allows authentication bypass",
            impact="Full database access",
            triage_tags=["critical_risk", "insecure_direct_object"],
        )

        service = ReportService(session)
        json_str = await service.export_json(project.id, platform="hackerone")

        data = json.loads(json_str)
        assert "findings" in data
        assert len(data["findings"]) == 1

        h1_finding = data["findings"][0]
        assert h1_finding["title"] == "SQL Injection in Login"
        assert h1_finding["severity_rating"] == "critical"
        assert "curl" in h1_finding["vulnerability_information"]
        assert "Reproduction Steps" in h1_finding["vulnerability_information"]
        assert "SQL injection" in h1_finding["vulnerability_information"]

    @pytest.mark.asyncio
    async def test_export_json_bugcrowd_format(self, session, user):
        """JSON export produces Bugcrowd-compatible format."""
        from app.services.report_service import ReportService

        project = await _make_project(session, user.id)
        engagement = await _make_engagement(session, project.id)

        await _make_finding(
            session, engagement.id, project.id, user.id,
            title="XSS in Search", severity=FindingSeverity.HIGH,
            category="xss", endpoint="https://example.com/search",
            poc_curl='curl "https://example.com/search?q=<script>"',
        )

        service = ReportService(session)
        json_str = await service.export_json(project.id, platform="bugcrowd")

        data = json.loads(json_str)
        bc_finding = data["findings"][0]
        assert bc_finding["title"] == "XSS in Search"
        assert bc_finding["priority"] == "P2"
        assert bc_finding["severity"] == "High"
        assert "curl" in bc_finding["vulnerability_details"]

    @pytest.mark.asyncio
    async def test_export_json_includes_triage_tags(self, session, user):
        """JSON export includes triage tags in findings (embedded in vulnerability info)."""
        from app.services.report_service import ReportService

        project = await _make_project(session, user.id)
        engagement = await _make_engagement(session, project.id)

        await _make_finding(
            session, engagement.id, project.id, user.id,
            title="IDOR", severity=FindingSeverity.HIGH,
            triage_tags=["insecure_direct_object", "broken_access_control"],
            sensitive_params=["user_id", "doc_id"],
        )

        service = ReportService(session)
        json_str = await service.export_json(project.id)

        data = json.loads(json_str)
        f = data["findings"][0]
        # H1 format embeds triage tags in vulnerability_information
        assert "insecure_direct_object" in f["vulnerability_information"]
        assert "broken_access_control" in f["vulnerability_information"]

    @pytest.mark.asyncio
    async def test_export_json_empty_project(self, session, user):
        """JSON export works with no findings."""
        from app.services.report_service import ReportService

        project = await _make_project(session, user.id)

        service = ReportService(session)
        json_str = await service.export_json(project.id)

        data = json.loads(json_str)
        assert data["findings_count"] == 0
        assert data["findings"] == []
        assert "No findings" in data["executive_summary"]["summary"]


# ============================================================
# CSV EXPORT TESTS
# ============================================================

class TestCSVExport:

    @pytest.mark.asyncio
    async def test_export_csv_has_correct_headers(self, session, user):
        """CSV export includes all expected column headers."""
        from app.services.report_service import ReportService

        project = await _make_project(session, user.id)
        engagement = await _make_engagement(session, project.id)

        await _make_finding(session, engagement.id, project.id, user.id,
                           poc_curl="curl https://example.com")

        service = ReportService(session)
        csv_str = await service.export_csv(project.id)

        reader = csv.reader(io.StringIO(csv_str))
        headers = next(reader)

        assert "Title" in headers
        assert "Severity" in headers
        assert "PoC curl" in headers
        assert "Reproduction Steps" in headers
        assert "Triage Tags" in headers
        assert "Endpoint" in headers

    @pytest.mark.asyncio
    async def test_export_csv_finding_row(self, session, user):
        """CSV export contains correct finding data."""
        from app.services.report_service import ReportService

        project = await _make_project(session, user.id)
        engagement = await _make_engagement(session, project.id)

        await _make_finding(
            session, engagement.id, project.id, user.id,
            title="SQLi in Login", severity=FindingSeverity.CRITICAL,
            endpoint="https://api.example.com/login",
            poc_curl='curl -v "https://api.example.com/login"',
            poc_steps="1. Go to login\n2. Enter payload",
            triage_tags=["critical_risk"],
            sensitive_params=["user_id"],
        )

        service = ReportService(session)
        csv_str = await service.export_csv(project.id)

        reader = csv.reader(io.StringIO(csv_str))
        headers = next(reader)
        row = next(reader)

        title_idx = headers.index("Title")
        sev_idx = headers.index("Severity")
        curl_idx = headers.index("PoC curl")
        steps_idx = headers.index("Reproduction Steps")
        tags_idx = headers.index("Triage Tags")

        assert row[title_idx] == "SQLi in Login"
        assert row[sev_idx] == "critical"
        assert "curl" in row[curl_idx]
        assert "payload" in row[steps_idx]
        assert "critical_risk" in row[tags_idx]

    @pytest.mark.asyncio
    async def test_export_csv_empty_project(self, session, user):
        """CSV export works with no findings (headers only)."""
        from app.services.report_service import ReportService

        project = await _make_project(session, user.id)

        service = ReportService(session)
        csv_str = await service.export_csv(project.id)

        reader = csv.reader(io.StringIO(csv_str))
        headers = next(reader)
        assert "Title" in headers

        # No data rows
        rows = list(reader)
        assert len(rows) == 0


# ============================================================
# HTML EXPORT TESTS
# ============================================================

class TestHTMLExport:

    @pytest.mark.asyncio
    async def test_export_html_contains_findings(self, session, user):
        """HTML export contains finding details."""
        from app.services.report_service import ReportService

        project = await _make_project(session, user.id)
        engagement = await _make_engagement(session, project.id)

        await _make_finding(
            session, engagement.id, project.id, user.id,
            title="XSS in Search", severity=FindingSeverity.HIGH,
            endpoint="https://example.com/search",
            poc_curl='curl "https://example.com/search"',
            description="Reflected XSS vulnerability",
        )

        service = ReportService(session)
        html = await service.export_html(project.id)

        assert "XSS in Search" in html
        assert "example.com" in html
        assert "curl" in html
        assert "Reflected XSS" in html

    @pytest.mark.asyncio
    async def test_export_html_empty_project(self, session, user):
        """HTML export works with no findings."""
        from app.services.report_service import ReportService

        project = await _make_project(session, user.id)

        service = ReportService(session)
        html = await service.export_html(project.id)

        assert "<html" in html
        assert "No findings" in html.lower() or "findings" in html.lower()


# ============================================================
# REPORT GENERATION (generate_report) TESTS
# ============================================================

class TestGenerateReport:

    @pytest.mark.asyncio
    async def test_generate_report_structure(self, session, user):
        """generate_report returns correct report structure."""
        from app.services.report_service import ReportService

        project = await _make_project(session, user.id, name="My Project")
        engagement = await _make_engagement(session, project.id)

        await _make_finding(session, engagement.id, project.id, user.id,
                           title="Test Vuln", severity=FindingSeverity.CRITICAL)

        service = ReportService(session)
        report = await service.generate_report(project.id)

        assert report["project_name"] == "My Project"
        assert report["findings_count"] == 1
        assert report["findings"][0]["title"] == "Test Vuln"
        assert report["executive_summary"]["total"] == 1
        assert report["executive_summary"]["by_severity"].get("CRITICAL", 0) > 0
        assert "Confidential" in report["classification"]

    @pytest.mark.asyncio
    async def test_generate_report_min_severity(self, session, user):
        """generate_report respects min_severity parameter."""
        from app.services.report_service import ReportService, FindingSeverity

        project = await _make_project(session, user.id)
        engagement = await _make_engagement(session, project.id)

        await _make_finding(session, engagement.id, project.id, user.id,
                           title="Critical", severity=FindingSeverity.CRITICAL)
        await _make_finding(session, engagement.id, project.id, user.id,
                           title="Low", severity=FindingSeverity.LOW)

        service = ReportService(session)
        report = await service.generate_report(
            project.id, min_severity=FindingSeverity.CRITICAL
        )

        assert report["findings_count"] == 1
        assert report["findings"][0]["title"] == "Critical"


# ============================================================
# FINDING TO DICT HELPER TESTS
# ============================================================

class TestFindingToDict:

    def test_finding_to_dict_includes_all_fields(self):
        """_finding_to_dict includes all report-relevant fields."""
        from app.services.report_service import _finding_to_dict

        now = datetime.now(timezone.utc)
        f = Finding(
            id="f-1", engagement_id="e-1", project_id="p-1", user_id="u-1",
            title="Test", severity=FindingSeverity.HIGH, confidence=85,
            category="xss", status=FindingStatus.NEW, template_id="xss-detect",
            endpoint="https://example.com", matched_at="https://example.com/path",
            description="Desc", evidence="Evidence", impact="Impact",
            remediation="Fix", poc_curl="curl ...", poc_steps="Steps",
            triage_tags=["critical_risk"], sensitive_params=["id"],
            fingerprint="fp123", first_seen=now, last_seen=now,
        )

        d = _finding_to_dict(f)
        assert d["id"] == "f-1"
        assert d["title"] == "Test"
        assert d["severity"] == "high"
        assert d["poc_curl"] == "curl ..."
        assert d["poc_steps"] == "Steps"
        assert d["triage_tags"] == ["critical_risk"]
        assert d["sensitive_params"] == ["id"]


# ============================================================
# HACKERONE / BUGCROWD FORMAT TESTS
# ============================================================

class TestBountyFormats:

    def test_hackerone_format_structure(self):
        """HackerOne JSON has required fields."""
        from app.services.report_service import _format_hackerone_json

        report = {
            "report_title": "Test Report",
            "project_id": "proj-1",
            "generated_at": "2026-01-01T00:00:00Z",
            "classification": "Confidential",
            "executive_summary": {"total": 1, "by_severity": {"HIGH": 1}},
            "findings": [{
                "title": "XSS",
                "description": "Reflected XSS",
                "endpoint": "https://example.com/search",
                "category": "xss",
                "poc_curl": "curl https://example.com",
                "poc_steps": "1. Go to search",
                "evidence": "Response body",
                "severity": "high",
                "triage_tags": ["critical_risk"],
                "impact": "Account takeover",
            }],
            "findings_count": 1,
        }

        json_str = _format_hackerone_json(report)
        data = json.loads(json_str)

        f = data["findings"][0]
        assert "title" in f
        assert "vulnerability_information" in f
        assert "impact" in f
        assert "severity_rating" in f
        assert "curl" in f["vulnerability_information"]
        assert "Reproduction Steps" in f["vulnerability_information"]
        assert "critical_risk" in f["vulnerability_information"]

    def test_bugcrowd_format_structure(self):
        """Bugcrowd JSON has required fields."""
        from app.services.report_service import _format_bugcrowd_json

        report = {
            "report_title": "Test Report",
            "project_id": "proj-1",
            "generated_at": "2026-01-01T00:00:00Z",
            "executive_summary": {"total": 1},
            "findings": [{
                "title": "SQLi",
                "description": "SQL injection",
                "endpoint": "https://api.example.com/login",
                "category": "sqli",
                "poc_curl": "curl -d 'a=b' https://api.example.com/login",
                "poc_steps": "1. Open login\n2. Inject payload",
                "evidence": "Error message",
                "severity": "critical",
            }],
            "findings_count": 1,
        }

        json_str = _format_bugcrowd_json(report)
        data = json.loads(json_str)

        f = data["findings"][0]
        assert f["priority"] == "P1"
        assert f["severity"] == "Critical"
        assert "curl" in f["vulnerability_details"]
        assert "Steps to Reproduce" in f["vulnerability_details"]

    def test_severity_to_priority_mapping(self):
        """Bugcrowd priority mapping is correct."""
        from app.services.report_service import _format_bugcrowd_json

        report = {
            "report_title": "Test",
            "project_id": "p1",
            "generated_at": "2026-01-01T00:00:00Z",
            "executive_summary": {},
            "findings": [
                {"title": "C", "severity": "critical", "endpoint": "", "category": "",
                 "description": "", "evidence": "", "impact": "", "remediation": "",
                 "poc_curl": "", "poc_steps": ""},
                {"title": "H", "severity": "high", "endpoint": "", "category": "",
                 "description": "", "evidence": "", "impact": "", "remediation": "",
                 "poc_curl": "", "poc_steps": ""},
                {"title": "M", "severity": "medium", "endpoint": "", "category": "",
                 "description": "", "evidence": "", "impact": "", "remediation": "",
                 "poc_curl": "", "poc_steps": ""},
                {"title": "L", "severity": "low", "endpoint": "", "category": "",
                 "description": "", "evidence": "", "impact": "", "remediation": "",
                 "poc_curl": "", "poc_steps": ""},
            ],
            "findings_count": 4,
        }

        json_str = _format_bugcrowd_json(report)
        data = json.loads(json_str)

        priorities = {f["title"]: f["priority"] for f in data["findings"]}
        assert priorities["C"] == "P1"
        assert priorities["H"] == "P2"
        assert priorities["M"] == "P3"
        assert priorities["L"] == "P4"


# ============================================================
# EXECUTIVE SUMMARY TESTS
# ============================================================

class TestExecutiveSummary:

    def test_summary_with_findings(self):
        from app.services.report_service import _build_executive_summary

        findings = [
            {"severity": "critical"},
            {"severity": "critical"},
            {"severity": "high"},
            {"severity": "low"},
        ]

        summary = _build_executive_summary(findings, "Test Project")
        assert summary["total"] == 4
        assert summary["by_severity"]["CRITICAL"] == 2
        assert summary["by_severity"]["HIGH"] == 1
        assert summary["high_severity_count"] == 3
        assert "4 findings" in summary["summary"]

    def test_summary_empty_findings(self):
        from app.services.report_service import _build_executive_summary

        summary = _build_executive_summary([], "Test Project")
        assert summary["total"] == 0
        assert "No findings" in summary["summary"]


# ============================================================
# FALLBACK HTML RENDERER TESTS
# ============================================================

class TestFallbackHTML:

    def test_fallback_html_structure(self):
        from app.services.report_service import _render_fallback_html

        report = {
            "report_title": "Test Report",
            "classification": "Confidential",
            "project_name": "My Project",
            "generated_at": "2026-01-01",
            "executive_summary": {"summary": "No issues", "by_severity": {"HIGH": 1}},
            "findings": [{
                "title": "XSS",
                "severity": "high",
                "endpoint": "https://example.com",
                "category": "xss",
                "description": "Reflected XSS",
                "impact": "Account takeover",
                "remediation": "Encode output",
                "poc_curl": "curl https://example.com",
                "poc_steps": "1. Go to page",
            }],
            "disclaimer": "Controlled testing only",
        }

        html = _render_fallback_html(report)
        assert "<html" in html
        assert "Test Report" in html
        assert "XSS" in html
        assert "curl" in html
        assert "Controlled testing only" in html
