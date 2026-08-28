"""RedPulse - Phase 4: Core Integration & End-to-End Pipeline Tests.

Tests for:
- Async pipeline orchestration (recon -> assess -> ingest)
- Finding ingestion with fingerprint deduplication
- Finding-asset mapping
- Test auth bypass for local E2E
- Error handling & graceful failure
- Scope enforcement through pipeline
"""

import os
import pytest
import uuid
from datetime import datetime, timezone
from unittest.mock import AsyncMock, patch, MagicMock
from sqlalchemy import create_engine, select
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.db.base import Base
from app.db.models import (
    User, Project, Engagement, Authorization, ScopeRule,
    Asset, ReconJob, ReconResult, ReconJobStatus, ReconTool,
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


async def _make_auth(session, engagement_id, project_id, user_id, verified=True, expires_at=None):
    a = Authorization(
        id=str(uuid.uuid4()),
        engagement_id=engagement_id,
        project_id=project_id,
        user_id=user_id,
        target_domain="example.com",
        method=AuthorizationMethod.DNS_TXT,
        verified=verified,
        expires_at=expires_at,
    )
    session.add(a)
    await session.commit()
    return a


async def _make_scope_rule(session, engagement_id, pattern, rule_type=RuleType.INCLUDE):
    r = ScopeRule(
        id=str(uuid.uuid4()),
        engagement_id=engagement_id,
        pattern=pattern,
        rule_type=rule_type,
        source=RuleSource.USER_DEFINED,
    )
    session.add(r)
    await session.commit()
    return r


async def _make_asset(session, engagement_id, value, asset_type=AssetType.SUBDOMAIN, source_tool=ReconTool.SUBFINDER, port=None, http_status=None):
    a = Asset(
        id=str(uuid.uuid4()),
        engagement_id=engagement_id,
        asset_type=asset_type,
        value=value,
        source_tool=source_tool,
        port=port,
        http_status=http_status,
        first_seen=datetime.now(timezone.utc),
        last_seen=datetime.now(timezone.utc),
    )
    session.add(a)
    await session.commit()
    return a


def _get_token(user):
    return create_access_token(subject=user.email)


# ============================================================
# FINDING INGESTION TESTS
# ============================================================

class TestFindingIngestion:

    @pytest.mark.asyncio
    async def test_ingest_single_finding(self, session, user):
        from app.services.finding_ingester import ingest_nuclei_finding

        project = await _make_project(session, user.id)
        engagement = await _make_engagement(session, project.id)
        asset = await _make_asset(session, engagement.id, "web.example.com")

        raw_finding = {
            "host": "web.example.com",
            "template_id": "technologies/nginx-detect",
            "severity": "info",
            "matched-at": "https://web.example.com",
            "info": {"name": "Nginx Detected", "description": "Nginx web server detected"},
            "raw_output": '{"template-id":"technologies/nginx-detect"}',
        }

        finding = await ingest_nuclei_finding(
            db=session,
            engagement_id=engagement.id,
            project_id=project.id,
            user_id=user.id,
            scan_id=None,
            raw_finding=raw_finding,
        )

        assert finding.id is not None
        assert finding.engagement_id == engagement.id
        assert finding.project_id == project.id
        assert finding.asset_id == asset.id
        assert finding.title == "Nginx Detected"
        assert finding.severity == FindingSeverity.INFO
        assert finding.status == FindingStatus.NEW
        assert finding.fingerprint is not None
        assert len(finding.fingerprint) == 64

    @pytest.mark.asyncio
    async def test_ingest_finding_dedup(self, session, user):
        from app.services.finding_ingester import ingest_nuclei_finding

        project = await _make_project(session, user.id)
        engagement = await _make_engagement(session, project.id)
        asset = await _make_asset(session, engagement.id, "web.example.com")

        raw = {
            "host": "web.example.com",
            "template_id": "technologies/nginx-detect",
            "severity": "info",
            "matched-at": "https://web.example.com",
            "info": {"name": "Nginx Detected"},
        }

        f1 = await ingest_nuclei_finding(session, engagement.id, project.id, user.id, None, raw)
        f2 = await ingest_nuclei_finding(session, engagement.id, project.id, user.id, None, raw)

        # Same fingerprint = same record, updated last_seen
        assert f1.id == f2.id
        assert f2.last_seen >= f1.first_seen

    @pytest.mark.asyncio
    async def test_ingest_finding_reopens_resolved(self, session, user):
        from app.services.finding_ingester import ingest_nuclei_finding, generate_fingerprint

        project = await _make_project(session, user.id)
        engagement = await _make_engagement(session, project.id)

        fingerprint = generate_fingerprint(engagement.id, "xss-detect", "https://x.example.com/path", "x.example.com")

        # Pre-create a resolved finding
        finding = Finding(
            id=str(uuid.uuid4()),
            engagement_id=engagement.id,
            project_id=project.id,
            user_id=user.id,
            title="XSS",
            template_id="xss-detect",
            severity=FindingSeverity.HIGH,
            confidence=85,
            fingerprint=fingerprint,
            status=FindingStatus.RESOLVED,
            first_seen=datetime.now(timezone.utc),
            last_seen=datetime.now(timezone.utc),
        )
        session.add(finding)
        await session.commit()

        raw = {
            "host": "x.example.com",
            "template_id": "xss-detect",
            "severity": "high",
            "matched-at": "https://x.example.com/path",
            "info": {"name": "XSS"},
        }

        result = await ingest_nuclei_finding(session, engagement.id, project.id, user.id, None, raw)
        assert result.id == finding.id
        assert result.status == FindingStatus.REOPENED

    @pytest.mark.asyncio
    async def test_ingest_batch(self, session, user):
        from app.services.finding_ingester import ingest_nuclei_findings_batch

        project = await _make_project(session, user.id)
        engagement = await _make_engagement(session, project.id)

        raw_findings = [
            {"host": f"host{i}.example.com", "template_id": f"template-{i}", "severity": "medium", "matched-at": f"https://host{i}.example.com", "info": {"name": f"Finding {i}"}}
            for i in range(5)
        ]

        findings = await ingest_nuclei_findings_batch(
            session, engagement.id, project.id, user.id, None, raw_findings
        )

        assert len(findings) == 5
        assert all(f.project_id == project.id for f in findings)
        assert all(f.engagement_id == engagement.id for f in findings)

    @pytest.mark.asyncio
    async def test_fingerprint_generation_deterministic(self):
        from app.services.finding_ingester import generate_fingerprint

        fp1 = generate_fingerprint("eng1", "template-a", "https://host.com/path", "host.com")
        fp2 = generate_fingerprint("eng1", "template-a", "https://host.com/path", "host.com")
        assert fp1 == fp2

        fp3 = generate_fingerprint("eng1", "template-b", "https://host.com/path", "host.com")
        assert fp1 != fp3

    @pytest.mark.asyncio
    async def test_severity_mapping(self):
        from app.services.finding_ingester import _severity_from_nuclei
        from app.db.models import FindingSeverity

        assert _severity_from_nuclei("critical") == FindingSeverity.CRITICAL
        assert _severity_from_nuclei("high") == FindingSeverity.HIGH
        assert _severity_from_nuclei("medium") == FindingSeverity.MEDIUM
        assert _severity_from_nuclei("low") == FindingSeverity.LOW
        assert _severity_from_nuclei("info") == FindingSeverity.INFO
        assert _severity_from_nuclei("unknown") == FindingSeverity.INFO


# ============================================================
# TEST AUTH BYPASS TESTS
# ============================================================

class TestAuthBypass:

    @pytest.mark.asyncio
    async def test_bypass_active_in_test_env(self, session, user):
        """When TESTING=1 and scope rules exist, auth check is bypassed."""
        os.environ["TESTING"] = "1"
        try:
            project = await _make_project(session, user.id)
            engagement = await _make_engagement(session, project.id)
            await _make_scope_rule(session, engagement.id, "*.example.com")

            # No Authorization record — would normally fail
            from app.services.scope_validator import validate_target
            result = await validate_target(engagement.id, "sub.example.com", session, user)
            assert result is None  # Allowed via bypass
        finally:
            del os.environ["TESTING"]

    @pytest.mark.asyncio
    async def test_bypass_blocked_without_scope_rules(self, session, user):
        """When TESTING=1 but no scope rules exist, auth check still enforced."""
        os.environ["TESTING"] = "1"
        try:
            project = await _make_project(session, user.id)
            engagement = await _make_engagement(session, project.id)
            # No scope rules, no authorization

            from app.services.scope_validator import validate_target, ScopeViolation
            with pytest.raises(ScopeViolation, match="No authorization"):
                await validate_target(engagement.id, "sub.example.com", session, user)
        finally:
            del os.environ["TESTING"]

    @pytest.mark.asyncio
    async def test_bypass_not_active_in_production(self, session, user):
        """When ENVIRONMENT=production, auth check is enforced even with scope rules."""
        os.environ["ENVIRONMENT"] = "production"
        os.environ.pop("TESTING", None)
        try:
            project = await _make_project(session, user.id)
            engagement = await _make_engagement(session, project.id)
            await _make_scope_rule(session, engagement.id, "*.example.com")

            from app.services.scope_validator import validate_target, ScopeViolation
            with pytest.raises(ScopeViolation, match="No authorization"):
                await validate_target(engagement.id, "sub.example.com", session, user)
        finally:
            os.environ.pop("ENVIRONMENT", None)

    @pytest.mark.asyncio
    async def test_bypass_allows_unverified_auth_with_scope_rules(self, session, user):
        """In test mode, unverified auth is bypassed when scope rules exist."""
        os.environ["TESTING"] = "1"
        try:
            project = await _make_project(session, user.id)
            engagement = await _make_engagement(session, project.id)
            await _make_auth(session, engagement.id, project.id, user.id, verified=False)
            await _make_scope_rule(session, engagement.id, "*.example.com")

            from app.services.scope_validator import validate_target
            result = await validate_target(engagement.id, "sub.example.com", session, user)
            assert result is None
        finally:
            del os.environ["TESTING"]


# ============================================================
# PIPELINE ORCHESTRATOR TESTS
# ============================================================

class TestPipelineOrchestrator:

    @pytest.mark.asyncio
    async def test_pipeline_scope_violation_fails(self, session, user):
        """Pipeline fails gracefully on scope violation."""
        os.environ["TESTING"] = "1"
        try:
            project = await _make_project(session, user.id)
            engagement = await _make_engagement(session, project.id)
            await _make_scope_rule(session, engagement.id, "*.example.com")

            from app.services.pipeline import PipelineOrchestrator

            orchestrator = PipelineOrchestrator(db=session, user=user)
            # Target is out of scope (no auth bypass needed for this test)
            result = await orchestrator.run(
                engagement_id=engagement.id,
                target="evil.com",
                recon_tools=["subfinder"],
                run_assessment=False,
            )
            assert result.status == "failed"
            assert any("Scope violation" in e for e in result.errors)
        finally:
            del os.environ["TESTING"]

    @pytest.mark.asyncio
    async def test_pipeline_recon_failure_graceful(self, session, user):
        """Pipeline completes gracefully when recon tool fails."""
        os.environ["TESTING"] = "1"
        try:
            project = await _make_project(session, user.id)
            engagement = await _make_engagement(session, project.id)
            await _make_scope_rule(session, engagement.id, "*.example.com")

            from app.services.pipeline import PipelineOrchestrator

            orchestrator = PipelineOrchestrator(db=session, user=user)

            # Mock the worker to simulate tool failure
            with patch.object(orchestrator.worker, 'run_job', new_callable=AsyncMock) as mock_run:
                mock_job = ReconJob(
                    id=str(uuid.uuid4()),
                    engagement_id=engagement.id,
                    user_id=user.id,
                    tool=ReconTool.SUBFINDER,
                    target="example.com",
                    status=ReconJobStatus.FAILED,
                    error_message="Subfinder not found",
                    completed_at=datetime.now(timezone.utc),
                )
                mock_run.return_value = mock_job

                result = await orchestrator.run(
                    engagement_id=engagement.id,
                    target="example.com",
                    recon_tools=["subfinder"],
                    run_assessment=False,
                )

                # Pipeline completed despite recon failure
                assert result.status == "completed"
                assert len(result.recon_jobs) == 1
                assert result.recon_jobs[0].status == ReconJobStatus.FAILED
        finally:
            del os.environ["TESTING"]

    @pytest.mark.asyncio
    async def test_pipeline_no_assets_skips_assessment(self, session, user):
        """Pipeline completes gracefully when 0 assets are found."""
        os.environ["TESTING"] = "1"
        try:
            project = await _make_project(session, user.id)
            engagement = await _make_engagement(session, project.id)
            await _make_scope_rule(session, engagement.id, "*.example.com")

            from app.services.pipeline import PipelineOrchestrator

            orchestrator = PipelineOrchestrator(db=session, user=user)

            with patch.object(orchestrator.worker, 'run_job', new_callable=AsyncMock) as mock_run:
                mock_job = ReconJob(
                    id=str(uuid.uuid4()),
                    engagement_id=engagement.id,
                    user_id=user.id,
                    tool=ReconTool.SUBFINDER,
                    target="example.com",
                    status=ReconJobStatus.COMPLETED,
                    result_summary={"assets_found": 0},
                    completed_at=datetime.now(timezone.utc),
                )
                mock_run.return_value = mock_job

                result = await orchestrator.run(
                    engagement_id=engagement.id,
                    target="example.com",
                    recon_tools=["subfinder"],
                    run_assessment=True,  # Would run nuclei but no assets
                )

                assert result.status == "completed"
                assert result.assets_found == 0
                assert len(result.findings) == 0
        finally:
            del os.environ["TESTING"]

    @pytest.mark.asyncio
    async def test_pipeline_run_assessment_false(self, session, user):
        """Pipeline skips assessment when run_assessment=False."""
        os.environ["TESTING"] = "1"
        try:
            project = await _make_project(session, user.id)
            engagement = await _make_engagement(session, project.id)
            await _make_scope_rule(session, engagement.id, "*.example.com")

            from app.services.pipeline import PipelineOrchestrator

            orchestrator = PipelineOrchestrator(db=session, user=user)

            with patch.object(orchestrator.worker, 'run_job', new_callable=AsyncMock) as mock_run:
                mock_job = ReconJob(
                    id=str(uuid.uuid4()),
                    engagement_id=engagement.id,
                    user_id=user.id,
                    tool=ReconTool.SUBFINDER,
                    target="example.com",
                    status=ReconJobStatus.COMPLETED,
                    result_summary={"assets_found": 3},
                    completed_at=datetime.now(timezone.utc),
                )
                mock_run.return_value = mock_job

                result = await orchestrator.run(
                    engagement_id=engagement.id,
                    target="example.com",
                    recon_tools=["subfinder"],
                    run_assessment=False,
                )

                assert result.status == "completed"
                assert result.scan is None
        finally:
            del os.environ["TESTING"]


# ============================================================
# VULNERABILITY SCAN MODEL TESTS
# ============================================================

class TestVulnScanModel:

    @pytest.mark.asyncio
    async def test_vuln_scan_create(self, session, user):
        project = await _make_project(session, user.id)
        engagement = await _make_engagement(session, project.id)

        scan = VulnerabilityScan(
            id=str(uuid.uuid4()),
            engagement_id=engagement.id,
            user_id=user.id,
            status=VulnScanStatus.PENDING,
            target="example.com",
        )
        session.add(scan)
        await session.commit()

        assert scan.id is not None
        assert scan.status == VulnScanStatus.PENDING

    @pytest.mark.asyncio
    async def test_finding_create(self, session, user):
        project = await _make_project(session, user.id)
        engagement = await _make_engagement(session, project.id)
        asset = await _make_asset(session, engagement.id, "vuln.example.com")

        finding = Finding(
            id=str(uuid.uuid4()),
            engagement_id=engagement.id,
            project_id=project.id,
            asset_id=asset.id,
            user_id=user.id,
            title="Test XSS",
            template_id="xss-detect",
            severity=FindingSeverity.HIGH,
            confidence=85,
            category="xss",
            fingerprint="abc123def456",
            status=FindingStatus.NEW,
            first_seen=datetime.now(timezone.utc),
            last_seen=datetime.now(timezone.utc),
        )
        session.add(finding)
        await session.commit()

        assert finding.id is not None
        assert finding.severity == FindingSeverity.HIGH
        assert finding.asset_id == asset.id
        assert finding.project_id == project.id


# ============================================================
# FINDING-TO-ASSET MAPPING TESTS
# ============================================================

class TestFindingAssetMapping:

    @pytest.mark.asyncio
    async def test_finding_linked_to_correct_asset(self, session, user):
        from app.services.finding_ingester import ingest_nuclei_finding

        project = await _make_project(session, user.id)
        engagement = await _make_engagement(session, project.id)
        asset1 = await _make_asset(session, engagement.id, "web.example.com")
        asset2 = await _make_asset(session, engagement.id, "api.example.com")

        raw = {
            "host": "api.example.com",
            "template_id": "xss-detect",
            "severity": "high",
            "matched-at": "https://api.example.com/search",
            "info": {"name": "XSS in Search"},
        }

        finding = await ingest_nuclei_finding(
            session, engagement.id, project.id, user.id, None, raw
        )

        assert finding.asset_id == asset2.id
        assert finding.asset_id != asset1.id

    @pytest.mark.asyncio
    async def test_finding_without_matching_asset(self, session, user):
        from app.services.finding_ingester import ingest_nuclei_finding

        project = await _make_project(session, user.id)
        engagement = await _make_engagement(session, project.id)

        raw = {
            "host": "unknown.example.com",
            "template_id": "info-disclose",
            "severity": "low",
            "matched-at": "https://unknown.example.com/robots.txt",
            "info": {"name": "Robots.txt Found"},
        }

        finding = await ingest_nuclei_finding(
            session, engagement.id, project.id, user.id, None, raw
        )

        assert finding.asset_id is None  # No matching asset
        assert finding.engagement_id == engagement.id


# ============================================================
# FINDING STATUS LIFECYCLE TESTS
# ============================================================

class TestFindingLifecycle:

    @pytest.mark.asyncio
    async def test_new_finding_default_status(self, session, user):
        from app.services.finding_ingester import ingest_nuclei_finding

        project = await _make_project(session, user.id)
        engagement = await _make_engagement(session, project.id)

        raw = {
            "host": "test.example.com",
            "template_id": "test-template",
            "severity": "medium",
            "matched-at": "https://test.example.com",
            "info": {"name": "Test Finding"},
        }

        finding = await ingest_nuclei_finding(
            session, engagement.id, project.id, user.id, None, raw
        )
        assert finding.status == FindingStatus.NEW

    @pytest.mark.asyncio
    async def test_finding_severity_confidence_mapping(self, session, user):
        from app.services.finding_ingester import ingest_nuclei_finding

        project = await _make_project(session, user.id)
        engagement = await _make_engagement(session, project.id)

        # Critical finding
        raw_critical = {
            "host": "crit.example.com",
            "template_id": "critical-sqli",
            "severity": "critical",
            "matched-at": "https://crit.example.com/login",
            "info": {"name": "SQL Injection"},
        }
        finding = await ingest_nuclei_finding(
            session, engagement.id, project.id, user.id, None, raw_critical
        )
        assert finding.severity == FindingSeverity.CRITICAL
        assert finding.confidence == 95
        assert finding.category == "sqli"

    @pytest.mark.asyncio
    async def test_finding_category_inference(self):
        from app.services.finding_ingester import _category_from_template

        assert _category_from_template("technologies/xss-detect") == "xss"
        assert _category_from_template("vulnerabilities/sqli-error") == "sqli"
        assert _category_from_template("misconfig/cors-misconfig") == "misconfiguration"
        assert _category_from_template("exposed-panels/admin-panel") == "exposure"
        assert _category_from_template("cves/CVE-2021-1234") == "known_vulnerabilities"
        assert _category_from_template("takeover/subdomain-takeover") == "takeover_indicators"
        assert _category_from_template("random-template") == "technology_specific"
