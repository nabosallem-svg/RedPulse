"""RedPulse - Phase 2: Recon & Asset Inventory Tests.

Tests for:
- Tool adapters (availability, parsing)
- Normalization and deduplication
- Change detection
- Scope enforcement for recon jobs
- Cross-user access isolation
- Edge cases (tool failure, timeout, malformed output)
"""

import pytest
import asyncio
import uuid
from datetime import datetime, timezone
from unittest.mock import AsyncMock, patch, MagicMock
from sqlalchemy import create_engine
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.db.base import Base
from app.db.models import (
    User, Project, Engagement, Authorization, ScopeRule,
    Asset, ReconJob, ReconResult, ReconJobStatus, ReconTool,
    AssetType, RuleType, RuleSource, AuthorizationMethod,
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
async def user_a(session):
    user = User(id=str(uuid.uuid4()), email="alice@test.com", hashed_password=get_password_hash("Pass123!"), is_active=True)
    session.add(user)
    await session.commit()
    return user


@pytest.fixture
async def user_b(session):
    user = User(id=str(uuid.uuid4()), email="bob@test.com", hashed_password=get_password_hash("Pass123!"), is_active=True)
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


def _get_token(user):
    return create_access_token(subject=user.email)


# ============================================================
# TOOL ADAPTER TESTS
# ============================================================

class TestToolAdapters:

    @pytest.mark.asyncio
    async def test_subfinder_adapter_parsing(self):
        from app.services.tools.subfinder import SubfinderAdapter
        adapter = SubfinderAdapter(binary_path="nonexistent")
        # Mock the run method
        adapter._available = True
        with patch.object(adapter, 'run', new_callable=AsyncMock) as mock_run:
            mock_run.return_value = MagicMock(
                success=True,
                raw_output="sub1.example.com\nsub2.example.com\n\nsub3.example.com",
                data=[],
                tool="subfinder",
                version="2.6.0",
                duration_seconds=1.5,
            )
            result = await adapter.discover("example.com")
            assert result.success
            assert len(result.data) == 3
            assert "sub1.example.com" in result.data
            assert "sub3.example.com" in result.data

    @pytest.mark.asyncio
    async def test_httpx_adapter_parsing(self):
        from app.services.tools.httpx_tool import HttpxAdapter
        adapter = HttpxAdapter(binary_path="nonexistent")
        adapter._available = True
        import json
        mock_output = "\n".join([
            json.dumps({"host": "web.example.com", "ip": "1.2.3.4", "port": 443, "scheme": "https", "status_code": 200, "title": "Home", "tech": ["nginx", "PHP"], "webserver": "nginx"}),
            json.dumps({"host": "api.example.com", "ip": "1.2.3.5", "port": 80, "scheme": "http", "status_code": 404, "title": "", "tech": [], "webserver": "Apache"}),
        ])
        with patch.object(adapter, 'run', new_callable=AsyncMock) as mock_run:
            mock_run.return_value = MagicMock(success=True, raw_output=mock_output, data=[], tool="httpx", version="1.3.0", duration_seconds=2.0)
            result = await adapter.discover("example.com")
            assert result.success
            assert len(result.data) == 2
            assert result.data[0]["host"] == "web.example.com"
            assert result.data[0]["technologies"] == ["nginx", "PHP"]
            assert result.data[1]["port"] == 80

    @pytest.mark.asyncio
    async def test_nmap_adapter_parsing(self):
        from app.services.tools.nmap_tool import NmapAdapter
        adapter = NmapAdapter(binary_path="nonexistent")
        mock_xml = """<?xml version="1.0"?>
        <nmaprun><host><address addr="1.2.3.4" addrtype="ipv4"/>
        <hostname name="example.com" type="PTR"/>
        <ports><port protocol="tcp" portid="80"><state state="open"/>
        <service name="http" product="nginx" version="1.18"/></port>
        <port protocol="tcp" portid="443"><state state="open"/>
        <service name="https" product="nginx" version="1.18"/></port></ports></host></nmaprun>"""
        adapter._available = True
        with patch.object(adapter, 'run', new_callable=AsyncMock) as mock_run:
            mock_run.return_value = MagicMock(success=True, raw_output=mock_xml, data=[], tool="nmap", version="7.94", duration_seconds=5.0)
            result = await adapter.discover("1.2.3.4")
            assert result.success
            assert len(result.data) == 2
            assert result.data[0]["port"] == 80
            assert result.data[0]["service"] == "http"
            assert result.data[0]["product"] == "nginx"
            assert result.data[1]["port"] == 443

    @pytest.mark.asyncio
    async def test_tool_unavailable(self):
        from app.services.tools.subfinder import SubfinderAdapter
        adapter = SubfinderAdapter(binary_path="nonexistent_binary_xyz")
        result = await adapter.discover("example.com")
        assert not result.success
        assert "not available" in result.error.lower() or "not found" in result.error.lower()

    @pytest.mark.asyncio
    async def test_tool_timeout(self):
        from app.services.tools.subfinder import SubfinderAdapter
        adapter = SubfinderAdapter(binary_path="nonexistent", timeout=1)
        adapter._available = True
        with patch('asyncio.create_subprocess_exec', new_callable=AsyncMock) as mock_proc:
            mock_proc.return_value.communicate = AsyncMock(side_effect=asyncio.TimeoutError)
            result = await adapter.run(["999"])
            assert not result.success
            assert "timed out" in result.error.lower()


# ============================================================
# NORMALIZER TESTS
# ============================================================

class TestNormalizer:

    @pytest.mark.asyncio
    async def test_upsert_asset_creates_new(self, session, engine):
        from app.services.normalizer import upsert_asset
        project = await _make_project(session, "u1")
        eng = await _make_engagement(session, project.id)
        asset = await upsert_asset(
            session, eng.id, "sub.example.com", AssetType.SUBDOMAIN,
            ReconTool.SUBFINDER,
        )
        assert asset.id is not None
        assert asset.value == "sub.example.com"
        assert asset.first_seen is not None

    @pytest.mark.asyncio
    async def test_upsert_asset_deduplicates(self, session, engine):
        from app.services.normalizer import upsert_asset
        project = await _make_project(session, "u2")
        eng = await _make_engagement(session, project.id)
        a1 = await upsert_asset(session, eng.id, "sub.example.com", AssetType.SUBDOMAIN, ReconTool.SUBFINDER)
        a2 = await upsert_asset(session, eng.id, "sub.example.com", AssetType.SUBDOMAIN, ReconTool.HTTPX)
        assert a1.id == a2.id  # Same asset, updated

    @pytest.mark.asyncio
    async def test_upsert_merges_fields(self, session, engine):
        from app.services.normalizer import upsert_asset
        project = await _make_project(session, "u3")
        eng = await _make_engagement(session, project.id)
        await upsert_asset(session, eng.id, "web.example.com", AssetType.SUBDOMAIN, ReconTool.SUBFINDER)
        a2 = await upsert_asset(
            session, eng.id, "web.example.com", AssetType.SUBDOMAIN, ReconTool.HTTPX,
            port=443, protocol="https", http_status=200, http_title="Home",
        )
        assert a2.port == 443
        assert a2.http_status == 200

    @pytest.mark.asyncio
    async def test_normalize_subfinder(self, session, engine):
        from app.services.normalizer import normalize_subfinder_results
        project = await _make_project(session, "u4")
        eng = await _make_engagement(session, project.id)
        job = ReconJob(id=str(uuid.uuid4()), engagement_id=eng.id, user_id="u4", tool=ReconTool.SUBFINDER, target="example.com", status=ReconJobStatus.PENDING)
        session.add(job)
        await session.commit()

        assets = await normalize_subfinder_results(session, eng.id, job.id, ["a.example.com", "b.example.com"])
        assert len(assets) == 2
        assert assets[0].source_tool == ReconTool.SUBFINDER


# ============================================================
# CHANGE DETECTION TESTS
# ============================================================

class TestChangeDetection:

    @pytest.mark.asyncio
    async def test_new_assets_detected(self, session, engine):
        from app.services.change_detector import detect_changes
        project = await _make_project(session, "u5")
        eng = await _make_engagement(session, project.id)
        changes = await detect_changes(session, eng.id, ["new.example.com", "also-new.example.com"])
        assert len(changes) == 2
        assert all(c.change_type.value == "new" for c in changes)

    @pytest.mark.asyncio
    async def test_no_changes_when_same(self, session, engine):
        from app.services.change_detector import detect_changes
        from app.services.normalizer import upsert_asset
        project = await _make_project(session, "u6")
        eng = await _make_engagement(session, project.id)
        await upsert_asset(session, eng.id, "known.example.com", AssetType.SUBDOMAIN, ReconTool.SUBFINDER)
        changes = await detect_changes(session, eng.id, ["known.example.com"])
        assert len(changes) == 0

    @pytest.mark.asyncio
    async def test_removed_assets_detected(self, session, engine):
        from app.services.change_detector import detect_changes
        from app.services.normalizer import upsert_asset
        project = await _make_project(session, "u7")
        eng = await _make_engagement(session, project.id)
        await upsert_asset(session, eng.id, "old.example.com", AssetType.SUBDOMAIN, ReconTool.SUBFINDER)
        changes = await detect_changes(session, eng.id, [])
        assert len(changes) == 1
        assert changes[0].change_type.value == "removed"


# ============================================================
# SCOPE ENFORCEMENT FOR RECON TESTS
# ============================================================

class TestReconScopeEnforcement:

    @pytest.mark.asyncio
    async def test_scope_violation_blocked(self, session, engine):
        from app.services.scope_validator import validate_target, ScopeViolation
        project = await _make_project(session, "u8")
        eng = await _make_engagement(session, project.id)
        user = await session.get(User, "u8")
        if not user:
            user = User(id="u8", email="scope@test.com", hashed_password=get_password_hash("Pass!"), is_active=True)
            session.add(user)
            await session.commit()

        await _make_auth(session, eng.id, project.id, user.id)
        await _make_scope_rule(session, eng.id, "*.example.com")

        with pytest.raises(ScopeViolation):
            await validate_target(eng.id, "evil.com", session, user)

    @pytest.mark.asyncio
    async def test_gov_target_always_blocked(self, session, engine):
        from app.services.scope_validator import validate_target, ScopeViolation
        project = await _make_project(session, "u9")
        eng = await _make_engagement(session, project.id)
        user = User(id="u9", email="gov@test.com", hashed_password=get_password_hash("Pass!"), is_active=True)
        session.add(user)
        await session.commit()
        await _make_auth(session, eng.id, project.id, user.id)
        await _make_scope_rule(session, eng.id, "*.gov")

        with pytest.raises(ScopeViolation):
            await validate_target(eng.id, "target.gov", session, user)

    @pytest.mark.asyncio
    async def test_scope_allowed_in_scope(self, session, engine):
        from app.services.scope_validator import validate_target
        project = await _make_project(session, "u10")
        eng = await _make_engagement(session, project.id)
        user = User(id="u10", email="ok@test.com", hashed_password=get_password_hash("Pass!"), is_active=True)
        session.add(user)
        await session.commit()
        await _make_auth(session, eng.id, project.id, user.id)
        await _make_scope_rule(session, eng.id, "*.example.com")

        result = await validate_target(eng.id, "sub.example.com", session, user)
        assert result is None  # No exception = allowed


# ============================================================
# CROSS-USER ACCESS TESTS
# ============================================================

class TestReconCrossUserAccess:

    @pytest.mark.asyncio
    async def test_user_b_cannot_see_user_a_jobs(self, session, engine):
        from app.services.normalizer import upsert_asset
        project_a = await _make_project(session, "alice_id")
        eng_a = await _make_engagement(session, project_a.id)
        job = ReconJob(
            id=str(uuid.uuid4()), engagement_id=eng_a.id, user_id="alice_id",
            tool=ReconTool.SUBFINDER, target="example.com", status=ReconJobStatus.COMPLETED,
        )
        session.add(job)
        await session.commit()

        # Verify job exists
        from sqlalchemy import select
        result = await session.execute(select(ReconJob).where(ReconJob.id == job.id))
        assert result.scalar_one_or_none() is not None

        # Verify user_b cannot access via project ownership
        project_b = await _make_project(session, "bob_id")
        result2 = await session.execute(
            select(ReconJob).join(Engagement).join(Project).where(
                ReconJob.engagement_id == eng_a.id,
                Project.owner_id == "bob_id",
            )
        )
        assert result2.scalar_one_or_none() is None


# ============================================================
# TOOL FAILURE TESTS
# ============================================================

class TestToolFailure:

    @pytest.mark.asyncio
    async def test_malformed_xml_nmap(self):
        from app.services.tools.nmap_tool import NmapAdapter
        adapter = NmapAdapter(binary_path="nonexistent")
        adapter._available = True
        with patch.object(adapter, 'run', new_callable=AsyncMock) as mock_run:
            mock_run.return_value = MagicMock(success=True, raw_output="this is not xml", data=[], tool="nmap", version="7.94", duration_seconds=0.1)
            result = await adapter.discover("1.2.3.4")
            assert result.success
            assert result.data == []  # Graceful degradation

    @pytest.mark.asyncio
    async def test_empty_output(self):
        from app.services.tools.subfinder import SubfinderAdapter
        adapter = SubfinderAdapter(binary_path="nonexistent")
        adapter._available = True
        with patch.object(adapter, 'run', new_callable=AsyncMock) as mock_run:
            mock_run.return_value = MagicMock(success=True, raw_output="", data=[], tool="subfinder", version="2.6.0", duration_seconds=0.1)
            result = await adapter.discover("example.com")
            assert result.success
            assert result.data == []
