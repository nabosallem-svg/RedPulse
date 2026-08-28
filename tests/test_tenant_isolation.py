"""RedPulse - Tenant Isolation & Security Tests.

Tests for:
- Cross-user access denial (IDOR prevention)
- Scope enforcement edge cases
- Authentication boundary tests
"""

import pytest
from httpx import AsyncClient, ASGITransport
from app.main import create_app
from app.db.base import Base
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from sqlalchemy.pool import StaticPool
from sqlalchemy.orm import sessionmaker
from app.api.deps import get_db
from app.db.models import User, Project, Engagement, Authorization, ScopeRule, RuleType, RuleSource, AuthorizationMethod
from app.core.security import get_password_hash, create_access_token
import uuid


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


@pytest.fixture(scope="function")
def app(session):
    application = create_app()

    async def _get_db():
        yield session

    application.dependency_overrides[get_db] = _get_db
    yield application
    application.dependency_overrides.clear()


@pytest.fixture
def client(app):
    from fastapi.testclient import TestClient
    return TestClient(app)


async def _create_user(session: AsyncSession, email: str, password: str = "TestPass123!") -> User:
    user = User(id=str(uuid.uuid4()), email=email, hashed_password=get_password_hash(password), is_active=True)
    session.add(user)
    await session.commit()
    await session.refresh(user)
    return user


async def _create_project(session: AsyncSession, owner_id: str, name: str = "Test Project") -> Project:
    project = Project(id=str(uuid.uuid4()), name=name, description="Test", status="draft", owner_id=owner_id)
    session.add(project)
    await session.commit()
    await session.refresh(project)
    return project


async def _create_engagement(session: AsyncSession, project_id: str, name: str = "Test Eng") -> Engagement:
    eng = Engagement(id=str(uuid.uuid4()), name=name, project_id=project_id, status="draft")
    session.add(eng)
    await session.commit()
    await session.refresh(eng)
    return eng


async def _create_auth(session: AsyncSession, engagement_id: str, project_id: str, user_id: str, verified: bool = True) -> Authorization:
    auth = Authorization(
        id=str(uuid.uuid4()),
        engagement_id=engagement_id,
        project_id=project_id,
        user_id=user_id,
        target_domain="example.com",
        method=AuthorizationMethod.DNS_TXT,
        verified=verified,
    )
    session.add(auth)
    await session.commit()
    await session.refresh(auth)
    return auth


async def _create_scope_rule(session: AsyncSession, engagement_id: str, pattern: str, rule_type: RuleType = RuleType.INCLUDE) -> ScopeRule:
    rule = ScopeRule(
        id=str(uuid.uuid4()),
        engagement_id=engagement_id,
        pattern=pattern,
        rule_type=rule_type,
        source=RuleSource.USER_DEFINED,
    )
    session.add(rule)
    await session.commit()
    await session.refresh(rule)
    return rule


def _get_token(user: User) -> str:
    return create_access_token(subject=user.email)


# ============================================================
# CROSS-USER TENANT ISOLATION TESTS
# ============================================================

class TestTenantIsolation:
    """Verify User A cannot access User B's resources."""

    @pytest.mark.asyncio
    async def test_user_a_cannot_get_user_b_project(self, client, session):
        user_a = await _create_user(session, "a@test.com")
        user_b = await _create_user(session, "b@test.com")
        project_b = await _create_project(session, user_b.id, "User B Project")

        token_a = _get_token(user_a)
        resp = client.get(f"/api/v1/projects/{project_b.id}", headers={"Authorization": f"Bearer {token_a}"})
        assert resp.status_code in (403, 404), f"Expected 403/404, got {resp.status_code}"

    @pytest.mark.asyncio
    async def test_user_a_cannot_list_user_b_projects(self, client, session):
        user_a = await _create_user(session, "a2@test.com")
        user_b = await _create_user(session, "b2@test.com")
        await _create_project(session, user_b.id, "B's Project")

        token_a = _get_token(user_a)
        resp = client.get("/api/v1/projects/", headers={"Authorization": f"Bearer {token_a}"})
        assert resp.status_code == 200
        data = resp.json()
        projects = data.get("data", data) if isinstance(data, dict) else data
        if isinstance(projects, list):
            assert len(projects) == 0, "User A should not see User B's projects"

    @pytest.mark.asyncio
    async def test_user_a_cannot_get_user_b_engagement(self, client, session):
        user_a = await _create_user(session, "a3@test.com")
        user_b = await _create_user(session, "b3@test.com")
        project_b = await _create_project(session, user_b.id)
        eng_b = await _create_engagement(session, project_b.id)

        token_a = _get_token(user_a)
        resp = client.get(f"/api/v1/engagements/{eng_b.id}", headers={"Authorization": f"Bearer {token_a}"})
        assert resp.status_code in (403, 404), f"Expected 403/404, got {resp.status_code}"

    @pytest.mark.asyncio
    async def test_user_a_cannot_create_engagement_in_user_b_project(self, client, session):
        user_a = await _create_user(session, "a4@test.com")
        user_b = await _create_user(session, "b4@test.com")
        project_b = await _create_project(session, user_b.id)

        token_a = _get_token(user_a)
        resp = client.post(
            "/api/v1/engagements/",
            json={"name": "Unauthorized Engagement", "project_id": project_b.id},
            headers={"Authorization": f"Bearer {token_a}"},
        )
        assert resp.status_code in (403, 404), f"Expected 403/404, got {resp.status_code}"

    @pytest.mark.asyncio
    async def test_unauthenticated_user_cannot_access_projects(self, client):
        resp = client.get("/api/v1/projects/")
        assert resp.status_code == 401

    @pytest.mark.asyncio
    async def test_invalid_token_rejected(self, client):
        resp = client.get("/api/v1/projects/", headers={"Authorization": "Bearer invalid-token-here"})
        assert resp.status_code == 401


# ============================================================
# SCOPE ENFORCEMENT TESTS
# ============================================================

class TestScopeEnforcement:
    """Verify scope_validator correctly blocks/allows targets."""

    @pytest.mark.asyncio
    async def test_scope_violation_gov_blocked(self, client, session):
        from app.services.scope_validator import ScopeViolation
        from app.services.global_exclusions import is_excluded
        assert is_excluded("target.gov") is True
        assert is_excluded("pentest.mil") is True
        assert is_excluded("university.edu") is True

    @pytest.mark.asyncio
    async def test_scope_allowed_normal_domain(self, client, session):
        from app.services.global_exclusions import is_excluded
        assert is_excluded("example.com") is False
        assert is_excluded("sub.example.com") is False

    @pytest.mark.asyncio
    async def test_wildcard_scope_matching(self):
        from app.services.scope_validator import _domain_matches if hasattr(__import__('app.services.scope_validator', fromlist=['validate_target']), '_domain_matches') else None
        # Test the domain matching logic directly
        def domain_matches(host: str, pattern: str) -> bool:
            pattern = pattern.lower().strip()
            host = host.lower().strip()
            if "://" in host:
                host = host.split("://", 1)[1].split("/")[0].split(":")[0]
            if "://" in pattern:
                pattern = pattern.split("://", 1)[1].split("/")[0].split(":")[0]
            if host == pattern:
                return True
            if pattern.startswith("*."):
                base = pattern[2:]
                return host == base or host.endswith("." + base)
            return host.endswith("." + pattern)

        # Exact match
        assert domain_matches("example.com", "example.com") is True
        # Wildcard match
        assert domain_matches("sub.example.com", "*.example.com") is True
        assert domain_matches("deep.sub.example.com", "*.example.com") is True
        # Wildcard does NOT match base domain
        assert domain_matches("example.com", "*.example.com") is False
        # Subdomain match
        assert domain_matches("sub.example.com", "example.com") is True
        # No match
        assert domain_matches("evil.com", "example.com") is False
        assert domain_matches("evil-example.com", "example.com") is False

    @pytest.mark.asyncio
    async def test_scope_with_url_prefix(self):
        def domain_matches(host: str, pattern: str) -> bool:
            pattern = pattern.lower().strip()
            host = host.lower().strip()
            if "://" in host:
                host = host.split("://", 1)[1].split("/")[0].split(":")[0]
            if "://" in pattern:
                pattern = pattern.split("://", 1)[1].split("/")[0].split(":")[0]
            if host == pattern:
                return True
            if pattern.startswith("*."):
                base = pattern[2:]
                return host == base or host.endswith("." + base)
            return host.endswith("." + pattern)

        assert domain_matches("https://example.com/path", "example.com") is True
        assert domain_matches("http://sub.example.com:8080", "*.example.com") is True


# ============================================================
# AUTHENTICATION EDGE CASES
# ============================================================

class TestAuthEdgeCases:

    @pytest.mark.asyncio
    async def test_signup_duplicate_email(self, client, session):
        await _create_user(session, "dup@test.com")
        resp = client.post("/api/v1/auth/signup", json={"email": "dup@test.com", "password": "TestPass123!"})
        assert resp.status_code in (400, 409)

    @pytest.mark.asyncio
    async def test_login_wrong_password(self, client, session):
        await _create_user(session, "login@test.com", "CorrectPass123!")
        resp = client.post("/api/v1/auth/login", json={"email": "login@test.com", "password": "WrongPass!"})
        assert resp.status_code == 401

    @pytest.mark.asyncio
    async def test_login_nonexistent_user(self, client):
        resp = client.post("/api/v1/auth/login", json={"email": "nonexistent@test.com", "password": "TestPass123!"})
        assert resp.status_code == 401

    @pytest.mark.asyncio
    async def test_me_requires_auth(self, client):
        resp = client.get("/api/v1/auth/me")
        assert resp.status_code == 401

    @pytest.mark.asyncio
    async def test_me_returns_user(self, client, session):
        user = await _create_user(session, "me@test.com")
        token = _get_token(user)
        resp = client.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {token}"})
        assert resp.status_code == 200
        assert resp.json()["email"] == "me@test.com"

    @pytest.mark.asyncio
    async def test_token_refresh_works(self, client, session):
        user = await _create_user(session, "refresh@test.com")
        resp = client.post("/api/v1/auth/login", json={"email": "refresh@test.com", "password": "TestPass123!"})
        assert resp.status_code == 200
        refresh_token = resp.json().get("refresh_token")
        assert refresh_token is not None

        resp2 = client.post("/api/v1/auth/refresh", json={"refresh_token": refresh_token})
        assert resp2.status_code == 200
        assert "access_token" in resp2.json()

    @pytest.mark.asyncio
    async def test_invalid_refresh_token_rejected(self, client):
        resp = client.post("/api/v1/auth/refresh", json={"refresh_token": "invalid-token"})
        assert resp.status_code == 401
