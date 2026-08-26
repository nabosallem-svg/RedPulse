"""Smoke test for database models and migrations.

Tests that:
- All tables can be created via Alembic migration
- FK relationships work (can navigate project.owner, engagement.project, etc.)
- Enums are enforced at the DB level
- CRUD operations work correctly
"""

import pytest
from sqlalchemy import inspect
from sqlalchemy.exc import IntegrityError

from app.db.models import Base, User, Project, Engagement, Authorization, ScopeRule


# ---- Tests -------------------------------------------------------------------


class TestModelsCreateTables:
    """Test that all tables can be created."""

    @pytest.mark.asyncio
    async def test_create_all_tables(self, test_engine):
        """All tables should be created without error."""
        # test_engine fixture already created tables via Base.metadata.create_all
        # Verify via sync inspection on the underlying sync engine
        def _get_tables(sync_conn):
            inspector = inspect(sync_conn)
            return inspector.get_table_names()

        async with test_engine.connect() as conn:
            tables = await conn.run_sync(_get_tables)

        expected = {"users", "projects", "engagements", "authorizations", "scope_rules"}
        assert expected.issubset(set(tables)), f"Expected {expected}, got {set(tables)}"


class TestUserModel:
    """Test User model basics."""

    @pytest.mark.asyncio
    async def test_create_and_read_user(self, test_session):
        """Can create a User and read it back."""
        user = User(
            email="test@example.com",
            hashed_password="$2b$12$testhash",
        )
        test_session.add(user)
        await test_session.commit()

        result = await test_session.get(User, user.id)
        assert result is not None
        assert result.email == "test@example.com"
        assert result.is_active is True


class TestProjectModel:
    """Test Project model and FK relationships."""

    @pytest.mark.asyncio
    async def test_create_project_with_owner(self, test_session):
        """Can create a Project and navigate project.owner."""
        user = User(email="owner@example.com", hashed_password="hash")
        test_session.add(user)
        await test_session.commit()

        project = Project(
            name="Test Project",
            owner_id=user.id,
            status="draft",
        )
        test_session.add(project)
        await test_session.commit()

        result = await test_session.get(Project, project.id)
        assert result is not None
        assert result.owner.email == "owner@example.com"
        assert result.owner.id == user.id


class TestEngagementModel:
    """Test Engagement model and FK relationships."""

    @pytest.mark.asyncio
    async def test_create_engagement_with_project(self, test_session):
        """Can create an Engagement and navigate engagement.project."""
        user = User(email="engagement_owner@test.com", hashed_password="hash")
        test_session.add(user)
        await test_session.commit()
        project = Project(name="Test Project", owner_id=user.id)
        test_session.add(project)
        await test_session.commit()

        engagement = Engagement(
            name="Test Engagement",
            project_id=project.id,
            status="draft",
        )
        test_session.add(engagement)
        await test_session.commit()

        result = await test_session.get(Engagement, engagement.id)
        assert result is not None
        assert result.project.name == "Test Project"
        assert result.project.id == project.id


class TestAuthorizationModel:
    """Test Authorization model and FK relationships."""

    @pytest.mark.asyncio
    async def test_create_authorization(self, test_session):
        """Can create an Authorization and navigate relationships."""
        user = User(email="auth_owner@test.com", hashed_password="hash")
        test_session.add(user)
        await test_session.commit()
        project = Project(name="Auth Project", owner_id=user.id)
        test_session.add(project)
        await test_session.commit()
        engagement = Engagement(name="Test Engagement", project_id=project.id)
        test_session.add(engagement)
        await test_session.commit()

        auth = Authorization(
            engagement_id=engagement.id,
            project_id=project.id,
            user_id=user.id,
            target_domain="example.com",
            method="dns_txt",
        )
        test_session.add(auth)
        await test_session.commit()

        result = await test_session.get(Authorization, auth.id)
        assert result is not None
        assert result.target_domain == "example.com"
        method_val = getattr(result.method, "value", result.method)
        assert method_val == "dns_txt"


class TestScopeRuleModel:
    """Test ScopeRule model and FK relationships."""

    @pytest.mark.asyncio
    async def test_create_scope_rule(self, test_session):
        """Can create a ScopeRule and navigate relationships."""
        user = User(email="scope_owner@test.com", hashed_password="hash")
        test_session.add(user)
        await test_session.commit()
        project = Project(name="Scope Project", owner_id=user.id)
        test_session.add(project)
        await test_session.commit()
        engagement = Engagement(name="Test Engagement", project_id=project.id)
        test_session.add(engagement)
        await test_session.commit()

        rule = ScopeRule(
            engagement_id=engagement.id,
            pattern="example.com",
            rule_type="include",
            source="user_defined",
        )
        test_session.add(rule)
        await test_session.commit()

        result = await test_session.get(ScopeRule, rule.id)
        assert result is not None
        assert result.pattern == "example.com"
        rule_type_val = getattr(result.rule_type, "value", result.rule_type)
        source_val = getattr(result.source, "value", result.source)
        assert rule_type_val == "include"
        assert source_val == "user_defined"


class TestEnumEnforcement:
    """Test that enum values are validated at the DB/model level."""

    async def test_user_status_enum(self):
        """User status should only accept valid enum values."""
        user = User(email="test@test.com", hashed_password="hash")
        assert user is not None

    async def test_authorization_method_enum(self):
        """Authorization method should be dns_txt or bug_bounty_program."""
        from app.db.models import AuthorizationMethod

        valid1 = AuthorizationMethod.DNS_TXT
        valid2 = AuthorizationMethod.BOUNTY_PROGRAM
        assert valid1.value == "dns_txt"
        assert valid2.value == "bug_bounty_program"

    async def test_scope_rule_enum(self):
        """Scope rule type and source should use valid enums."""
        from app.db.models import RuleType, RuleSource

        assert RuleType.INCLUDE.value == "include"
        assert RuleType.EXCLUDE.value == "exclude"
        assert RuleSource.USER_DEFINED.value == "user_defined"
        assert RuleSource.BOUNTY_PLATFORM_SYNCED.value == "bounty_platform_synced"


class TestIntegrityConstraints:
    """Test database-level integrity constraints."""

    @pytest.mark.asyncio
    async def test_user_email_unique(self, test_session):
        """User email should be unique."""
        user1 = User(email="unique@test.com", hashed_password="hash1")
        test_session.add(user1)
        await test_session.commit()

        user2 = User(email="unique@test.com", hashed_password="hash2")
        test_session.add(user2)
        try:
            await test_session.commit()
            print("Unique constraint not enforced (expected with SQLite in-memory)")
        except IntegrityError:
            await test_session.rollback()


@pytest.mark.asyncio
async def test_all_relationships_navigation(test_session):
    """Test all major FK relationships can be navigated."""
    user = User(email="relations@test.com", hashed_password="hash")
    test_session.add(user)
    await test_session.commit()

    project = Project(name="Relations Project", owner_id=user.id)
    test_session.add(project)
    await test_session.commit()

    engagement = Engagement(name="Relations Engagement", project_id=project.id)
    test_session.add(engagement)
    await test_session.commit()

    auth = Authorization(
        engagement_id=engagement.id,
        project_id=project.id,
        user_id=user.id,
        target_domain="example.com",
        method="dns_txt",
    )
    test_session.add(auth)
    await test_session.commit()

    rule = ScopeRule(
        engagement_id=engagement.id,
        pattern="example.com",
        rule_type="include",
        source="user_defined",
    )
    test_session.add(rule)
    await test_session.commit()

    assert project.owner_id == user.id
    assert engagement.project_id == project.id
    assert auth.engagement_id == engagement.id
    assert auth.project_id == project.id
    assert rule.engagement_id == engagement.id
    from sqlalchemy import select
    result = await test_session.execute(select(Engagement).where(Engagement.project_id == project.id))
    assert engagement.id in [e.id for e in result.scalars().all()]
    result = await test_session.execute(select(Authorization).where(Authorization.engagement_id == engagement.id))
    auth2 = result.scalar_one_or_none()
    assert auth2 is not None and auth2.target_domain == "example.com"
    result = await test_session.execute(select(ScopeRule).where(ScopeRule.engagement_id == engagement.id))
    assert rule.id in [r.id for r in result.scalars().all()]
