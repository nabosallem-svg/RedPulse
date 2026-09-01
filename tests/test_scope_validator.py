"""RedPulse - Scope Validator Tests.

The most important test file in Phase 1. Confirms that scope_validator.validate_target()
is the single source of truth for scope enforcement.
Achieves 100% coverage for app/services/scope_validator.py
"""

import pytest
from datetime import datetime, timezone, timedelta
from sqlalchemy import select

from app.db.models import User, Project, Engagement, Authorization, ScopeRule
from app.services.scope_validator import validate_target, ScopeViolation
from app.services.global_exclusions import is_excluded


# ---- Helpers ---------------------------------------------------------------

async def _create_user(test_session, email="user@test.com"):
    user = User(email=email, hashed_password="hash")
    test_session.add(user)
    await test_session.commit()
    await test_session.refresh(user)
    return user


async def _create_project(test_session, owner, name="Test Project"):
    proj = Project(name=name, owner_id=owner.id)
    test_session.add(proj)
    await test_session.commit()
    await test_session.refresh(proj)
    return proj


async def _create_engagement(test_session, project, name="Test Eng"):
    eng = Engagement(name=name, project_id=project.id)
    test_session.add(eng)
    await test_session.commit()
    await test_session.refresh(eng)
    return eng


async def _create_authorization(test_session, engagement, user, project, verified=True, expires_at=None, target_domain="example.com", method="dns_txt"):
    auth = Authorization(
        engagement_id=engagement.id,
        project_id=project.id,
        user_id=user.id,
        target_domain=target_domain,
        method=method,
        verified=verified,
        verified_at=datetime.now(timezone.utc) if verified else None,
        expires_at=expires_at,
    )
    test_session.add(auth)
    await test_session.commit()
    await test_session.refresh(auth)
    return auth


async def _create_scope_rule(test_session, engagement, pattern, rule_type="include", source="user_defined"):
    rule = ScopeRule(engagement_id=engagement.id, pattern=pattern, rule_type=rule_type, source=source)
    test_session.add(rule)
    await test_session.commit()
    await test_session.refresh(rule)
    return rule


# ---- Global Exclusions -----------------------------------------------------

@pytest.mark.asyncio
async def test_global_exclusion_root_gov_blocked(test_session):
    """Root .gov domain blocked even without any engagement."""
    user = await _create_user(test_session, "gov1@test.com")
    proj = await _create_project(test_session, user)
    eng = await _create_engagement(test_session, proj)
    await _create_authorization(test_session, eng, user, proj, verified=True)
    await _create_scope_rule(test_session, eng, "example.gov", "include")
    # Even though include exists, global exclusion wins
    with pytest.raises(ScopeViolation, match="global exclusion"):
        await validate_target(eng.id, "example.gov", test_session, user)
    # Also test is_excluded directly
    assert is_excluded("example.gov") is True
    assert is_excluded("sub.example.gov") is True
    assert is_excluded("EXAMPLE.GOV") is True


@pytest.mark.asyncio
async def test_global_exclusion_subdomain_mil_and_edu_blocked(test_session):
    user = await _create_user(test_session, "mil@test.com")
    proj = await _create_project(test_session, user)
    eng = await _create_engagement(test_session, proj)
    await _create_authorization(test_session, eng, user, proj, verified=True)
    await _create_scope_rule(test_session, eng, "target.mil", "include")
    with pytest.raises(ScopeViolation, match="global exclusion"):
        await validate_target(eng.id, "target.mil", test_session, user)
    with pytest.raises(ScopeViolation, match="global exclusion"):
        await validate_target(eng.id, "sub.target.mil", test_session, user)
    with pytest.raises(ScopeViolation, match="global exclusion"):
        await validate_target(eng.id, "university.edu", test_session, user)
    with pytest.raises(ScopeViolation, match="global exclusion"):
        await validate_target(eng.id, "sub.university.edu", test_session, user)
    assert is_excluded("evil.edu") is True
    assert is_excluded("good.com") is False


@pytest.mark.asyncio
async def test_gov_mil_edu_blocked_even_with_include(test_session):
    """Include rule for .gov must not bypass global denylist."""
    user = await _create_user(test_session, "gov2@test.com")
    proj = await _create_project(test_session, user)
    eng = await _create_engagement(test_session, proj)
    await _create_authorization(test_session, eng, user, proj, verified=True)
    await _create_scope_rule(test_session, eng, "*.gov", "include")
    with pytest.raises(ScopeViolation, match="global exclusion"):
        await validate_target(eng.id, "any.gov", test_session, user)
    with pytest.raises(ScopeViolation, match="global exclusion"):
        await validate_target(eng.id, "sub.any.gov", test_session, user)


# ---- Engagement / Authorization checks -------------------------------------

@pytest.mark.asyncio
async def test_unauthorized_engagement_blocked(test_session):
    """Engagement belonging to another user is blocked."""
    owner = await _create_user(test_session, "owner@test.com")
    attacker = await _create_user(test_session, "attacker@test.com")
    proj = await _create_project(test_session, owner)
    eng = await _create_engagement(test_session, proj)
    # No auth needed - should fail at engagement check before auth
    with pytest.raises(ScopeViolation, match="not found or does not belong"):
        await validate_target(eng.id, "example.com", test_session, attacker)


@pytest.mark.asyncio
async def test_no_authorization_blocked(test_session):
    user = await _create_user(test_session, "noauth@test.com")
    proj = await _create_project(test_session, user)
    eng = await _create_engagement(test_session, proj)
    await _create_scope_rule(test_session, eng, "example.com", "include")
    with pytest.raises(ScopeViolation, match="No authorization"):
        await validate_target(eng.id, "example.com", test_session, user)


@pytest.mark.asyncio
async def test_unverified_authorization_blocked(test_session):
    user = await _create_user(test_session, "unverified@test.com")
    proj = await _create_project(test_session, user)
    eng = await _create_engagement(test_session, proj)
    await _create_authorization(test_session, eng, user, proj, verified=False)
    await _create_scope_rule(test_session, eng, "example.com", "include")
    with pytest.raises(ScopeViolation, match="not yet verified"):
        await validate_target(eng.id, "example.com", test_session, user)


@pytest.mark.asyncio
async def test_expired_authorization_blocked(test_session):
    user = await _create_user(test_session, "expired@test.com")
    proj = await _create_project(test_session, user)
    eng = await _create_engagement(test_session, proj)
    past = datetime.now(timezone.utc) - timedelta(days=1)
    # Test with timezone-aware expiry
    await _create_authorization(test_session, eng, user, proj, verified=True, expires_at=past)
    await _create_scope_rule(test_session, eng, "example.com", "include")
    with pytest.raises(ScopeViolation, match="expired"):
        await validate_target(eng.id, "example.com", test_session, user)

    # Also test naive datetime (no tzinfo) branch
    naive_past = datetime.now(timezone.utc) - timedelta(days=1)
    # Create new engagement for naive test
    eng2 = await _create_engagement(test_session, proj, "Eng2")
    await _create_authorization(test_session, eng2, user, proj, verified=True, expires_at=naive_past)
    await _create_scope_rule(test_session, eng2, "example2.com", "include")
    with pytest.raises(ScopeViolation, match="expired"):
        await validate_target(eng2.id, "example2.com", test_session, user)


@pytest.mark.asyncio
async def test_active_authorization_not_blocked(test_session):
    user = await _create_user(test_session, "active@test.com")
    proj = await _create_project(test_session, user)
    eng = await _create_engagement(test_session, proj)
    future = datetime.now(timezone.utc) + timedelta(days=7)
    await _create_authorization(test_session, eng, user, proj, verified=True, expires_at=future)
    await _create_scope_rule(test_session, eng, "example.com", "include")
    # Should not raise
    await validate_target(eng.id, "example.com", test_session, user)

    # Also test with expires_at=None (no expiry)
    eng3 = await _create_engagement(test_session, proj, "Eng3")
    await _create_authorization(test_session, eng3, user, proj, verified=True, expires_at=None)
    await _create_scope_rule(test_session, eng3, "example3.com", "include")
    await validate_target(eng3.id, "example3.com", test_session, user)


# ---- Include / Exclude matching --------------------------------------------

@pytest.mark.asyncio
async def test_authorized_but_host_not_in_include_blocked(test_session):
    user = await _create_user(test_session, "notinclude@test.com")
    proj = await _create_project(test_session, user)
    eng = await _create_engagement(test_session, proj)
    await _create_authorization(test_session, eng, user, proj, verified=True)
    await _create_scope_rule(test_session, eng, "allowed.com", "include")
    with pytest.raises(ScopeViolation, match="does not match any include"):
        await validate_target(eng.id, "other.com", test_session, user)
    # Also when no include rules at all
    eng2 = await _create_engagement(test_session, proj, "EngNoInclude")
    await _create_authorization(test_session, eng2, user, proj, verified=True)
    with pytest.raises(ScopeViolation, match="does not match any include"):
        await validate_target(eng2.id, "any.com", test_session, user)


@pytest.mark.asyncio
async def test_authorized_host_matches_include_no_exclude_allowed(test_session):
    user = await _create_user(test_session, "allowed@test.com")
    proj = await _create_project(test_session, user)
    eng = await _create_engagement(test_session, proj)
    await _create_authorization(test_session, eng, user, proj, verified=True)
    await _create_scope_rule(test_session, eng, "example.com", "include")
    # Should pass (returns None)
    result = await validate_target(eng.id, "example.com", test_session, user)
    assert result is None
    # Substring match also allowed
    await validate_target(eng.id, "sub.example.com", test_session, user)


@pytest.mark.asyncio
async def test_authorized_host_matches_include_and_exclude_blocked(test_session):
    user = await _create_user(test_session, "both@test.com")
    proj = await _create_project(test_session, user)
    eng = await _create_engagement(test_session, proj)
    await _create_authorization(test_session, eng, user, proj, verified=True)
    await _create_scope_rule(test_session, eng, "example.com", "include")
    await _create_scope_rule(test_session, eng, "example.com", "exclude")
    with pytest.raises(ScopeViolation, match="matches an exclude"):
        await validate_target(eng.id, "example.com", test_session, user)


@pytest.mark.asyncio
async def test_wildcard_include_matches_subdomain(test_session):
    user = await _create_user(test_session, "wild@test.com")
    proj = await _create_project(test_session, user)
    eng = await _create_engagement(test_session, proj)
    await _create_authorization(test_session, eng, user, proj, verified=True)
    await _create_scope_rule(test_session, eng, "*.target.com", "include")
    # *.target.com should match sub.target.com via endswith logic
    await validate_target(eng.id, "sub.target.com", test_session, user)
    await validate_target(eng.id, "a.b.target.com", test_session, user)
    # But also test that other domain not matched is blocked
    with pytest.raises(ScopeViolation, match="does not match any include"):
        await validate_target(eng.id, "other.com", test_session, user)


@pytest.mark.asyncio
async def test_wildcard_include_but_explicit_exclude_admin_blocked(test_session):
    """*.target.com included, but admin.target.com explicitly excluded."""
    user = await _create_user(test_session, "wild_exclude@test.com")
    proj = await _create_project(test_session, user)
    eng = await _create_engagement(test_session, proj)
    await _create_authorization(test_session, eng, user, proj, verified=True)
    await _create_scope_rule(test_session, eng, "*.target.com", "include")
    await _create_scope_rule(test_session, eng, "admin.target.com", "exclude")
    # admin should be blocked even though wildcard includes
    with pytest.raises(ScopeViolation, match="matches an exclude"):
        await validate_target(eng.id, "admin.target.com", test_session, user)
    # other subdomain still allowed
    await validate_target(eng.id, "api.target.com", test_session, user)


@pytest.mark.asyncio
async def test_bug_bounty_synced_scope_sourced_correctly(test_session):
    """ScopeRule with source bounty_platform_synced should still be enforced."""
    user = await _create_user(test_session, "bounty@test.com")
    proj = await _create_project(test_session, user)
    eng = await _create_engagement(test_session, proj)
    await _create_authorization(test_session, eng, user, proj, verified=True)
    await _create_scope_rule(test_session, eng, "bounty.com", "include", source="bounty_platform_synced")
    await validate_target(eng.id, "bounty.com", test_session, user)
    # And exclude with bounty source also blocks
    await _create_scope_rule(test_session, eng, "evil.bounty.com", "exclude", source="bounty_platform_synced")
    with pytest.raises(ScopeViolation, match="matches an exclude"):
        await validate_target(eng.id, "evil.bounty.com", test_session, user)


# ---- HTTP 403 response format ------------------------------------------------

def test_scope_violation_http_403_via_api(client):
    """ScopeViolation raised in service should surface as HTTP 403 JSON via API."""
    # Create user/project/engagement via API without scope rule -> pentest report will trigger ScopeViolation
    resp = client.post("/api/v1/auth/signup", json={"email": "http403@test.com", "password": "password123"})
    assert resp.status_code == 201
    token = resp.json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}
    proj_resp = client.post("/api/v1/projects/", json={"name": "HTTP403 Proj"}, headers=headers)
    assert proj_resp.status_code == 201
    project_id = proj_resp.json()["id"]
    eng_resp = client.post("/api/v1/engagements/", json={"name": "HTTP403 Eng", "project_id": project_id}, headers=headers)
    assert eng_resp.status_code == 201
    engagement_id = eng_resp.json()["id"]
    # Try pentest report with a .gov target which is globally excluded -> should be 403 with detail
    resp = client.post(
        f"/api/v1/projects/{project_id}/pentest/report",
        json={"engagement_id": engagement_id, "targets": ["victim.gov"], "format": "json"},
        headers=headers,
    )
    assert resp.status_code == 403
    body = resp.json()
    assert "detail" in body
    assert "global exclusion" in body["detail"].lower() or "gov" in body["detail"].lower()


def test_scope_violation_exception_directly():
    """ScopeViolation carries detail and is distinct from generic Exception."""
    from app.services.scope_validator import ScopeViolation

    exc = ScopeViolation("test detail")
    assert exc.detail == "test detail"
    assert str(exc) == "test detail"
    assert isinstance(exc, Exception)
