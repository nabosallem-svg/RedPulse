"""Tests for False Positive Triage Workflow — marks Finding as false_positive with reason and feeds AI."""
import uuid
import pytest
from sqlalchemy import select

from app.db.models import (
    User, Project, Engagement, Finding, FindingStatus, FindingSeverity,
    TriageFeedback, TriageDecision, Workspace,
)
from app.core.security import get_password_hash, create_access_token
from app.services.triage_service import TriageService, TriageAIService
from app.services.workspace_service import WorkspaceService

# ---------- helpers ----------
async def _create_user(session, email, password="TestPass123!"):
    user = User(id=str(uuid.uuid4()), email=email, hashed_password=get_password_hash(password), is_active=True)
    session.add(user)
    await session.commit()
    await session.refresh(user)
    return user

async def _create_workspace(session, owner, name="WS", slug=None):
    slug = slug or f"ws-{uuid.uuid4().hex[:8]}"
    return await WorkspaceService.create_workspace(session, owner, name, slug, "desc")

async def _create_project(session, owner_id, workspace_id=None, name="Proj"):
    proj = Project(id=str(uuid.uuid4()), name=name, description="test", owner_id=owner_id, workspace_id=workspace_id)
    session.add(proj)
    await session.commit()
    await session.refresh(proj)
    return proj

async def _create_engagement(session, project_id, name="Eng"):
    eng = Engagement(id=str(uuid.uuid4()), name=name, project_id=project_id)
    session.add(eng)
    await session.commit()
    await session.refresh(eng)
    return eng

async def _create_finding(session, engagement_id, project_id, user_id, title="XSS reflected", template_id="xss-reflected", category="xss", severity=FindingSeverity.HIGH, confidence=80):
    finding = Finding(
        id=str(uuid.uuid4()), engagement_id=engagement_id, project_id=project_id, user_id=user_id,
        title=title, template_id=template_id, category=category, severity=severity, confidence=confidence,
        fingerprint=str(uuid.uuid4())[:16], status=FindingStatus.NEW, endpoint="https://example.com/search?q=test",
        evidence="vulnerable param q", description="desc"
    )
    session.add(finding)
    await session.commit()
    await session.refresh(finding)
    return finding

def _token(user):
    return create_access_token(subject=user.email)


# ---------- service-level tests ----------
class TestFalsePositiveService:
    @pytest.mark.asyncio
    async def test_mark_false_positive_updates_status_and_stores_reason(self, test_session):
        user = await _create_user(test_session, "fp_serv1@test.com")
        ws = await _create_workspace(test_session, user)
        proj = await _create_project(test_session, user.id, ws.id)
        eng = await _create_engagement(test_session, proj.id)
        finding = await _create_finding(test_session, eng.id, proj.id, user.id)

        fb = await TriageService.submit_triage(test_session, finding.id, user, decision="false_positive", reason="WAF blocks payload", evidence="https://example.com/?q=<script>")

        assert fb.decision == TriageDecision.FALSE_POSITIVE
        assert fb.reason == "WAF blocks payload"
        assert fb.evidence == "https://example.com/?q=<script>"
        assert fb.finding_id == finding.id
        assert fb.analyst_id == user.id
        assert fb.ai_prediction in ("false_positive", "true_positive")
        assert fb.ai_was_correct is not None
        # Finding status mutated
        res = await test_session.execute(select(Finding).where(Finding.id == finding.id))
        updated = res.scalar_one()
        assert updated.status == FindingStatus.FALSE_POSITIVE

    @pytest.mark.asyncio
    async def test_invalid_decision_raises(self, test_session):
        user = await _create_user(test_session, "fp_invalid@test.com")
        ws = await _create_workspace(test_session, user)
        proj = await _create_project(test_session, user.id, ws.id)
        eng = await _create_engagement(test_session, proj.id)
        finding = await _create_finding(test_session, eng.id, proj.id, user.id)
        with pytest.raises(ValueError, match="Invalid decision"):
            await TriageService.submit_triage(test_session, finding.id, user, decision="not_real")

    @pytest.mark.asyncio
    async def test_ai_layer_learns_from_false_positive(self, test_session):
        user = await _create_user(test_session, "fp_ai_learn@test.com")
        ws = await _create_workspace(test_session, user)
        proj = await _create_project(test_session, user.id, ws.id)
        eng = await _create_engagement(test_session, proj.id)
        template = f"fp-learn-{uuid.uuid4().hex[:6]}"
        # No history -> suggestion default true_positive
        f0 = await _create_finding(test_session, eng.id, proj.id, user.id, title="seed", template_id=template)
        sugg_before = await TriageAIService.suggest(test_session, f0)
        # Seed 4 FPs for same template
        for i in range(4):
            f = await _create_finding(test_session, eng.id, proj.id, user.id, title=f"FP{i}", template_id=template)
            await TriageService.submit_triage(test_session, f.id, user, decision="false_positive", reason=f"reason {i}")
        # New finding same template should now be predicted false_positive
        f_new = await _create_finding(test_session, eng.id, proj.id, user.id, title="new", template_id=template)
        sugg_after = await TriageAIService.suggest(test_session, f_new)
        assert sugg_after["prediction"] == "false_positive"
        assert sugg_after["fp_rate"] >= 0.8
        assert sugg_after["sample_count"] >= 4

    @pytest.mark.asyncio
    async def test_history_and_metrics_reflect_false_positives(self, test_session):
        user = await _create_user(test_session, "fp_metrics@test.com")
        ws = await _create_workspace(test_session, user)
        proj = await _create_project(test_session, user.id, ws.id)
        eng = await _create_engagement(test_session, proj.id)
        f1 = await _create_finding(test_session, eng.id, proj.id, user.id, template_id="tpl-metrics-fp")
        f2 = await _create_finding(test_session, eng.id, proj.id, user.id, template_id="tpl-metrics-fp")
        await TriageService.submit_triage(test_session, f1.id, user, decision="false_positive", reason="fp1")
        await TriageService.submit_triage(test_session, f2.id, user, decision="true_positive", reason="real")
        hist = await TriageService.get_finding_history(test_session, f1.id)
        assert len(hist) == 1
        assert hist[0].decision == TriageDecision.FALSE_POSITIVE
        items, total = await TriageService.list_feedback(test_session, project_id=proj.id)
        assert total >= 2
        metrics = await TriageAIService.get_fp_metrics(test_session)
        assert metrics["total_feedbacks"] >= 2
        assert metrics["false_positives"] >= 1
        dataset = await TriageAIService.get_training_dataset(test_session, limit=10)
        assert any(r["decision"] == "false_positive" for r in dataset)


# ---------- API-level tests ----------
class TestFalsePositiveAPI:
    @pytest.mark.asyncio
    async def test_mark_false_positive_endpoint_success(self, client, test_session):
        user = await _create_user(test_session, "fp_api1@test.com")
        ws = await _create_workspace(test_session, user)
        proj = await _create_project(test_session, user.id, ws.id)
        eng = await _create_engagement(test_session, proj.id)
        finding = await _create_finding(test_session, eng.id, proj.id, user.id)
        token = _token(user)

        resp = client.post(f"/api/v1/findings/{finding.id}/false-positive", json={"reason": "WAF triggered, not exploitable", "evidence": "https://example.com/?q=123"}, headers={"Authorization": f"Bearer {token}"})
        assert resp.status_code == 201, resp.text
        data = resp.json()["data"]
        assert data["feedback"]["decision"] == "false_positive"
        assert data["feedback"]["reason"] == "WAF triggered, not exploitable"
        assert data["finding"]["status"] == "false_positive"
        assert "ai_prediction" in data["feedback"]
        # Finding actually updated in DB
        res = await test_session.execute(select(Finding).where(Finding.id == finding.id))
        assert res.scalar_one().status == FindingStatus.FALSE_POSITIVE
        # History contains it
        hist = client.get(f"/api/v1/findings/{finding.id}/triage/history", headers={"Authorization": f"Bearer {token}"})
        assert hist.status_code == 200
        assert len(hist.json()["data"]) == 1

    @pytest.mark.asyncio
    async def test_false_positive_feeds_ai(self, client, test_session):
        user = await _create_user(test_session, "fp_api_ai@test.com")
        ws = await _create_workspace(test_session, user)
        proj = await _create_project(test_session, user.id, ws.id)
        eng = await _create_engagement(test_session, proj.id)
        template = f"tpl-fp-ai-{uuid.uuid4().hex[:6]}"
        # Create and mark 4 FPs to train
        for i in range(4):
            f = await _create_finding(test_session, eng.id, proj.id, user.id, title=f"F{i}", template_id=template)
            tok = _token(user)
            r = client.post(f"/api/v1/findings/{f.id}/false-positive", json={"reason": f"reason {i}"}, headers={"Authorization": f"Bearer {tok}"})
            assert r.status_code == 201
        # New finding same template -> AI should suggest false_positive
        f_new = await _create_finding(test_session, eng.id, proj.id, user.id, title="new", template_id=template)
        token = _token(user)
        sugg = client.get(f"/api/v1/findings/{f_new.id}/triage/suggest", headers={"Authorization": f"Bearer {token}"})
        assert sugg.status_code == 200
        assert sugg.json()["data"]["prediction"] == "false_positive"
        assert sugg.json()["data"]["sample_count"] >= 4

    @pytest.mark.asyncio
    async def test_false_positive_validation_requires_reason(self, client, test_session):
        user = await _create_user(test_session, "fp_api_val@test.com")
        ws = await _create_workspace(test_session, user)
        proj = await _create_project(test_session, user.id, ws.id)
        eng = await _create_engagement(test_session, proj.id)
        finding = await _create_finding(test_session, eng.id, proj.id, user.id)
        token = _token(user)
        # Missing reason -> 422
        resp = client.post(f"/api/v1/findings/{finding.id}/false-positive", json={}, headers={"Authorization": f"Bearer {token}"})
        assert resp.status_code == 422
        # Too short reason (<5) -> 422
        resp2 = client.post(f"/api/v1/findings/{finding.id}/false-positive", json={"reason": "bad"}, headers={"Authorization": f"Bearer {token}"})
        assert resp2.status_code == 422
        # Empty reason
        resp3 = client.post(f"/api/v1/findings/{finding.id}/false-positive", json={"reason": ""}, headers={"Authorization": f"Bearer {token}"})
        assert resp3.status_code == 422

    @pytest.mark.asyncio
    async def test_false_positive_not_found_and_isolation(self, client, test_session):
        owner = await _create_user(test_session, "fp_owner@test.com")
        stranger = await _create_user(test_session, "fp_stranger@test.com")
        ws = await _create_workspace(test_session, owner)
        proj = await _create_project(test_session, owner.id, ws.id)
        eng = await _create_engagement(test_session, proj.id)
        finding = await _create_finding(test_session, eng.id, proj.id, owner.id)
        # 404 for nonexistent
        token_owner = _token(owner)
        resp = client.post(f"/api/v1/findings/{str(uuid.uuid4())}/false-positive", json={"reason": "does not exist"}, headers={"Authorization": f"Bearer {token_owner}"})
        assert resp.status_code == 404
        # Isolation: stranger cannot mark owner's finding
        token_stranger = _token(stranger)
        resp2 = client.post(f"/api/v1/findings/{finding.id}/false-positive", json={"reason": "try hijack"}, headers={"Authorization": f"Bearer {token_stranger}"})
        assert resp2.status_code in (403, 404)
        # No auth -> 401
        resp3 = client.post(f"/api/v1/findings/{finding.id}/false-positive", json={"reason": "no auth"})
        assert resp3.status_code == 401

    @pytest.mark.asyncio
    async def test_false_positive_audit_and_workspace_member(self, client, test_session):
        owner = await _create_user(test_session, "fp_ws_owner@test.com")
        member = await _create_user(test_session, "fp_ws_member@test.com")
        ws = await _create_workspace(test_session, owner)
        from app.db.models import WorkspaceRole
        await WorkspaceService.invite_member(test_session, ws.id, owner.id, member.email, WorkspaceRole.ANALYST)
        proj = await _create_project(test_session, owner.id, ws.id)
        eng = await _create_engagement(test_session, proj.id)
        finding = await _create_finding(test_session, eng.id, proj.id, owner.id)
        token_member = _token(member)
        # Analyst in workspace should be able to mark false_positive via workspace RBAC fallback
        resp = client.post(f"/api/v1/findings/{finding.id}/false-positive", json={"reason": "member triage via workspace"}, headers={"Authorization": f"Bearer {token_member}"})
        assert resp.status_code == 201
        # Metrics should reflect
        resp2 = client.get("/api/v1/triage/metrics", headers={"Authorization": f"Bearer {token_member}"})
        assert resp2.status_code == 200
        assert resp2.json()["data"]["total_feedbacks"] >= 1

    @pytest.mark.asyncio
    async def test_generic_triage_still_works(self, client, test_session):
        user = await _create_user(test_session, "fp_generic@test.com")
        ws = await _create_workspace(test_session, user)
        proj = await _create_project(test_session, user.id, ws.id)
        eng = await _create_engagement(test_session, proj.id)
        finding = await _create_finding(test_session, eng.id, proj.id, user.id)
        token = _token(user)
        # Generic endpoint with decision false_positive should also work and feed AI
        resp = client.post(f"/api/v1/findings/{finding.id}/triage", json={"decision": "false_positive", "reason": "generic path"}, headers={"Authorization": f"Bearer {token}"})
        assert resp.status_code == 201
        assert resp.json()["data"]["decision"] == "false_positive"
        # Verify training dataset contains it
        ds = client.get("/api/v1/triage/training-dataset?limit=5", headers={"Authorization": f"Bearer {token}"})
        assert ds.status_code == 200
        assert any(d["decision"] == "false_positive" for d in ds.json()["data"])
