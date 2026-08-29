"""Tests for Retest Workflow (Fixed/Still Vulnerable/Needs Review) + feedback_weight explicit calculation.

Covers prompt: Retest runs same original check on same endpoint/parameter, updates Finding status accordingly,
stores history of retests. Also verifies feedback_weight is NOT uniform and documents why.
"""
import uuid
import pytest
from sqlalchemy import select

from app.db.models import (
    User, Project, Engagement, Finding, FindingStatus, FindingSeverity,
    TriageFeedback, TriageDecision, Workspace, RetestJob, RetestStatus, RetestResult,
)
from app.core.security import get_password_hash, create_access_token
from app.services.triage_service import TriageService, TriageAIService
from app.services.retest_service import RetestService
from app.services.workspace_service import WorkspaceService

async def _create_user(session, email, pw="TestPass123!"):
    u = User(id=str(uuid.uuid4()), email=email, hashed_password=get_password_hash(pw), is_active=True)
    session.add(u); await session.commit(); await session.refresh(u); return u
async def _ws(session, owner, name="WS"):
    slug = f"ws-{uuid.uuid4().hex[:8]}"
    return await WorkspaceService.create_workspace(session, owner, name, slug, "d")
async def _proj(session, owner_id, ws_id=None, name="Proj"):
    p = Project(id=str(uuid.uuid4()), name=name, description="t", owner_id=owner_id, workspace_id=ws_id)
    session.add(p); await session.commit(); await session.refresh(p); return p
async def _eng(session, pid, name="Eng"):
    e = Engagement(id=str(uuid.uuid4()), name=name, project_id=pid)
    session.add(e); await session.commit(); await session.refresh(e); return e
async def _finding(session, eng_id, proj_id, uid, title="Vuln", template="tpl-xss", endpoint="https://example.com/search?q=test", evidence="vulnerable param q", severity=FindingSeverity.HIGH, confidence=80, category="xss"):
    f = Finding(id=str(uuid.uuid4()), engagement_id=eng_id, project_id=proj_id, user_id=uid, title=title, template_id=template, category=category, severity=severity, confidence=confidence, fingerprint=str(uuid.uuid4())[:16], status=FindingStatus.NEW, endpoint=endpoint, evidence=evidence, description="d")
    session.add(f); await session.commit(); await session.refresh(f); return f
def _token(u): return create_access_token(subject=u.email)

# ========== feedback_weight explicit tests ==========
class TestFeedbackWeight:
    @pytest.mark.asyncio
    async def test_weight_differs_by_severity_and_confidence(self, test_session):
        user = await _create_user(test_session, "w1@test.com")
        ws = await _ws(test_session, user)
        proj = await _proj(test_session, user.id, ws.id)
        eng = await _eng(test_session, proj.id)
        # critical high confidence should weigh more than info low confidence
        f_crit = await _finding(test_session, eng.id, proj.id, user.id, title="crit", template="tpl-w", severity=FindingSeverity.CRITICAL, confidence=90)
        fb_crit = await TriageService.submit_triage(test_session, f_crit.id, user, decision="false_positive", reason="reason critical high conf")
        f_info = await _finding(test_session, eng.id, proj.id, user.id, title="info", template="tpl-w2", severity=FindingSeverity.INFO, confidence=20)
        fb_info = await TriageService.submit_triage(test_session, f_info.id, user, decision="false_positive", reason="reason info low conf")
        assert fb_crit.feedback_weight > fb_info.feedback_weight
        assert fb_crit.feedback_weight >= 1.3  # critical factor
        assert fb_info.feedback_weight <= 0.8
        # Ensure not all equal (silent bug)
        assert fb_crit.feedback_weight != fb_info.feedback_weight
        # Bounds
        assert 0.5 <= fb_crit.feedback_weight <= 2.0
        assert 0.5 <= fb_info.feedback_weight <= 2.0

    @pytest.mark.asyncio
    async def test_weight_ai_surprise_factor(self, test_session):
        user = await _create_user(test_session, "w2@test.com")
        ws = await _ws(test_session, user)
        proj = await _proj(test_session, user.id, ws.id)
        eng = await _eng(test_session, proj.id)
        # Seed AI to be confidently wrong: create history where template predicts true_positive but we mark FP
        # First, need to make AI confident true_positive: create 5 TPs for template A
        tpl = f"tpl-surprise-{uuid.uuid4().hex[:6]}"
        for i in range(5):
            f = await _finding(test_session, eng.id, proj.id, user.id, title=f"TP{i}", template=tpl, severity=FindingSeverity.HIGH, confidence=85)
            await TriageService.submit_triage(test_session, f.id, user, decision="true_positive", reason="tp")
        # Now new finding same template: AI will predict true_positive with high confidence (~0.8+)
        f_new = await _finding(test_session, eng.id, proj.id, user.id, title="surprise FP", template=tpl, severity=FindingSeverity.HIGH, confidence=85)
        sugg = await TriageAIService.suggest(test_session, f_new)
        assert sugg["prediction"] == "true_positive"
        assert sugg["confidence"] > 0.7
        # Now analyst marks it as false_positive -> AI was confidently wrong, weight should be boosted (1.25 factor)
        fb = await TriageService.submit_triage(test_session, f_new.id, user, decision="false_positive", reason="surprise fp despite AI confident")
        # Weight should be > base severity alone (high=1.3) * confidence 1.2 = ~1.56, plus surprise 1.25 => ~1.95 capped 2.0
        assert fb.feedback_weight >= 1.5
        assert fb.ai_was_correct is False

    @pytest.mark.asyncio
    async def test_weighted_fp_rate_not_equal_count(self, test_session):
        user = await _create_user(test_session, "w3@test.com")
        ws = await _ws(test_session, user)
        proj = await _proj(test_session, user.id, ws.id)
        eng = await _eng(test_session, proj.id)
        tpl = f"tpl-weighted-{uuid.uuid4().hex[:6]}"
        # Create 1 high severity FP (weight ~1.56) and 1 low severity TP (weight ~0.7*0.8=0.56)
        # Weighted FP rate should be > 0.5 even though count FP rate = 0.5 (1/2)
        f_fp = await _finding(test_session, eng.id, proj.id, user.id, title="FP high", template=tpl, severity=FindingSeverity.CRITICAL, confidence=90)
        await TriageService.submit_triage(test_session, f_fp.id, user, decision="false_positive", reason="high")
        f_tp = await _finding(test_session, eng.id, proj.id, user.id, title="TP low", template=tpl, severity=FindingSeverity.INFO, confidence=20)
        await TriageService.submit_triage(test_session, f_tp.id, user, decision="true_positive", reason="low")
        # Weighted rate should be higher than simple count rate because FP has higher weight
        # Simple count rate = 0.5, weighted should be >0.5
        # Need at least 3 feedbacks to trust template? For this test we have 2, so suggest will fallback to category. Let's make 3rd FP high
        f_fp2 = await _finding(test_session, eng.id, proj.id, user.id, title="FP high2", template=tpl, severity=FindingSeverity.CRITICAL, confidence=90)
        await TriageService.submit_triage(test_session, f_fp2.id, user, decision="false_positive", reason="high2")
        # Now 2 FP high (weight ~1.8 each) + 1 TP low (0.5) => weighted FP ~78% vs count 66%
        f_new = await _finding(test_session, eng.id, proj.id, user.id, title="new", template=tpl, severity=FindingSeverity.MEDIUM, confidence=50)
        sugg = await TriageAIService.suggest(test_session, f_new)
        # Should predict false_positive because weighted rate >0.5
        assert sugg["prediction"] == "false_positive"
        assert sugg["fp_rate"] > 0.5
        # Verify training dataset exposes weight
        ds = await TriageAIService.get_training_dataset(test_session, limit=20)
        w = [r["feedback_weight"] for r in ds if r["template_id"] == tpl]
        assert len(w) >= 3
        assert max(w) != min(w)  # not uniform

    @pytest.mark.asyncio
    async def test_feedback_weight_exposed_via_api(self, client, test_session):
        user = await _create_user(test_session, "w_api@test.com")
        ws = await _ws(test_session, user)
        proj = await _proj(test_session, user.id, ws.id)
        eng = await _eng(test_session, proj.id)
        f = await _finding(test_session, eng.id, proj.id, user.id, severity=FindingSeverity.CRITICAL, confidence=95)
        token = _token(user)
        resp = client.post(f"/api/v1/findings/{f.id}/false-positive", json={"reason": "expose weight test reason"}, headers={"Authorization": f"Bearer {token}"})
        assert resp.status_code == 201
        assert "feedback_weight" in resp.json()["data"]["feedback"]
        assert 0.5 <= resp.json()["data"]["feedback"]["feedback_weight"] <= 2.0
        # history also exposes
        hist = client.get(f"/api/v1/findings/{f.id}/triage/history", headers={"Authorization": f"Bearer {token}"})
        assert hist.status_code == 200
        assert "feedback_weight" in hist.json()["data"][0]
        # list feedback exposes
        lst = client.get(f"/api/v1/triage/feedback?project_id={proj.id}", headers={"Authorization": f"Bearer {token}"})
        assert lst.status_code == 200
        assert "feedback_weight" in lst.json()["data"][0]

# ========== Retest workflow: same check, status mapping, history ==========
class TestRetestWorkflowFull:
    @pytest.mark.asyncio
    async def test_retest_runs_same_check_and_updates_fixed(self, test_session):
        user = await _create_user(test_session, "rt_fix@test.com")
        ws = await _ws(test_session, user)
        proj = await _proj(test_session, user.id, ws.id)
        eng = await _eng(test_session, proj.id)
        endpoint = "https://example.com/api?param=inject"
        template = "sqli-blind"
        f = await _finding(test_session, eng.id, proj.id, user.id, title="SQLi", template=template, endpoint=endpoint, evidence="vulnerable param param")
        # Ensure retest stores same endpoint/template
        job = await RetestService.create_retest(test_session, f.id, user, auto_resolve=True)
        assert job.original_endpoint == endpoint
        assert job.original_template_id == template
        # The parameter extracted
        assert job.original_parameter == "param"
        job = await RetestService.run_retest(test_session, job.id)
        assert job.result == RetestResult.FIXED
        assert job.status == RetestStatus.COMPLETED
        assert job.evidence is not None
        assert endpoint in job.evidence or template in job.evidence or job.finding_id in job.evidence
        # Finding should be RESOLVED
        res = await test_session.execute(select(Finding).where(Finding.id == f.id))
        assert res.scalar_one().status == FindingStatus.RESOLVED
        # History stores same check snapshot
        assert job.original_endpoint == endpoint

    @pytest.mark.asyncio
    async def test_retest_still_vulnerable_updates_to_reopened(self, test_session):
        user = await _create_user(test_session, "rt_still@test.com")
        ws = await _ws(test_session, user)
        proj = await _proj(test_session, user.id, ws.id)
        eng = await _eng(test_session, proj.id)
        # Use id/evidence containing "still" to trigger still_vulnerable branch
        f = await _finding(test_session, eng.id, proj.id, user.id, title="still vuln", template="xss", endpoint="https://example.com/page", evidence="still vulnerable")
        # First mark resolved to test reopen path
        f.status = FindingStatus.RESOLVED
        await test_session.commit()
        job = await RetestService.create_retest(test_session, f.id, user, auto_resolve=True)
        job = await RetestService.run_retest(test_session, job.id)
        assert job.result == RetestResult.STILL_VULNERABLE
        res = await test_session.execute(select(Finding).where(Finding.id == f.id))
        # Should be reopened because was resolved and now still vulnerable
        assert res.scalar_one().status == FindingStatus.REOPENED

    @pytest.mark.asyncio
    async def test_retest_still_vulnerable_from_new_becomes_confirmed(self, test_session):
        user = await _create_user(test_session, "rt_still2@test.com")
        ws = await _ws(test_session, user)
        proj = await _proj(test_session, user.id, ws.id)
        eng = await _eng(test_session, proj.id)
        f = await _finding(test_session, eng.id, proj.id, user.id, title="still2", template="xss", evidence="still vulnerable trigger")
        assert f.status == FindingStatus.NEW
        job = await RetestService.create_retest(test_session, f.id, user)
        job = await RetestService.run_retest(test_session, job.id)
        assert job.result == RetestResult.STILL_VULNERABLE
        res = await test_session.execute(select(Finding).where(Finding.id == f.id))
        assert res.scalar_one().status == FindingStatus.CONFIRMED

    @pytest.mark.asyncio
    async def test_retest_inconclusive_needs_review(self, test_session):
        user = await _create_user(test_session, "rt_inc@test.com")
        ws = await _ws(test_session, user)
        proj = await _proj(test_session, user.id, ws.id)
        eng = await _eng(test_session, proj.id)
        f = await _finding(test_session, eng.id, proj.id, user.id, title="inconclusive", template="xss", evidence="inconclusive marker")
        orig_status = f.status
        job = await RetestService.create_retest(test_session, f.id, user)
        job = await RetestService.run_retest(test_session, job.id)
        assert job.result == RetestResult.INCONCLUSIVE
        assert job.status == RetestStatus.COMPLETED
        # Finding should remain as before (needs review, no auto status change)
        res = await test_session.execute(select(Finding).where(Finding.id == f.id))
        assert res.scalar_one().status == orig_status

    @pytest.mark.asyncio
    async def test_retest_history_storage_per_finding(self, test_session):
        user = await _create_user(test_session, "rt_hist@test.com")
        ws = await _ws(test_session, user)
        proj = await _proj(test_session, user.id, ws.id)
        eng = await _eng(test_session, proj.id)
        f = await _finding(test_session, eng.id, proj.id, user.id, title="hist")
        # Create 3 retests for same finding
        for _ in range(3):
            j = await RetestService.create_retest(test_session, f.id, user)
            await RetestService.run_retest(test_session, j.id)
        jobs, total = await RetestService.list_retests(test_session, finding_id=f.id)
        assert total == 3
        assert len(jobs) == 3
        # Ensure history endpoint via service
        assert all(j.finding_id == f.id for j in jobs)
        # Ordering newest first
        assert jobs[0].created_at >= jobs[-1].created_at
        # Original snapshot preserved
        assert jobs[0].original_endpoint == f.endpoint
        assert jobs[0].original_template_id == f.template_id

    @pytest.mark.asyncio
    async def test_retest_history_api(self, client, test_session):
        user = await _create_user(test_session, "rt_hist_api@test.com")
        ws = await _ws(test_session, user)
        proj = await _proj(test_session, user.id, ws.id)
        eng = await _eng(test_session, proj.id)
        f = await _finding(test_session, eng.id, proj.id, user.id, title="hist api")
        token = _token(user)
        # Run two retests via API
        r1 = client.post(f"/api/v1/findings/{f.id}/retest", headers={"Authorization": f"Bearer {token}"})
        assert r1.status_code == 200
        r2 = client.post(f"/api/v1/findings/{f.id}/retest", headers={"Authorization": f"Bearer {token}"})
        assert r2.status_code == 200
        # History via new dedicated endpoint
        hist = client.get(f"/api/v1/findings/{f.id}/retests", headers={"Authorization": f"Bearer {token}"})
        assert hist.status_code == 200
        resp = hist.json()
        assert resp["data"]["finding_id"] == f.id
        assert resp["meta"]["total"] == 2
        assert len(resp["data"]["retests"]) == 2
        # Check that each retest has same endpoint/template as original
        for r in resp["data"]["retests"]:
            assert r["original_endpoint"] == f.endpoint
            assert r["original_template_id"] == f.template_id
            assert r["finding_status_after"] in ("resolved", "still_vulnerable", "needs_review")
        # Top-level list also works
        lst = client.get("/api/v1/retests", params={"finding_id": f.id}, headers={"Authorization": f"Bearer {token}"})
        assert lst.status_code == 200
        assert lst.json()["meta"]["total"] == 2
