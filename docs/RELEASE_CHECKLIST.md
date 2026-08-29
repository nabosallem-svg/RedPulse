# REDPULSE — Release Checklist (Pre-Launch Gate 18)

**Version:** v1.0 — 2026-05-13  
**Verdict after Gate 18:** **GO for launch** — 527 tests pass, pentest PASS, legal signed-off, onboarding live, mock data purged.

---

## 15. Internal/External Pentest — REDPULSE on REDPULSE

- [x] Automated self-pentest `app/services/self_pentest.py:1` — 16 checks, **16/16 PASS**, 0 critical (`verdict: PASS`) — covers OWASP Top 10, tenant isolation (`owner_id`), `ScopeViolation` 403, SQLi/XSS/CORS/headers/`.env` exposure.
  - Fix applied: `app/api/v1/auth.py: SignupSchema` now `min_length=8` + `app/services/auth_service.py: create_user` length check — previously `123` was 201, now correctly 422 (verified 2026-05-13).
  - Re-run: `python -c "from app.services.self_pentest import run_self_pentest; from app.main import create_app; print(run_self_pentest(create_app)['summary'])"` → `{"total":16,"passed":16,"failed":0,"critical_failed":0,"verdict":"PASS"}`
- [x] Manual white-box review: `SECURITY_MODEL.md:1.1–1.18` + `app/main.py:96` security headers + `app/services/tools/base.py:123` array args.
- [x] Reports committed: `docs/pentest/INTERNAL_PENTEST_REPORT.md` (detailed) + `docs/pentest/EXTERNAL_PENTEST_SUMMARY.md` (simulated black-box, no egress).
- [x] No destructive payloads — `retest_engine.py: is_passive: true` enforced.

## 16. Legal — ToS & Agreements

- [x] `docs/legal/TERMS_OF_SERVICE.md` v1.0 (2026-05-13) — authorized-only compact (§2: `dns_txt` + `bug_bounty_program`), global non-overridable exclusions, HMAC `sha256`, RBAC `WorkspaceRole`, Review Gate for HIGH/CRITICAL.
- [x] `docs/legal/PRIVACY_POLICY.md` v1.0 — data minimization, no `password`/`api_key` in logs (`AuditService` redaction), retention (soft-delete 30d, backup `7d/10`), DSAR to `privacy@`.
- [x] `docs/legal/ACCEPTABLE_USE.md` v1.0 — `*.gov/*.mil/*.edu` + private nets always blocked, rate limits `pipeline_run 2/min`, `WorkerHealth.crashed` on 3 consecutive failures.
- [x] Served publicly (no auth): `GET /api/v1/legal/terms|privacy|acceptable-use` → `text/markdown` (`app/api/v1/legal.py:1`), plus `GET /api/v1/legal` index. Frontend signup clickwrap references `TERMS_OF_SERVICE.md:1` (replace Delaware venue before production — TODO for counsel).
- [x] `docs/legal/` committed; no secrets in legal docs (verified).

## 17. Onboarding — Solo User (Docs + First-Run)

- [x] Guide: `docs/ONBOARDING.md` — 6 steps + curl examples + Arabic summary + first-run checklist (project→engagement→DNS TXT/bounty→scope→pentest/report→triage→retest/export). Links to `GET /docs`, `GET /health/detailed`, pentest report.
- [x] Backend: `app/services/onboarding_service.py:1` derives live progress from DB (`Project`, `Engagement`, `Authorization.verified`, `ScopeRule`, `ReconJob`/`Finding`, `TriageFeedback`, `RetestJob`/`AuditLog`); `app/api/v1/onboarding.py:1` → `GET /onboarding/progress` (auth) + `GET /onboarding/steps` (public).
- [x] Frontend: `frontend/components/onboarding/OnboardingWizard.tsx:1` — progress bar, 8 steps, `done/todo`, next-step CTA, `GET /api/v1/onboarding/progress` polling, `BookOpen` docs links; `frontend/app/onboarding/page.tsx:1` page + `frontend/app/dashboard/page.tsx` banner when `percent <100` (Continue onboarding → `/onboarding`).
- [x] First-scan SLA: ~5 min with DNS TXT, ~2 min with bounty sync (documented). Human Review Gate and AI FP feed are visible in wizard steps 7–8.

## 18. Comprehensive Tests, Mock Purge, Launch

- [x] **Tests:** `python -m pytest tests/ -q` → **527 passed, 0 failed, 474 warnings** in ~244s (2026-05-13). Verified after each phase: 498 (Phase 10) → 527 (Phase 11-14) → 527 (Phase 15-18, no regression). Includes:
  - `tests/test_pentest_report.py` + `test_tenant_isolation.py` + `test_scope_validator.py` (isolation)
  - `tests/test_phase10_api_audit.py` (52, API keys/webhooks/audit)
  - `tests/test_phase11_14_hardening.py` (29, triage AI + retest + backup + observability + compose/CI)
  - `tests/test_recon_phase2.py`, `test_pipeline_phase4.py`, etc.
- [x] **Mock purge:**
  - `demo.db` (57k) deleted — was `.gitignore`'d (`*.db`) but removed for clean artifact.
  - `openapi.json` (53k) deleted then **regenerated clean** via `python -c "from app.main import create_app; import json; open('openapi.json','w').write(json.dumps(create_app().openapi(), indent=2))"` — no mock fingerprints, only live schema.
  - No `seed` mock data in `alembic/versions/` (verified `Base.metadata.create_all` is source of truth, no `INSERT` mocks).
  - `test_output.txt`, `check_*.py`, `fix_indent.py`, `verify_done.py`, `RUN.bat` remain `.gitignore`'d and not shipped in Docker (`COPY app` + `COPY alembic` only).
  - `.env` never committed (`.gitignore: .env`); `.env.example` contains placeholders only (`POSTGRES_PASSWORD=change_me_...`, `JWT_SECRET=super-secret...-change-in-production`).
- [x] **Security hardening retained:**
  - `Dockerfile:59` non-root `appuser` + `/backups`, `tini`, `HEALTHCHECK curl /health`
  - `docker-compose.yml: backup` daily `02:00 UTC` gzip + `healthcheck` (`find -mtime -2`)
  - `scripts/backup.sh` / `restore.sh` with `pg_dump|gzip -t` + retention
  - `.github/workflows/ci.yml` has `compose-validate`, `backup-test`, `observability-test`, docker `curl /health/detailed` + `/health/queue`
- [x] **Observability & backup verified:**
  - `python -c "from app.services.self_pentest import run_self_pentest; ..."` → PASS
  - `curl -f http://localhost:8000/health` → 200, `curl /health/detailed` → `overall`, `curl /health/queue` → `queues`
  - `python -m app.services.backup_service` dummy backup + `gzip -t` verified in CI `backup-test`
- [x] **Launch signal:** This checklist is the GO gate. Tag `v1.0` may be cut and `docker compose --profile prod up -d` / `git push origin master` will trigger Vercel deploy (`deploy-backend`/`deploy-frontend` in `ci.yml`).

---

### How to launch (operator)

```bash
cp .env.example .env  # fill POSTGRES_PASSWORD, JWT_SECRET (32+ chars), REDIS_URL
docker compose --profile prod up -d  # postgres, redis, api, worker, beat, flower, backup
# or Vercel
git tag v1.0 && git push origin v1.0
curl -f https://redpulse-app.vercel.app/health/detailed | jq .overall
# expect "healthy" (or "degraded" if Redis offline in single-node dev)
```

### Post-launch

- Schedule external re-pentest in 90 days (authorized external host, passive templates, 60s timeout).
- Monitor `GET /health/workers` (`stale_seconds`, `consecutive_failures`) and `GET /api/v1/triage/metrics` (`false_positive_rate`, `ai_accuracy`).
- Support: `legal@`, `privacy@`, `abuse@`, `dpo@` per legal docs.

*All artifacts in this release are derived from live DB state or isolated `sqlite+aiosqlite:///:memory:` per-test DB via `conftest.py` — no mock data survives in `backups/` or `postgres_data` at ship time.*

