# REDPULSE — Onboarding for Individual User

**Audience:** Solo security researcher / bug-bounty hunter launching REDPULSE for the first time.  
**Time to first scan:** ~5 minutes (with DNS TXT) or ~2 minutes (bounty program sync).  
**Prereqs:** Account on `redpulse-app.vercel.app`, ownership of a target domain **or** a HackerOne/Bugcrowd program with in-scope assets.

> **تجربة أول استخدام (عربي):** أنشئ حساب → أنشئ مشروعاً و Workspace → ثبّت التفويض (سجل TXT أو اربط برنامج bounty) → حدد النطاق (include/exclude) → شغّل أول recon + فحص النواة (Nuclei) → راجع النتائج وقلّص الإيجابيات الكاذبة → أعد الاختبار بعد الإصلاح وصدّر التقرير.

---

## 0. Quick links

- API docs: `GET /docs` (Swagger) / `GET /redoc`
- Legal (must read): `GET /api/v1/legal/terms` · `/privacy` · `/acceptable-use`
- Health (debug): `GET /health` · `GET /health/detailed`
- Pentest report (why we’re safe to launch): `docs/pentest/INTERNAL_PENTEST_REPORT.md`

## 1. Create account & project (60s)

1. `POST /api/v1/auth/signup` → `{email, password>=8}`. You get `access_token` (30m) + `refresh_token` (via `create_access_token`/`create_refresh_token` in `app/core/security.py`).  
2. `POST /api/v1/projects` → `{name: "My First Project"}`. The response includes `project.id` — save it. A default `Workspace` (“Personal”) is auto-created on first project if none exists (`workspace_service.create_workspace`).

**Frontend:** `/signup` → `/dashboard` auto-creates project card. The **OnboardingWizard** (`frontend/components/onboarding/OnboardingWizard.tsx`) shows Step 1 as DONE once `GET /api/v1/projects/` returns `total>=1`.

## 2. Prove authorization for your target (60–120s)

You must verify you own the target before any scan runs (`SECURITY_MODEL.md:1.1`).

**Option A — DNS TXT (most reliable, `app/services/dns_verification.py`):**

1. `POST /api/v1/engagements` → `{project_id, name: "Eng 1"}`
2. `POST /api/v1/engagements/{engagement_id}/authorization/dns-txt` with `{target_domain: "example.com"}` → you get `{verification_token: "redpulse-verify=abc...", instructions}`.
3. Add that TXT at `example.com` in your DNS provider. Wait 30–60s.
4. `POST /api/v1/engagements/{engagement_id}/authorization/verify` → `{verified: true}`. The token is stored in `authorizations.verification_token` and checked via `dns_verification.py`.

**Option B — Bug bounty program sync:**

1. `POST /api/v1/platform-connections` (HackerOne/Bugcrowd OAuth token).
2. `POST /api/v1/engagements/{id}/authorization/bounty-program` with `{bounty_platform: "hackerone", bounty_program_handle: "the-company"}`.
3. The platform pulls `ScopeRule`s with `source: bounty_platform_synced` into your `engagement.scope_rules`.

**Frontend:** Onboarding Step 2 shows “Verify” button; wizard polls `GET /api/v1/engagements/{id}` until `authorization.verified == true` or shows `is_excluded` reason (gov/mil never passes — `global_exclusions.py`).

## 3. Define scope (45s)

- `POST /api/v1/engagements/{id}/scope` with `{pattern: "example.com", rule_type: "include", source: "user_defined"}` — wildcard `*.example.com` supported (`domain_matches` helper).
- Add excludes: `{pattern: "admin.example.com", rule_type: "exclude"}`.
- Verify with `POST /api/v1/vuln/scope-check` `{engagement_id, target}` → `{in_scope: true}`. Every later `POST /recon/jobs` and `POST /projects/{id}/pentest/report` re-validates via `validate_target` as the **last step before execution** — see `SECURITY_MODEL.md:1.11`.

**Tip:** Keep include minimal. The wizard warns if you try to include `*.gov`/`*.edu` — global exclusion wins.

## 4. Run your first scan (60–90s)

### Fast path — controlled pentest report (one call)
```bash
curl -X POST https://your-api/api/v1/projects/$PROJECT_ID/pentest/report \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"engagement_id":"'$ENG_ID'","targets":["https://example.com"],"format":"html"}' | \
  tee report.html
```
Behind the scenes: `validate_target` per target → `VulnScanner.scan_targets` (passive, `SCANNER_TIMEOUT` 60s) → CVSS (`cvss/calculate_cvss_v4`) → PoC (`poc_extractor`) → attack-path chaining → `reporting_engine.build_report` → Telegram ping (optional). No destructive exploit.

### Granular path
- `POST /api/v1/recon/jobs` `{engagement_id, tool: "subfinder", target: "example.com"}` → assets
- `GET /api/v1/recon/assets?engagement_id=...` → review `in_scope` assignment
- `POST /api/v1/vuln/scan?engagement_id=...` with `targets: ["https://sub.example.com"]`
- `POST /api/v1/pipeline/run` `{engagement_id, target: "example.com", recon_tools: ["subfinder"]}` for full pipeline (auto `run_pipeline` with Celery `scans` queue if `async_mode: true`)

The wizard’s Step 4 auto-completes when `GET /api/v1/reports/{project_id}/findings` returns `findings_count>=1` or when `GET /health/queue` shows `celery` healthy.

## 5. Triage false positives (AI feeds forward) (60s)

1. `GET /api/v1/reports/{project_id}/findings?min_severity=high` — sort by `priority` (deterministic `0.4*severity + 0.4*confidence + 0.2*criticality`).
2. For each finding, `GET /api/v1/findings/{id}/triage/suggest` → `{prediction: "false_positive"|"true_positive", confidence, reasoning, fp_rate}`. This uses your workspace’s own `TriageFeedback` history (`FP_RATE_THRESHOLD 0.50`).
3. Submit verdict: `POST /api/v1/findings/{id}/triage` `{"decision":"false_positive","reason":"WAF blocks"}`. The finding’s `status` becomes `false_positive` and the feedback is stored for future suggestions (next time the same `template_id` is seen, AI will suggest FP if historical rate >50%).
4. Dashboard `GET /api/v1/triage/metrics` shows `false_positive_rate` and `top_false_positive_templates`.

> **Why this matters before export:** `finding:export` and `reporting/export` require `review_gate` approval for `HIGH/CRITICAL` — un-reviewed FPs are blocked.

## 6. Fix & retest, then export (60s)

1. Fix the vuln on the target.
2. `POST /api/v1/findings/{id}/retest` (or `/verify-fix` legacy) → `{result: "fixed"|"still_vulnerable", verified_at}`. If `fixed` and `auto_resolved=true`, the finding flips to `RESOLVED` (`FindingStatus.RESOLVED`). This is a **passive** micro-scan (`retest_engine.py: is_passive: true`, single request, 10s timeout).
3. Batch: `POST /api/v1/findings/batch-retest` `{"finding_ids": [...]}`
4. Export: `GET /api/v1/reports/{project_id}/export?format=json&min_severity=high&platform=hackerone` (or `csv`/`html`/`pdf?format=pdf`). Webhook `custom_webhooks` receive `export.created` with `X-RedPulse-Signature`.

**Frontend:** Step 6’s “Export HackerOne JSON” button is enabled only when `GET /api/v1/triage/feedback?project_id=...` has no pending `needs_review` and `GET /retests/stats/summary` shows `fix_rate` — the wizard calls `GET /api/v1/audit-logs/resource/export/{id}` to show audit trail.

---

## First-run checklist (copy to your notes)

- [ ] `POST /auth/signup` → token saved in `localStorage` (httpOnly false, Bearer header)
- [ ] `POST /projects` → save `project_id`
- [ ] `POST /engagements` → save `engagement_id`
- [ ] `POST /engagements/{id}/authorization/dns-txt` + DNS TXT + `POST .../verify` **OR** bounty sync
- [ ] At least one `ScopeRule` include (e.g., `example.com`)
- [ ] `POST /vuln/scope-check` → `in_scope: true`
- [ ] `POST /projects/{id}/pentest/report` → `200` + HTML or `GET /reports/{id}/export?format=json`
- [ ] ≥1 finding triaged (`false_positive`/`true_positive`)
- [ ] Optional retest → `fixed` → report shows `RESOLVED`

Stuck? `GET /health/detailed` tells you if `postgres`/`redis`/`celery` are `healthy` vs `crashed/down`; `GET /health/workers` shows `stale_seconds` and `consecutive_failures`. Backups run daily at `02:00 UTC` (`docker-compose backup` service) — see `scripts/restore.sh`.

## What we removed before launch

See `RELEASE_CHECKLIST.md: Purge Mock Data` — `demo.db`, `openapi.json` mock stubs, and any `fingerprint` demo seeds are scrubbed before `v1.0` tag.

## Feedback

We’re pre-launch — if the wizard fails, `POST /api/v1/audit-logs` is immutable; send us the `finding_id` + `X-Request-Id` header. The self-pentest that cleared launch is in `docs/pentest/INTERNAL_PENTEST_REPORT.md` — no criticals.

