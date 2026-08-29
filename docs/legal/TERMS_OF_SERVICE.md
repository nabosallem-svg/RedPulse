# REDPULSE Terms of Service (ToS) — v1.0

**Effective Date:** 2026-05-13  
**Last Updated:** 2026-05-13  
**Provider:** REDPULSE (the “Platform”, “we”, “us”) — Automated security research & continuous monitoring.  
**Contact:** `legal@redpulse.dev` / `abuse@redpulse.dev` (24h)  
**Jurisdiction:** State of Delaware, USA (or your primary contracting entity — replace before public launch). This is a template; have counsel review before production.

> **Arabic Summary (ملخص عربي غير ملزم قانونياً):** هذه اتفاقية استخدام مصرحة فقط — لا يجوز فحص أي هدف بدون تفويض مثبت (DNS TXT أو برنامج Bug Bounty). أنت مسؤول وحدك عن نطاق الفحص، ونحن لا ننفذ أي استغلال تخريبي، والنتائج تمر عبر بوابة مراجعة بشرية قبل التصدير.

---

## 1. Acceptance & Eligibility

1.1 By creating an account, you agree to these Terms, our **Privacy Policy** (`PRIVACY_POLICY.md`) and **Acceptable Use Policy** (`ACCEPTABLE_USE.md`), which are incorporated by reference.  
1.2 You must be ≥18 and have authority to authorize testing of the targets you add. Enterprise accounts require a verified signatory.  
1.3 If you register on behalf of an organization, you bind that organization.

## 2. Authorized-Only Testing (Core Compact)

2.1 **No target may be scanned without a verified Authorization.** Accepted methods (per `app/db/models.py: AuthorizationMethod`):
   - `dns_txt` — you publish a `redpulse-verify=<token>` TXT record on the target apex.
   - `bug_bounty_program` — you connect a HackerOne/Bugcrowd program with in-scope assets synced via `ScopeRule` (`source: bounty_platform_synced`).

2.2 Every `ScanJob`, `Recon` task, and `pentest/report` target is re-validated **last step before execution** via `scope_validator.validate_target` (`app/services/scope_validator.py`). Out-of-scope is **LOG + SKIP**, no execution.

2.3 **Global exclusions are non-overridable:** `*.gov`, `*.mil`, `*.edu`, government TLD variants, loopback/private IP ranges, and `is_excluded` (`app/services/global_exclusions.py`) are always blocked even if added to include rules.

2.4 **You are solely responsible for the scope you declare.** Mis-declared scope that results in unauthorized testing is a material breach; see §10.

## 3. Non-Destructive by Design

3.1 The Platform performs **passive/targeted verification only**: `retest_engine.py` and `VulnScanner` use non-destructive, single-payload micro-scans with timeouts (`SCANNER_TIMEOUT` 60s, `TOOL_TIMEOUT` 300s). No ransomware, no data exfiltration beyond evidence snippet, no persistence.

3.2 You must not configure the Platform to perform destructive exploits via custom templates. Reports that require destructive proof must be proven manually outside the Platform.

3.3 `ScopeViolation` raises **403** (`app/main.py:226`); we never downgrade a scope failure to a warning.

## 4. Accounts, API Keys & Workspaces (RBAC)

4.1 **Workspaces** isolate tenants: every tenant-owned row carries `workspace_id`/`project_id`/`organization_id` and is filtered (see `SECURITY_MODEL.md:1.2`). Roles: Owner > Admin > Analyst > Viewer (`app/db/models.py: WorkspaceRole`).  
4.2 You must protect credentials: passwords are bcrypt-hashed (`app/core/security.py`), JWT RS256/HS256 with 30m expiry (`ACCESS_TOKEN_EXPIRE_MINUTES`), API keys are `rp_` + `sha256` stored as hash (`app/services/api_key_service.py:47`), HMAC webhook secrets `sha256` (`custom_webhook_service.py:42`).  
4.3 **API keys** are shown once. Leaked keys must be rotated (`POST /api/v1/api-keys/{id}/rotate`) immediately; we may revoke keys that appear in public repos.  
4.4 You are responsible for all activity under your keys. Rate limits (`app/core/rate_limit.py:43`, Redis `memory://` fallback) enforce per-key quotas; abuse may trigger temporary `429`.

## 5. Data & Intellectual Property

5.1 **Your data:** You retain ownership of project definitions, scopes, and target lists. You grant us a license to process it to provide the service and to generate anonymized, aggregated security metrics (no target disclosure).  
5.2 **Findings & Reports:** You own pentest reports generated for your authorized targets. `audit_logs` are immutable for compliance and retained per your plan (see Privacy Policy).  
5.3 **Our IP:** The platform, detection rules, CVSS/priority scoring (`SECURITY_MODEL.md:1.7`), and AI analysis `is_ai: true` wrappers remain ours.

## 6. Human Review Gate (Safety Gates)

6.1 High-severity findings (`CRITICAL`/`HIGH` CVSS) must pass `FindingReview`/`ReportReview` (`app/services/review_gate.py`, `app/api/v1/review_gate.py`) — statuses `pending → approved|rejected|changes_requested` — before export to GitHub/Jira (`app/services/integrations.py`) or customer PDF.  
6.2 AI analysis (`is_ai: true`) **never** bypasses authorization, **never** invents evidence, and **never** auto-submits reports without human approval (`SECURITY_MODEL.md:1.7.3`). Audit trail distinguishes scanner evidence vs AI.

## 7. Acceptable Use (summary — see AUP for full)

- No testing of out-of-scope, government, or third-party assets without authorization.
- No use to facilitate or automate unauthorized access, harassment, or disruption.
- No reverse-engineering of detection rules to evade platform protections.
- Respect `User-Agent: RedPulse-Webhooks/1.0` and `X-RedPulse-Signature: sha256=...` for webhook verification.

## 8. Privacy

See `PRIVACY_POLICY.md`. Highlights: we collect `users.email`, `hashed_password`, `projects` metadata, and scan `evidence` snippets (truncated to 200 chars for fingerprint hash). No passwords/API keys in logs. `.env` never committed.

## 9. Warranties, Disclaimers & Liability

9.1 **AS-IS.** The Platform detects known patterns; it does not guarantee absence of vulnerabilities. CVSS/priority scores are deterministic estimates, not warranties.  
9.2 **No consequential damages.** To the maximum extent permitted, we are not liable for loss of bounty, business interruption, or target downtime you cause by mis-scoped testing.  
9.3 **Cap.** Our aggregate liability is capped at the fees you paid in the 3 months preceding the claim (or $100 for free plans).

## 10. Enforcement & Termination

10.1 We may suspend or terminate accounts that: (i) trigger repeated `ScopeViolation` 403s, (ii) exceed global exclusions, (iii) abuse `X-API-Key` scopes, or (iv) trigger `WorkerHealth` crash alerts (`app/services/observability_service.py:14`) attributable to abusive load.  
10.2 You may export your data via `GET /api/v1/reports/{id}/export` (`format: json|csv|html|pdf`) before termination; after 30 days, tenant data is soft-deleted (`is_active`=false) then purged per retention schedule.  
10.3 Reverse-launch cleanup (`demo.db`, `openapi.json` mock scrub) is part of `RELEASE_CHECKLIST.md`.

## 11. Changes & Notice

We will post updated Terms with a new **Effective Date** and, for material changes, email owners 14 days in advance. Continued use after notice constitutes acceptance.

## 12. Governing Law & Disputes

Delaware law, without regard to conflicts; informal resolution via `legal@` for 30 days, then binding arbitration in Wilmington, DE (AAA Commercial Rules), unless we agree to litigate. **Replace this section with your actual counsel’s venue.**

---

**Acknowledgment:** By clicking “I agree” on signup (`frontend/app/signup/page.tsx`) you affirm you have read and understand the authorized-only compact in §2–§3 and that you have authority over every target you will add.

*This template was prepared for REDPULSE pre-launch (Phase 13) and is not a substitute for licensed legal advice. Have outside counsel review before public availability.*

