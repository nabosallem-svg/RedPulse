# REDPULSE Acceptable Use Policy (AUP) — v1.0

**Effective:** 2026-05-13  
**Enforced by:** `scope_validator`, `global_exclusions.is_excluded`, `WorkerHealth` + `ObservabilityService`, and human `ReviewGate`.

> **ملخص:** استخدم المنصة فقط لأهداف تملكها أو لديك تفويض كتابي عليها. أي محاولة لفحص `gov/mil/edu`, الشبكات الخاصة، أو تجاوز التفويض ستُحظر تلقائياً وتؤدي للإيقاف.

## 1. You Must

1. **Authorize every target** via `Authorization` (`dns_txt` TXT `redpulse-verify=...` or synced `ScopeRule` from HackerOne/Bugcrowd) before any `ScanJob`/`pentest/report` target is executed. The Platform re-validates every target as the **last step before execution** — see `app/services/scope_validator.py` and `app/api/v1/pentest.py:66`.

2. **Keep scopes tight.** Use `include` rules minimally (`example.com`, `*.example.com` wildcard supported per `domain_matches` tests) and add `exclude` for `admin.example.com` etc.

3. **Respect the Review Gate.** `CRITICAL`/`HIGH` findings require `POST /api/v1/review-gate/.../approve` before `export-ticket`/`bounty_export`/`reporting/export` (`finding:export` scope) — `app/services/review_gate.py`.

4. **Handle secrets safely.** Rotate any `rp_` API key (`app/api/v1/api_keys.py: rotate`) you suspect leaked; verify webhook `X-RedPulse-Signature: sha256=...` (`custom_webhook_service.py:42`).

## 2. You Must Not

- **No unauthorized testing:** Do not add, scan, or pentest targets you do not own or have written permission to test — including `*.gov`, `*.mil`, `*.edu`, government TLDs, and `127.0.0.0/8`, `10/8`, `192.168/16` (blocked by `global_exclusions.py` even if added to includes — `TestGlobalExclusions` enforces).

- **No destructive or disruptive use:** Do not configure `NUCLEI_BIN` templates or `SCANNER_TIMEOUT` to cause DoS, no `shell=True` payloads, no `--exec` patterns. `retest_engine.py` is passive verification only (`is_passive: true`).

- **No harassment/circumvention:** Do not use findings to harass, do not scrape bounty platforms beyond `RateLimiter` (`user_rate_limiter.py` scans/hour 10), do not attempt to bypass tenant isolation (`Project.owner_id` checks) or `require_project_access`.

- **No secret harvesting for abuse:** Do not forward `evidence` containing `javascript_secrets`/`sensitive_secret` triage tags outside a need-to-know workflow (`triage_service.py: TriageTag`).

- **No infrastructure abuse:** Do not hammer `POST /api/v1/pipeline/run` (`RATE_LIMITS["pipeline_run"] 2/min`), `POST /auth/signup` (`3/min`), or Celery `scans` queue beyond `QUEUE_DEPTH_WARN 100` / `CRITICAL 500` (`observability_service.py`). Workers that crash 3× consecutively are marked `crashed`.

## 3. Enforcement Workflow

1. **Automated:** `is_excluded` → immediate block + reason; `ScopeViolation` → HTTP 403; `UserRateLimiter` → `429` with `Retry-After`; `WorkerHealth.consecutive_failures >=3` → status `crashed` visible at `GET /health/queue`.
2. **Human:** Abuse reports to `abuse@` are triaged within 24h. Confirmed AUP violation → warning suspension (72h) → termination. Customers on paid plans may appeal with scope proof (DNS TXT or bounty program screenshot).
3. **Appeal:** Provide `engagement_id` + `verification_token` or `bounty_program_handle` that demonstrates authorization; we re-run `validate_target` and restore if `in_scope`.

## 4. Reporting Abuse

Email `abuse@redpulse.dev` with `project_id` (or `finding_id`/`retest_id`), `evidence` snippet, and `X-Request-Id` if available (from `structured_log`). For law enforcement, include legal process to `legal@`.

## 5. Relation to ToS & Privacy

This AUP is part of the ToS (`TERMS_OF_SERVICE.md §7`). Violating this AUP is a material breach of the ToS and may result in termination per ToS `§10`. Privacy handling of evidence is per `PRIVACY_POLICY.md §2`.

*Pre-launch note: Seed on `main` the `global_exclusions` denylist is authoritative; any customer request to allowlist a `.gov`/`.mil` asset requires manual legal review and direct DB exemption with `is_wildcard: false` + explicit `expires_at` — never via self-serve UI.*

