# REDPULSE Privacy Policy — v1.0

**Effective:** 2026-05-13  
**Controller:** REDPULSE — `privacy@redpulse.dev`  
**DPO:** `dpo@redpulse.dev`  
**Applies to:** Web app (`redpulse-app.vercel.app`), API (`redpulse-api` via `vercel.json`), and workers (`docker-compose.yml` services `api/worker/beat`).

> **ملخص عربي:** نجمع الحد الأدنى فقط (بريدك، كلمة سر مجزأة، مشاريعك وأهدافك المصرحة). لا نسجل كلمات السر أو مفاتيح API في السجلات، ونخزنها مجزأة، ونسمح لك بتصدير/حذف بياناتك.

## 1. Data We Collect

| Category | Example | Source | Purpose |
|----------|---------|--------|---------|
| Account | `users.email`, `hashed_password` (`app/db/models.py: User`), workspace membership | Signup | Auth, RBAC (`WorkspaceRole`) |
| Project & Scope | `projects.name`, `ScopeRule.pattern`, `Authorization.verification_token` (DNS TXT) | You | Scoped scanning (`validate_target`) |
| Operational | `assets.value`, `findings.evidence` (truncated), `recon_results.raw_output` | Scanner | Deduplication via `fingerprint` (`|`.join + `sha256`) |
| Audit & Observability | `audit_logs`, `WorkerHealth` heartbeats, `ApiKey.prefix`/`key_hash` (never plain key) | System | Compliance, queue health (`/health/detailed`) |
| Usage | Rate-limit counters (Redis `memory://` fallback), `X-API-Key` `last_used_at` | System | Abuse prevention |

We **do not** collect government IDs, payment instrument numbers directly (handled by `billing_service.py` via Stripe customer IDs), or destructively exfiltrated target data beyond the evidence snippet needed to reproduce.

## 2. What We Don’t Collect / Log

Per `SECURITY_MODEL.md:1.5` and `app/services/audit_service.py` / `app/core/logging.py`, the following are **never** logged in plaintext: `password`, `api_key`/`secret`, `token`, `JWT_SECRET`, `POSTGRES_PASSWORD`, `TELEGRAM_BOT_TOKEN`. `AuditLog.details` redacts those keys to `***REDACTED***`. Scanner `evidence` is truncated to 200 chars for fingerprinting.

## 3. Legal Basis & Use

- **Contract (Art. 6(1)(b))**: Provide scoped scanning, triage, retest, reporting, webhook delivery.
- **Legitimate interest (6(1)(f))**: Tenant isolation, rate limiting, observability (`/health/queue`), backup/DR (`BackupService`).
- **Consent (6(1)(a))**: Bounty platform OAuth (`PlatformConnection.access_token`) — revoked via disconnect.

We **do not** sell data, and we **do not** train public models on your target lists. `TriageFeedback` and `RetestJob` are tenant-isolated and used only to improve your workspace’s own AI FP suppression (`triage_service.py: FP_RATE_THRESHOLD 0.50`).

## 4. Retention

- **Findings & assets:** Until project deletion + 30-day soft-delete, then purge.
- **Audit logs:** Immutable, retained per plan (default 1 year for Free/Trial, longer for paid — configurable via `BACKUP_RETENTION_DAYS`).
- **Backups:** Gzip `pg_dump` in `backup_data` volume (`docker-compose.yml: backup`), retention `7d` / `10` max, daily `02:00 UTC` cron; restore via `scripts/restore.sh`. Verify via `gzip -t` and `BackupService.verify_backup`.

## 5. Your Rights

Access, correction, export (`GET /api/v1/reports/{id}/export`), and deletion (`DELETE /api/v1/projects/{id}` cascades per `cascade="all, delete-orphan"`). For GDPR/CCPA requests, email `privacy@` with subject `DSR: <email>`; we respond within 30 days. Workspace Owners can remove members (`workspace_service.remove_member` — last admin protection).

## 6. Sub-processors

- **Vercel** (hosting `app`/`frontend`), **Postgres 16** (`postgres` service), **Redis 7** (`redis`), **Celery + Flower** (`worker`/`beat`/`flower`). No third-party AI sub-processor in offline mode; if you enable external AI later, it will be opt-in per workspace.

## 7. Security Measures

- Passwords bcrypt-hashed (`passlib`), JWT HS256 30m (`get_password_hash`, `create_access_token`).
- `HttpOnly` not used (JWT Bearer); `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `Permissions-Policy` headers on every response (`app/main.py:97`).
- Explicit CORS allowlist (no `*`) — `BACKEND_CORS_ORIGINS` plus `default_origins`.
- Subprocess array args, no `shell=True` (`tools/base.py:123`).
- `.env` not in VCS; `.env.example` committed with placeholders.

## 8. International Transfers

Data stays in the region of your `postgres` service (default Vercel region). For EU workspaces, choose EU Postgres; otherwise Standard Contractual Clauses apply.

## 9. Contact & Updates

Same notice mechanism as ToS `§11`. This policy is versioned in `docs/legal/` and served at `GET /api/v1/legal/privacy` and `GET /legal/privacy` (frontend).

*Not legal advice — adapt retention and sub-processor list to your actual hosting choices before launch.*

