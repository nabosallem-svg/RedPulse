# ReconPilot - Security Model

## 1. Core Security Principles

### 1.1. Scope as Primary Security Boundary
- **The project scope is the absolute security boundary**
- No scanner job may execute against targets outside the project's authorized scope
- Scope enforcement happens BEFORE scanner execution, not after
- Every scan job must verify target scope membership as the last step

### 1.2. Tenant Isolation
- **Every database object must be isolated by organization/project ownership**
- Row-level security in all queries - never trust JOINs without project_id filtering
- Users can only access projects (and their contents) they own or have been explicitly granted access to
- Organization membership roles enforce: Owner > Admin > Analyst > Viewer

### 1.3. Subprocess Safety
- **Never construct shell commands directly from user input**
- All arguments passed as arrays to `asyncio.create_subprocess_exec()`
- No `shell=True` unless absolutely necessary (and even then, heavily vetted)
- Command injection prevention at the API layer - validate all inputs before passing to subprocesses

### 1.4. SSRF Protections
- Disallow arbitrary URL fetching from user input in web interface
- URL validation: only allow http/https schemes
- No internal/localhost URL access through the platform
- Proxy/redirect chains validated and limited

### 1.5. Secret Management
- **Never log**: passwords, API keys, bot tokens, authentication tokens, sensitive secrets
- Environment variables via .env file (never committed to VCS)
- .env.example provides the template without real values
- AI API keys stored encrypted at rest
- All secrets have rotation policies

### 1.6. Authentication & Authorization
- **Password hashing**: using passlib with strong defaults (bcrypt/argon2)
- **JWT tokens** for session management with short expiry
- Token scopes/claims for authorization decisions
- All API endpoints require valid authentication
- Password minimum length: 8 characters

### 1.7. Finding Security Scoring

#### 1.7.1. Separate Severity, Confidence, Priority
```
severity:   HWG (HIGH, MEDIUM, LOW) - nature of the issue
confidence: 0-100 percentage - evidence quality
priority:   deterministic score - severity + confidence + asset criticality
```

#### 1.7.2. Priority Algorithm (Deterministic)
```
priority = (severity_weight × 0.4) + (confidence × 0.4) + (asset_criticality × 0.2)
where:
- severity_weight: HIGH=100, MEDIUM=50, LOW=25
- confidence: actual percentage (0-100)
- asset_criticality: 0-100 based on asset type/category

Example:
  severity = HIGH (100), confidence = 95, asset_criticality = 70
  priority = (100 × 0.4) + (95 × 0.4) + (70 × 0.2) = 40 + 38 + 14 = 92
```

#### 1.7.3. AI Boundary Conditions
- AI MUST NOT bypass authorization
- AI MUST NOT perform destructive exploitation
- AI MUST NOT invent evidence
- AI MUST NOT claim a vulnerability is confirmed when evidence does not support it
- AI MUST NOT automatically submit reports without user review
- Every AI-generated statement must be distinguishable from scanner evidence
- AI analysis wrapped in `AIAnalysis` schema with `is_ai: true` flag
- Core security scoring remains deterministic - AI provides analysis/recommendations only

### 1.8. Audit Logging
- **Every major operation is audited**
- Includes: timestamp, project_id, scan_id, job_id, event, level, error information
- Never log: passwords, API keys, bot tokens, authentication tokens, sensitive secrets
- Immutable audit trail for compliance and forensic analysis
- Audit log entries cannot be modified after creation

### 1.9. Rate Limiting
- **Scan concurrency limits**: configurable per project (default: 50 concurrent scans)
- **API rate limiting**: per-user or per-organization limits
- **Subprocess rate limiting**: prevent resource exhaustion from too many concurrent scanner processes
- Rate limits enforced at the FastAPI middleware level

### 1.10. Resource Limits
- Maximum scan timeout (default: 300 seconds for full scan, 120 seconds for recon)
- Maximum concurrent processes per worker
- Memory limits on scanner output processing
- CPU time limits for long-running operations

### 1.11. Scope Enforcement Workflow
```
User adds target → Scope normalization → Scope database check → 
Scope status assigned (in_scope/out_of_scope/pending_review) → 
Scanner job verification (LAST step before execution) → 
If out_of_scope: LOG and SKIP → 
If in_scope: Execute scanner → Process findings → Deduplicate
```

### 1.12. Data Sanitization
- All user-supplied data sanitized before database storage
- HTML escaping in API responses
- File name sanitization for any generated reports
- Path traversal prevention in file operations

### 1.13. Input Validation
- All API request bodies validated via Pydantic schemas
- Enum validation for all categorical fields
- Length limits on string fields
- Pattern validation for domains, hostnames, IP addresses
- Regex-based validation for scope values

### 1.14. Error Handling
- Errors logged without exposing sensitive information
- User-friendly error messages (no stack traces in production)
- Graceful degradation - failure of one feature doesn't collapse the whole system
- All errors have error codes for programmatic handling

### 1.15. Configuration Security
- .env file never committed to repository
- .env.example provides required variables without values
- Default values for all optional configs
- Environment-specific configurations (development vs production)
- SECRET_KEY must be set - no defaults allowed

### 1.16. Dependencies Security
- Regular dependency vulnerability scanning (pip-audit, safety)
- Pin dependency versions in requirements.txt
- No unpinned or caret/tilde version ranges in production
- Virtual environment isolation (venv or conda)

### 1.17. Frontend Security
- XSS prevention via proper HTML escaping
- CSRF tokens for state-changing operations
- Content Security Policy (CSP) headers
- No sensitive data embedded in frontend JavaScript
- All API calls go through authenticated endpoints only

### 1.18. Data Retention
- Findings retained according to project settings
- Audit logs retained indefinitely (or per compliance requirements)
- Old assets/archive handled via is_active flag
- Historical change tracking via asset_changes table

### 1.19. Deletion & Data Gravity
- Soft delete pattern for most entities (status flags vs. actual DB deletion)
- Cascade deletes only within project boundary (project-scoped tables)
- No cross-project data exposure during deletion operations
- User data export capability before deletion

### 1.20. Compliance Considerations
- Designed for bug bounty and penetration testing compliance
- Audit trail supports compliance reporting
- Data isolation supports multi-tenant compliance
- No automatic data submission to third parties without explicit user consent