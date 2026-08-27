# RedPulse - Project Rules and Guidelines

## Overview
RedPulse is an authorized security assessment and continuous monitoring platform. All work must enforce scope boundaries and respect authorization limits.

## Architecture Rules

### 1. Phase-Gated Development
- Work strictly through the 14 defined phases (see PHASES.md)
- Do not implement features out of order - each phase builds on the previous
- Phase 1 (skeleton) must be functional before Phase 2 (database) begins

### 2. Scope Enforcement is MANDATORY
- Every scanner job MUST verify targets belong to project authorized scope
- Never trust scanner output blindly - always validate against scope
- The system must refuse to scan out-of-scope targets
- Maintain clear states: in_scope, out_of_scope, pending_review
- Log every scope decision

### 3. Tenant Isolation
- Every tenant-owned database object must be isolated by organization/project ownership
- Row-level security in SQL queries - never trust JOINs without project_id filtering
- Multi-tenancy must work from the beginning - not bolted on later

### 4. Security Boundary Discipline
- Never construct shell commands directly from user input
- Pass arguments as arrays, never use shell=True unless absolutely necessary
- Implement command injection prevention at the subprocess level
- SSRF protections where relevant - never allow arbitrary URL fetching from user input
- Resource limits and timeouts on all external process execution

### 5. Data Model Purity
- Use SQLAlchemy ORM with Pydantic schemas for all data validation
- Never bypass the ORM with raw SQL except for performance-critical migrations
- All findings must have stable fingerprints based on: project + asset + check + endpoint + relevant evidence
- Do not rely only on finding title for deduplication

### 6. AI Boundary Conditions
- AI MUST NOT bypass authorization
- AI MUST NOT perform destructive exploitation
- AI MUST NOT invent evidence
- AI MUST NOT claim a vulnerability is confirmed when evidence does not support it
- AI MUST NOT automatically submit reports without user review
- Every AI-generated statement must be distinguishable from scanner evidence
- AI is optional analysis layer - core security scoring must remain deterministic

### 7. Configuration
- Use .env for all configuration - never hardcode secrets
- Create .env.example with all required variables
- Do not commit .env files
- SUBFINDER_BIN, HTTPX_BIN, NUCLEI_BIN must be configurable with custom paths

### 8. Testing Requirements
- Every major module needs: unit tests, integration tests
- Scope enforcement tests must exist and pass
- Database tests must verify isolation
- Scanner parser tests with mock outputs
- Deduplication tests
- Monitoring/change detection tests
- API tests
- Create mock scanner outputs - DO NOT require real external targets

### 9. Logging Standards
- Structured logging for every major operation
- Include: timestamp, project_id, scan_id, job_id, event, level, error information
- Never log: passwords, API keys, bot tokens, authentication tokens, sensitive secrets

### 10. SaaS Usage Limits
- Free: 1 project, limited assets, limited scans, daily monitoring
- Pro: more projects, more assets, more frequent monitoring, AI analysis, advanced reports, notifications
- Business: teams, higher limits, API, integrations, advanced monitoring
- Do not implement payment processing in first engineering phase

### 11. API Design
- Use REST endpoints as specified in spec
- Use Pydantic request/response schemas
- Version APIs from the start

### 12. Definition of Done
- Each feature must include: implementation, tests, error handling, logging, documentation, configuration, security considerations
- Application must start cleanly
- No broken imports
- No placeholder TODOs for core functionality
- No fake scanner results
- No hardcoded secrets

### 13. Development Strategy
- Follow the 14-phase plan exactly
- Before coding: analyze repo, create AGENTS.md, create architecture docs, create roadmap
- Implement phases sequentially: skeleton â†’ DB â†’ scope â†’ recon â†’ asset â†’ scanner â†’ findings â†’ monitoring â†’ notifications â†’ AI â†’ frontend â†’ auth â†’ testing â†’ Docker
- Do not start implementing until architecture is internally consistent

### 14. Emergencies
If a decision genuinely blocks implementation, ask for confirmation. Otherwise, proceed with the planned architecture.