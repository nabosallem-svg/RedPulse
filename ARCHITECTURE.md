# RedPulse - Architecture Specification

## 1. High-Level Architecture

### 1.1. Overview
RedPulse is a Python FastAPI application with PostgreSQL as the persistence layer. The system follows a modular, phase-gated approach where each phase builds upon the previous one.

### 1.2. Component Diagram
```
+---------------------+       +---------------------+       +---------------------+
|   FastAPI Application|<----->|   PostgreSQL Database|<----->|   External Tools   |
+---------------------+       +---------------------+       +---------------------+
|   API Routes        |       |   SQLAlchemy ORM   |       |   Subfinder        |
|   Auth & Auth       |       |   Models           |       |   HTTPX            |
|   Scope Engine      |       |   Migrations (Alembic)|    |   Nuclei           |
|   Recon Engine      |       |   Sessions         |       +---------------------+
|   Asset Service     |       |   Connection Pool  |
|   Scanner Service   |       |
|   Finding Service   |       |
|   Monitoring Service|       |
|   Notification Svc  |       |
|   AI Analysis Svc   |       |
|   Report Service    |       |
+---------------------+       +---------------------+
           ^                          ^
           |                          |
+---------------------+       +---------------------+
|   Background Workers|       |   File Storage     |
|   (asyncio tasks)   |       |   Reports/Artifacts|
+---------------------+       +---------------------+

+---------------------+
|   Frontend (Next.js)|
+---------------------+
```

## 2. Technology Stack

### 2.1. Backend
- **Python 3.11+**
- **FastAPI** - HTTP framework and API
- **SQLAlchemy** - ORM
- **Alemic** - Database migrations
- **Pydantic** - Data validation (v2)
- **asyncio** - Concurrency and background tasks
- **Uvicorn** - ASGI server

### 2.2. Database
- **PostgreSQL** - Production primary database
- **SQLite** - Allowed for local development/testing only

### 2.3. Background Processing
- **asyncio workers** - Initial MVP approach
- **Redis** - Prepared for dedicated worker processes (not required until Phase 8+)

### 2.4. Frontend
- **Next.js** with TypeScript
- **Tailwind CSS** - Styling
- **Server-Sent Events / WebSockets** - Real-time progress

## 3. Directory Structure

```
RedPulse/
â”œâ”€â”€ AGENTS.md                  # Project rules (this file)
â”œâ”€â”€ ARCHITECTURE.md            # Architecture specification
â”œâ”€â”€ pyproject.toml            # Python project config
â”œâ”€â”€ requirements.txt          # Dependencies
â”œâ”€â”€ .env.example              # Configuration template
â”œâ”€â”€ alembic.ini              # Migration config
â”œâ”€â”€ scripts/                 # Helper scripts
â”‚   â””â”€â”€ init_db.py
â”œâ”€â”€ migrations/              # SQLAlchemy migrations
â”œâ”€â”€ app/
â”‚   â”œâ”€â”€ __init__.py
â”‚   â”œâ”€â”€ main.py               # FastAPI entry point
â”‚   â”œâ”€â”€ config.py             # Configuration loading from .env
â”‚   â”œâ”€â”€ core/                # Core functionality
â”‚   â”‚   â”œâ”€â”€ security.py       # Auth, scope enforcement
â”‚   â”‚   â””â”€â”€ logging.py        # Structured logging
â”‚   â”œâ”€â”€ models/              # SQLAlchemy models
â”‚   â”œâ”€â”€ schemas/             # Pydantic schemas
â”‚   â”œâ”€â”€ api/                 # Route handlers (route modules)
â”‚   â”‚   â”œâ”€â”€ v1/
â”‚   â”‚   â”‚   â”œâ”€â”€ projects.py
â”‚   â”‚   â”‚   â”œâ”€â”€ scopes.py
â”‚   â”‚   â”‚   â”œâ”€â”€ scans.py
â”‚   â”‚   â”‚   â”œâ”€â”€ assets.py
â”‚   â”‚   â”‚   â”œâ”€â”€ findings.py
â”‚   â”‚   â”‚   â”œâ”€â”€ monitoring.py
â”‚   â”‚   â”‚   â”œâ”€â”€ reports.py
â”‚   â”‚   â”‚   â””â”€â”€ notifications.py
â”‚   â”œâ”€â”€ services/            # Business logic services
â”‚   â”‚   â”œâ”€â”€ scope_engine.py
â”‚   â”‚   â”œâ”€â”€ recon_engine.py
â”‚   â”‚   â”œâ”€â”€ asset_service.py
â”‚   â”‚   â”œâ”€â”€ scanner_service.py
â”‚   â”‚   â”œâ”€â”€ finding_service.py
â”‚   â”‚   â”œâ”€â”€ monitoring_service.py
â”‚   â”‚   â”œâ”€â”€ ai_service.py
â”‚   â”‚   â””â”€â”€ report_service.py
â”‚   â””â”€â”€ workers/             # Background task workers
â”‚       â”œâ”€â”€ __init__.py
â”‚       â”œâ”€â”€ recon_worker.py
â”‚       â”œâ”€â”€ monitoring_worker.py
â”‚       â””â”€â”€ notification_worker.py
â””â”€â”€ tests/                   # Test suite
    â”œâ”€â”€ unit/
    â”œâ”€â”€ integration/
    â”œâ”€â”€ conftest.py
    â””â”€â”€ fixtures/
```

## 4. Database Design Philosophy

### 4.1. Tenant Isolation
- **Every table must be filtered by project_id or organization_id**
- Never perform cross-project queries without explicit authorization
- Use SQLAlchemy query scopes or middleware to enforce isolation

### 4.2. Core Tables (planned)
- `users` - User accounts with password hashing
- `organizations` - Organization entities
- `organization_members` - Many-to-many user-organization links with roles
- `projects` - Security assessment projects
- `scopes` - Authorized target scopes per project
- `scans` - Scan jobs
- `scan_jobs` - Individual scan jobs within scans
- `assets` - Discovered assets with full metadata
- `asset_changes` - Historical change tracking
- `findings` - Security findings
- `finding_events` - Finding state change history
- `reports` - Generated reports
- `notifications` - Notification records
- `monitoring_configs` - Continuous monitoring configurations
- `audit_logs` - Audit trail of significant operations

### 4.3. Indexing Strategy
- Index project_id on all tenant-owned tables
- Index on scope-related columns (hostname, scheme, port combinations)
- Index on finding status and severity for dashboard queries
- Index on monitoring configs for change detection

## 5. Worker Architecture

### 5.1. Design Philosophy
- **asyncio-first** - Use asyncio for I/O-bound operations
- **Task queue prepared** - Design for Redis/RQ integration later
- **No threading** - Use asyncio tasks, not OS threads
- **Graceful shutdown** - Handle SIGTERM/SIGINT for cleanup

### 5.2. Worker Types
1. **Recon Worker** - Runs subfinder, httpx, nuclei
2. **Monitoring Worker** - Continuous monitoring cycles
3. **Notification Worker** - Sends Telegram/notifications
4. **Report Worker** - Generates reports

### 5.3. Worker Patterns
- Each worker is an asyncio Task managed in the FastAPI lifespan
- Workers communicate via database state (no in-process shared state needed for MVP)
- Workers use structured logging with context (project_id, scan_id, job_id)
- Workers handle their own process cleanup (subprocess.Popen management)
- Cancellation support via asyncio.Task.cancel()

### 5.4. Subprocess Execution Pattern
```python
import asyncio
import subprocess

async def run_scanner(cmd_args, timeout=300):
    """Run a scanner subprocess with proper error handling."""
    try:
        process = await asyncio.create_subprocess_exec(
            *cmd_args,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        try:
            stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=timeout)
        except asyncio.TimeoutError:
            process.kill()
            await process.wait()
            raise ScannerTimeoutError(f"Scanner timed out after {timeout}s")
        
        if process.returncode != 0:
            raise ScannerError(f"Scanner failed: {stderr.decode()}")
        
        return stdout.decode()
    except Exception:
        # Log and re-raise appropriate error
        raise
```

## 6. Scope Engine Architecture

### 6.1. Scope Normalization
- Input: domain, subdomain, scope file, explicitly authorized targets
- Output: normalized list of in-scope targets
- Validation: DNS resolution check, format validation

### 6.2. Asset States
```
in_scope      â†’ authorized and currently being scanned
out_of_scope  â†’ explicitly out of scope, never to be scanned
pending_review â†’ discovered during scan, needs manual review for scope assignment
```

### 6.3. Scope Enforcement
- Every scanner job checks target against project scope before execution
- Scope check is the LAST step before scanner execution
- If target is out_of_scope â†’ log and skip
- If target is pending_review â†’ log and either include or exclude based on policy

## 7. Recon Engine Architecture

### 7.1. Modular Design
- **Plugins/Adapters** for each external tool
- Interface contract: `run(targets) -> Assets`
- Configuration-driven tool paths (SUBFINDER_BIN, HTTPX_BIN, NUCLEI_BIN)

### 7.2. Initial Tools
1. **Subfinder** - Passive subdomain discovery
2. **HTTPX** - Host probing and HTTP metadata collection

### 7.3. Tool Interface Contract
```python
class ReconTool(Protocol):
    name: str
    binary: str  # config-driven path
    
    async def discover(self, targets: List[str]) -> List[Asset]:
        """Discover assets from targets"""
        ...
    
    async def probe(self, targets: List[str]) -> List[ProbeResult]:
        """Probe targets for HTTP metadata"""
        ...
```

### 7.4. Concurrency Model
- Limited concurrency per tool (configurable, default 50)
- Per-target timeouts
- Stderr capture and structured logging
- Retries where safe (transient errors only)
- Process cleanup on completion or cancellation

## 8. Security Scanner Architecture

### 8.1. Scanner Abstraction
- Base class or protocol for all scanners
- Targeting layer: asset â†’ classify â†’ determine relevant checks â†’ execute targeted scan

### 8.2. Nuclei Integration
- Run nuclei templates against in-scope assets only
- Template categories: exposure, misconfiguration, known vulnerabilities, technology-specific, API-related, takeover indicators
- Configurable scan profiles: Quick, Standard, Deep
- Priority: high-confidence/high-severity checks first

### 8.3. Targeting Layer
```
Asset
  â†’ classify (determine type: HTTP, API, etc.)
  â†’ determine relevant checks (match template tags to asset type/tech)
  â†’ execute targeted scan (run only relevant templates)
```

### 8.4. Scan Profiles
- **Quick**: Minimal templates, fast execution
- **Standard**: Balanced coverage (default)
- **Deep**: All relevant templates, thorough coverage

### 8.5. Finding Generation
- Each nuclei template run produces a finding
- Finding fingerprint based on: project + asset + template_id + endpoint
- Duplicate detection prevents noise
- Confidence and severity assessed per finding

## 9. Finding and Scoring Model

### 9.1. Finding Fields
```
id, project_id, asset_id, title, template_id, category, severity, confidence, priority
endpoint, evidence, description, impact, remediation, fingerprint
first_seen, last_seen, status (new/confirmed/false_positive/accepted/resolved/reopened)
```

### 9.2. Scoring Philosophy
- **severity**: HWG (HIGH, MEDIUM, LOW) based on nature of issue
- **confidence**: Percentage (0-100) based on evidence quality
- **priority**: Deterministic score = f(severity, confidence, asset criticality)
- Do NOT equate scanner severity with actual priority

### 9.3. Priority Algorithm (example)
```
priority = (severity_weight * 0.4) + (confidence * 0.4) + (asset_weight * 0.2)
where:
- severity_weight: HIGH=100, MEDIUM=50, LOW=25
- asset_weight: based on asset type/criticality
```

### 9.4. Finding States
```
new â†’ confirmed â†’ (accepted/resolved) | false_positive
      â†‘              |
      â””â”€â”€ reopened (if reappears)
```

## 10. AI Security Analyst

### 10.1. Role
Optional analysis layer that helps with:
- Explaining findings
- Summarizing evidence
- Identifying related findings
- Suggesting manual verification steps
- Explaining potential impact
- Suggesting remediation
- Generating report drafts
- Reviewing report quality

### 10.2. Hard Boundaries
- AI MUST NOT bypass authorization
- AI MUST NOT perform destructive exploitation
- AI MUST NOT invent evidence
- AI MUST NOT claim vulnerability is confirmed when evidence does not support it
- AI MUST NOT automatically submit reports without user review
- Every AI-generated statement must be distinguishable from scanner evidence

### 10.3. AI Output Marking
- AI responses wrapped in `AIAnalysis` schema with `is_ai: true` flag
- All AI statements presented as analysis/recommendations, not facts
- User can accept or reject each AI suggestion

## 11. Report Generator

### 11.1. Report Structure
```
title, executive_summary, affected_assets, severity, confidence
technical_description, evidence, reproduction_guidance
impact, remediation, timestamps
```

### 11.2. Output Formats
- **HTML** - Professional dashboard-style view
- **JSON** - Machine-readable data
- **PDF** - Planned for future

### 11.3. Report Quality Checker
Automated checks:
- affected asset present
- clear title
- evidence provided
- reproduction guidance
- impact analysis
- remediation steps
- Score out of 100
- Missing/weak sections highlighted

### 11.4. Report Status
- DRAFT until user reviews
- Never automatically submitted to bug bounty platforms without explicit user confirmation
- Official integrations only with user confirmation

## 12. Continuous Monitoring

### 12.1. Monitoring Cycle
After each cycle:
1. Discover assets (recon)
2. Compare with historical state
3. Detect changes
4. Check new/changed assets
5. Process findings
6. Deduplicate
7. Alert important changes

### 12.2. Detectable Changes
- New assets
- Removed assets
- New endpoints
- Technology changes
- New findings
- Reopened findings

### 12.3. Schedules
- Every 6 hours
- Daily
- Weekly

## 13. Notification Architecture

### 13.1. Initial Provider
- **Telegram** - Bot-based notifications

### 13.2. Future Providers
- Discord
- Slack
- Email
- Webhooks

### 13.3. Notification Categories
- NEW_ASSET
- IMPORTANT_CHANGE
- HIGH_FINDING
- CRITICAL_FINDING
- SCAN_FAILED
- SCAN_COMPLETED
- REGRESSION

### 13.4. Notification Rules
- Never expose secrets or sensitive credentials
- Filter by user preferences and organization settings
- Rate-limited to prevent spam

## 14. API Design

### 14.1. Base Pattern
All endpoints follow REST conventions with versioning:
```
/api/v1/projects
/api/v1/projects/{id}/scopes
/api/v1/projects/{id}/scans
/api/v1/projects/{id}/assets
/api/v1/projects/{id}/findings
/api/v1/projects/{id}/reports
/api/v1/projects/{id}/monitoring
/api/v1/projects/{id}/changes
```

### 14.2. Response Format
```json
{
  "success": true,
  "data": { ... },
  "meta": {
    "request_id": "...",
    "timestamp": "..."
  }
}
```

### 14.3. Error Format
```json
{
  "success": false,
  "error": {
    "code": "ERR_CODE",
    "message": "Human-readable message",
    "details": {...}
  }
}
```

## 15. Phased Implementation Roadmap

```
Phase 1: Project skeleton + configuration + logging
Phase 2: Database + models + migrations
Phase 3: Scope engine
Phase 4: Recon engine
Phase 5: Asset intelligence
Phase 6: Nuclei scanner
Phase 7: Findings + deduplication + scoring
Phase 8: Continuous monitoring
Phase 9: Notifications
Phase 10: AI analysis + reporting
Phase 11: Frontend dashboard
Phase 12: Authentication + organizations + SaaS controls
Phase 13: Testing + security hardening
Phase 14: Docker + deployment documentation
```

Each phase has specific entry/exit criteria and must be fully functional before proceeding.