# ReconPilot - Technical Risks and Dependencies

## 1. Technical Risks

### 1.1. External Tool Dependencies
- **Risk**: Subfinder, httpx, nuclei must be installed and available
- **Mitigation**: Configurable binary paths via SUBFINDER_BIN, HTTPX_BIN, NUCLEI_BIN env vars
- **Contingency**: Fallback to library implementations if binaries unavailable
- **Status**: HIGH risk - core functionality depends on external tools

### 1.2. Scope Enforcement Bypass
- **Risk**: Misconfigured scope could allow scanning of out-of-scope targets
- **Mitigation**: Defense-in-depth - scope check at multiple levels (DB, before subprocess, after results)
- **Contingency**: All scanner output validated against scope; out-of-scope results discarded
- **Status**: CRITICAL - scope is the primary security boundary

### 1.3. Subprocess Injection
- **Risk**: Command injection through improperly validated target inputs
- **Mitigation**: Never use shell=True; validate all inputs as domains/hostnames; regex allowlists
- **Contingency**: Input validation layer that rejects anything not matching domain/subdomain pattern
- **Status**: CRITICAL - could lead to full system compromise

### 1.4. False Positive Flood
- **Risk**: Nuclei templates producing many false positives, overwhelming users
- **Mitigation**: Configurable scan profiles (Quick/Standard/Deep), confidence-based filtering, deduplication
- **Contingency**: AI analysis to help filter/cluster findings; user can mark false positives
- **Status**: HIGH - impacts usability and trust

### 1.5. PostgreSQL Scalability
- **Risk**: Large number of assets/findings could impact query performance
- **Mitigation**: Proper indexing strategy (all tenant-owned tables indexed by project_id), connection pooling
- **Contingency**: Read replicas for dashboard queries; query optimization; partitioning by project
- **Status**: MEDIUM - manageable with proper indexing

### 1.6. Concurrent Worker Failures
- **Risk**: Worker crashes leaving orphaned jobs or inconsistent state
- **Mitigation**: Database-coordinated pattern with FOR UPDATE SKIP LOCKED, heartbeat/lease mechanism
- **Contingency**: Graceful shutdown handling, stale job reclamation after timeout
- **Status**: MEDIUM - handled by database transactions

### 1.7. AI Security Boundary Violation
- **Risk**: AI model could generate unsafe or unauthorized content
- **Mitigation**: Hard-coded boundary conditions; every AI statement marked as AI-generated; user must review
- **Contingency**: AI output filtered through security reviewer; option to disable AI layer
- **Status**: HIGH - reputational and security risk

### 1.8. Telegram Notification Exposure
- **Risk**: Notification system could expose sensitive data via Telegram
- **Mitigation**: Never include secrets in notification messages; filter category-appropriate data
- **Contingency**: Manual review of notification content before sending; option to disable notifications
- **Status**: MEDIUM - manageable with content filtering

### 1.9. Database Migration Errors
- **Risk**: Alembic migrations could break production data
- **Mitigation**: Test migrations in development; backup before production deployment; migration test suite
- **Contingency**: Rollback scripts for each migration; gradual rollout
- **Status**: HIGH - data loss risk if migrations fail

### 1.10. Real Target Exposure in Tests
- **Risk**: Automated tests using real targets could scan unauthorized systems
- **Mitigation**: Mock all scanner outputs; no real targets required for tests; use test fixtures only
- **Contingency**: Test environment with isolated test database and project
- **Status**: HIGH - could cause legal issues if unauthorized scanning occurs

## 2. Dependencies

### 2.1. Hard Dependencies (Required for MVP)
| Dependency | Version | Purpose |
|------------|---------|---------|
| Python | 3.11+ | Runtime |
| FastAPI | 0.104+ | Web framework |
| SQLAlchemy | 2.0+ | ORM |
| Alembic | 1.12+ | Database migrations |
| Pydantic | 2.7+ | Data validation |
| PostgreSQL | 13+ | Production database |
| Uvicorn | 0.29+ | ASGI server |

### 2.2. Optional Dependencies (MVP-Ready)
| Dependency | Version | Purpose |
|------------|---------|---------|
| passlib | 1.7+ | Password hashing |
| jose (python-jose) | 3.3+ | JWT token handling |
| pydantic-settings | 2.1+ | Configuration management |
| python-dotenv | 1.0+ | .env file loading |

### 2.3. External Tool Dependencies (Optional - Configurable)
| Tool | Env Var | Purpose |
|------|---------|---------|
| subfinder | SUBFINDER_BIN | Subdomain discovery |
| httpx | HTTPX_BIN | Host probing & HTTP metadata |
| nuclei | NUCLEI_BIN | Vulnerability scanner templates |

### 2.4. Development Dependencies
| Dependency | Version | Purpose |
|------------|---------|---------|
| pytest | 8.0+ | Testing |
| httpx[async] | 0.27+ | API testing client |
| respx | 0.18+ | Mock HTTP server for tests |
| alembic-cli | 1.12+ | Migration commands |
| black | 23.0+ | Code formatting |
| ruff | 0.1.0+ | Linting |

### 2.5. Infrastructure Dependencies (Phase 8+)
| Dependency | Version | Purpose |
|------------|---------|---------|
| Redis | 7+ | Worker coordination (Phase 8+) |
| prometheus_client | 0.20+ | Metrics collection (Phase 13+) |
| grafana/dashboard | - | Monitoring dashboard (Phase 13+) |
| Docker | 25+ | Containerization (Phase 14) |

### 2.6. AI Dependencies (Phase 10+, Optional)
| Dependency | Version | Purpose |
|------------|---------|---------|
| openai | 1.3+ | OpenAI API client |
| anthropic | 0.5+ | Anthropic API client |
| Together | 1.0+ | Together AI client |

### 2.7. Notification Dependencies (Phase 9+, Optional)
| Dependency | Purpose |
|------------|---------|
| python-telegram-bot | Telegram integration |
| discord-webhook | Discord integration |
| slack_sdk | Slack integration |
| aiosmtplib | Email integration |

### 2.8. PDF Generation (Future)
| Dependency | Purpose |
|------------|---------|
| reportlab | PDF generation |
| weasyprint | HTML to PDF conversion |

## 3. Risk Mitigation Summary

### 3.1. Priority Order
1. **Scope enforcement** - CRITICAL - must work perfectly
2. **Subprocess safety** - CRITICAL - command injection prevention
3. **External tool availability** - HIGH - configurable paths
4. **False positive management** - HIGH - deduplication + profiling
5. **AI boundary conditions** - HIGH - hard-coded restrictions
6. **Database migration safety** - HIGH - test rollback paths
7. **Test isolation** - HIGH - mock all external targets
8. **Scalability** - MEDIUM - proper indexing
9. **Worker stability** - MEDIUM - database coordination
10. **Notification safety** - MEDIUM - content filtering

### 3.2. Mitigation Strategies Already Implemented
- AGENTS.md security rules enforce scope and subprocess safety
- ARCHITECTURE.md documents all boundary conditions
- All API endpoints use Pydantic schema validation
- Subprocess execution pattern with timeout, cancellation, stderr capture
- Database-coordinated worker pattern with proper locking
- Mock scanner outputs in test strategy (no real targets)
- Configuration via .env with .env.example template
- No hardcoded secrets anywhere in the codebase

### 3.3. Remaining Mitigations to Implement
- Input validation regex patterns for domains/subdomains
- JWT authentication implementation
- Password hashing with passlib
- Alembic migration setup and test suite
- Connection pool configuration for PostgreSQL
- Rate limiting middleware
- CSP and security headers for frontend
- AI analysis layer with output marking
- Telegram notification integration (content filtering)
- Monitoring and metrics collection setup