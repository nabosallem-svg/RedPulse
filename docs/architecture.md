# RedPulse Architecture

## System Overview

RedPulse is a controlled pentesting SaaS platform. It provides authorized security assessment with strict scope enforcement. All scanning is targeted and authorized before execution.

```
┌─────────────────────────────────────────────────┐
│                   Frontend                       │
│              Next.js Dashboard                   │
│         redpulse-app.vercel.app                  │
└─────────────────┬───────────────────────────────┘
                  │ REST API (JWT Bearer)
┌─────────────────▼───────────────────────────────┐
│                FastAPI Backend                    │
│          red-pulse-nine.vercel.app               │
├─────────────────────────────────────────────────┤
│  Auth │ Projects │ Engagements │ Scope │ Recon   │
├─────────────────────────────────────────────────┤
│          SQLAlchemy Async + asyncpg              │
└─────────────────┬───────────────────────────────┘
                  │
┌─────────────────▼───────────────────────────────┐
│            Supabase PostgreSQL                   │
│    Connection Pooler (port 6543)                 │
└─────────────────────────────────────────────────┘
```

## Main Components

### Backend (`app/`)

| Module | Purpose |
|--------|---------|
| `app/main.py` | FastAPI app factory, middleware, route registration, lifespan |
| `app/core/config.py` | Pydantic settings (env-based configuration) |
| `app/core/security.py` | JWT creation/validation, bcrypt password hashing |
| `app/core/logging.py` | Structured JSON logging |
| `app/db/base.py` | SQLAlchemy async declarative base |
| `app/db/models.py` | ORM models: User, Project, Engagement, Authorization, ScopeRule, PlatformConnection |
| `app/db/session.py` | Async engine, session factory, IPv4 resolution for Vercel |
| `app/api/deps.py` | Dependency injection: get_db, get_current_user, require_project_access |
| `app/api/v1/auth.py` | Signup, login, token refresh, /me |
| `app/api/v1/projects.py` | Project CRUD (create, list, get) |
| `app/api/v1/engagements.py` | Engagement CRUD (create, list, get) |
| `app/api/v1/authorization.py` | DNS TXT and bug bounty authorization |
| `app/api/v1/scope.py` | Scope rule management (add, list) |
| `app/services/scope_validator.py` | Central scope enforcement choke-point |
| `app/services/global_exclusions.py` | .gov/.mil/.edu denylist |
| `app/services/dns_verification.py` | DNS TXT record verification |
| `app/services/auth_service.py` | User creation, authentication |
| `app/services/cvss.py` | CVSS v4.0 scoring |
| `app/services/compliance.py` | OWASP/PCI/ISO mapping |

### Frontend (`frontend/`)

| Module | Purpose |
|--------|---------|
| `frontend/lib/api.ts` | Axios client with JWT refresh, interceptors |
| `frontend/app/login/page.tsx` | Login form |
| `frontend/app/signup/page.tsx` | Registration form |
| `frontend/app/dashboard/page.tsx` | Stats overview |
| `frontend/app/dashboard/projects/page.tsx` | Project list + create |
| `frontend/app/dashboard/projects/[id]/page.tsx` | Project detail + auth + scope |
| `frontend/app/dashboard/engagements/page.tsx` | Engagement list |
| `frontend/app/dashboard/engagements/[id]/page.tsx` | Findings view |

## Data Flow

### Authentication Flow

```
1. User submits email/password
2. POST /api/v1/auth/signup or /login
3. Backend hashes password (bcrypt), creates JWT (30min access, 30day refresh)
4. Frontend stores tokens in localStorage (rp_token, rp_refresh)
5. Every API request includes Authorization: Bearer <access_token>
6. On 401, frontend attempts refresh via POST /api/v1/auth/refresh
7. If refresh fails, redirect to /login
```

### Authorization Flow (DNS TXT)

```
1. User creates engagement (status: draft)
2. User requests authorization via POST /engagements/{id}/authorization
3. Backend generates verification token
4. User adds DNS TXT record: RedPulse-verify=<token>
5. Backend verifies DNS record via dns.resolver
6. Authorization row created with verified=True
7. Engagement status updated to authorized
```

### Scope Enforcement Flow

```
Target → scope_validator.validate_target()
  ├─ 1. Global exclusion (.gov/.mil/.edu) → ScopeViolation
  ├─ 2. Engagement exists + belongs to user → ScopeViolation
  ├─ 3. Authorization verified + not expired → ScopeViolation
  ├─ 4. Target matches include ScopeRule → ScopeViolation
  └─ 5. Target matches exclude ScopeRule → ScopeViolation
  → All passed: target is allowed
```

**Every future scanner (recon, vuln, nuclei) MUST call `validate_target()` before touching any target.**

## Database Relationships

```
User
  ├─ has many → Project (owner_id)
  ├─ has many → Authorization (user_id)
  └─ has many → PlatformConnection (user_id)

Project
  ├─ belongs to → User (owner_id)
  ├─ has many → Engagement (project_id)
  └─ has many → Authorization (project_id)

Engagement
  ├─ belongs to → Project (project_id)
  ├─ has one → Authorization (engagement_id)
  └─ has many → ScopeRule (engagement_id)

Authorization
  ├─ belongs to → Engagement (engagement_id)
  ├─ belongs to → Project (project_id)
  └─ belongs to → User (user_id)

ScopeRule
  └─ belongs to → Engagement (engagement_id)
```

## Scope Enforcement Interface

The central enforcement point for all target operations:

```python
from app.services.scope_validator import validate_target, ScopeViolation

# Before any scan/recon operation:
try:
    await validate_target(
        engagement_id="uuid",
        host_or_url="example.com",
        db=db_session,
        current_user=user,
    )
    # Target is in scope - proceed
except ScopeViolation as e:
    # Target is out of scope - return 403
    raise HTTPException(status_code=403, detail=str(e))
```

## Phase 2 Extension Points

### Asset Model (Future)

```python
class Asset(Base):
    __tablename__ = "assets"
    id = Column(String(36), primary_key=True)
    project_id = Column(String(36), ForeignKey("projects.id"))
    engagement_id = Column(String(36), ForeignKey("engagements.id"))
    hostname = Column(String(255))
    ip_address = Column(String(45))
    scheme = Column(String(10))
    port = Column(Integer)
    status_code = Column(Integer)
    technologies = Column(JSON)
    first_seen = Column(DateTime)
    last_seen = Column(DateTime)
    in_scope = Column(Boolean)
```

### Recon Engine Interface (Future)

```python
class ReconEngine:
    async def run(self, engagement_id: str, target: str, db: AsyncSession, user: User):
        # 1. Validate scope
        await validate_target(engagement_id, target, db, user)
        # 2. Discover subdomains (subfinder)
        # 3. Probe HTTP services (httpx)
        # 4. Normalize and store assets
        # 5. Return asset list
```

### Scanner Interface (Future)

```python
class VulnScanner:
    async def scan(self, engagement_id: str, targets: List[str], db: AsyncSession, user: User):
        for target in targets:
            # 1. Validate scope for each target
            await validate_target(engagement_id, target, db, user)
            # 2. Run nuclei templates
            # 3. Store findings with deduplication
            # 4. Return findings
```

## Configuration

All configuration via environment variables (never hardcoded):

| Variable | Purpose | Default |
|----------|---------|---------|
| `DATABASE_URL` | PostgreSQL connection | (required) |
| `JWT_SECRET` | JWT signing key | (required in prod) |
| `BACKEND_CORS_ORIGINS` | Allowed CORS origins | `["*"]` |
| `ENVIRONMENT` | deployment env | `development` |
| `LOG_LEVEL` | Logging level | `INFO` |

## Deployment

- **Backend**: Vercel serverless (FastAPI)
- **Frontend**: Vercel (Next.js)
- **Database**: Supabase PostgreSQL (free tier)
- **CI/CD**: GitHub → Vercel auto-deploy on push to master
