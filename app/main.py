"""RedPulse - Main Application Entry Point.

FastAPI application with lifecycle management, middleware, and route inclusion.
"""

import logging
import sys
from contextlib import asynccontextmanager

from fastapi import FastAPI, Depends, Request, Response, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from fastapi.exceptions import HTTPException

from app.core.logging import setup_logging
from app.core.config import get_settings
from app.core.security import get_password_hash
from app.core.rate_limit import setup_rate_limiting, limiter, RATE_LIMITS
from app.db.models import User

from app.api.deps import get_current_user, get_db
from app.api.v1.recon import router as recon_router
from app.api.v1.vuln import router as vuln_router
from app.services.scope_validator import ScopeViolation

# Setup logging first
setup_logging()
logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan manager.

    Startup: Initialize database, load configs.
    Shutdown: Cleanup resources, close connections.
    """
    logger.info("Starting RedPulse application...")
    # Serverless-friendly bootstrap: create tables if they don't exist so the
    # API works on platforms like Vercel without a separate migration step.
    # Fails gracefully (logs a warning) if the database is unreachable.
    try:
        from app.db.base import Base
        from app.db.session import engine

        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)
        logger.info("Database schema verified/created.")
    except Exception as exc:  # pragma: no cover - environment dependent
        logger.warning("Startup schema bootstrap skipped: %s", exc)
    yield
    logger.info("Shutting down RedPulse application...")


def create_app() -> FastAPI:
    """Create and configure the FastAPI application."""
    settings = get_settings()

    app = FastAPI(
        title="RedPulse",
        description="Automated security research and continuous attack-surface monitoring platform",
        version="0.1.0",
        docs_url="/docs" if settings.LOG_LEVEL != "disabled" else None,
        redoc_url="/redoc" if settings.LOG_LEVEL != "disabled" else None,
        lifespan=lifespan,
    )

    # Health check - must return {"status": "ok"}
    @app.get("/health", tags=["system"])
    async def health_check():
        return {"status": "ok"}

    # CORS - explicit origins for production security
    default_origins = [
        "http://localhost:3000",
        "http://localhost:3001",
        "http://127.0.0.1:3000",
        "http://127.0.0.1:3001",
        "https://redpulse-app.vercel.app",
        "https://redpulse-frontend.vercel.app",
    ]
    configured = settings.BACKEND_CORS_ORIGINS or []
    origins = []
    for o in list(configured) + default_origins:
        if o and o != "*" and o not in origins:
            origins.append(o)
    app.add_middleware(
        CORSMiddleware,
        allow_origins=origins,
        allow_credentials=True,
        allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
        allow_headers=["Authorization", "Content-Type", "Accept"],
        expose_headers=["Content-Disposition"],
    )

    # Security headers for frontend
    @app.middleware("http")
    async def add_security_headers(request: Request, call_next):
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
        response.headers["X-API-Version"] = "0.1.0"
        return response

    # Rate limiting (SlowAPI)
    setup_rate_limiting(app)

    # Include API routes
    from app.api.v1.auth import router as auth_router

    app.include_router(auth_router, prefix="/api/v1/auth", tags=["auth"])

    from app.api.v1.projects import router as projects_router

    app.include_router(projects_router, prefix="/api/v1/projects", tags=["projects"])

    from app.api.v1.engagements import router as engagements_router

    app.include_router(engagements_router, prefix="/api/v1/engagements", tags=["engagements"])

    from app.api.v1.authorization import router as authorization_router

    app.include_router(authorization_router, prefix="/api/v1/engagements", tags=["authorization"])

    from app.api.v1.scope import router as scope_router

    app.include_router(scope_router, prefix="/api/v1/engagements", tags=["scope"])

    app.include_router(recon_router, prefix="/api/v1/recon", tags=["recon"])

    app.include_router(vuln_router, prefix="/api/v1/vuln", tags=["vulnerability"])

    from app.api.v1.pipeline import router as pipeline_router

    app.include_router(pipeline_router, prefix="/api/v1/pipeline", tags=["pipeline"])

    from app.api.v1.pentest import router as pentest_router

    app.include_router(pentest_router, prefix="/api/v1/projects", tags=["pentest"])

    from app.api.v1.compliance import router as compliance_router

    app.include_router(compliance_router, prefix="/api/v1/projects", tags=["compliance"])

    from app.api.v1.exports import router as exports_router

    app.include_router(exports_router, prefix="/api/v1/findings", tags=["integrations"])

    from app.api.v1.retest import router as retest_router

    app.include_router(retest_router, prefix="/api/v1/findings", tags=["retest"])

    from app.api.v1.bounty_export import router as bounty_router

    app.include_router(bounty_router, prefix="/api/v1/projects", tags=["bounty"])

    from app.api.v1.reporting import router as reporting_router

    app.include_router(reporting_router, prefix="/api/v1/reports", tags=["reports"])

    from app.api.v1.webhooks import router as webhooks_router

    app.include_router(webhooks_router, prefix="/api/v1", tags=["webhooks", "monitoring"])

    from app.api.v1.review_gate import router as review_router

    app.include_router(review_router, prefix="/api/v1", tags=["review-gate"])

    from app.api.v1.workspaces import router as workspaces_router

    app.include_router(workspaces_router, prefix="/api/v1/workspaces", tags=["workspaces"])

    from app.api.v1.billing import router as billing_router

    app.include_router(billing_router, prefix="/api/v1/billing", tags=["billing"])

    from app.api.v1.duplicate_prediction import router as dup_router

    app.include_router(dup_router, prefix="/api/v1", tags=["duplicate-prediction"])

    # Phase 10: Public API + API Keys + Custom Webhooks + Audit Logging
    from app.api.v1.api_keys import router as api_keys_router

    app.include_router(api_keys_router, prefix="/api/v1/api-keys", tags=["api-keys"])

    from app.api.v1.custom_webhooks import router as custom_webhooks_router

    app.include_router(custom_webhooks_router, prefix="/api/v1", tags=["custom-webhooks"])

    from app.api.v1.audit_logs import router as audit_router

    app.include_router(audit_router, prefix="/api/v1", tags=["audit-logs"])

    from app.api.v1.public_api import router as public_api_router

    app.include_router(public_api_router, prefix="/api/v1/public", tags=["public-api"])

    # Phase 11-12: Triage (False Positive workflow feeding AI) + Retest
    from app.api.v1.triage import router as triage_router

    app.include_router(triage_router, prefix="/api/v1", tags=["triage"])

    from app.api.v1.retests import router as retests_router

    app.include_router(retests_router, prefix="/api/v1/retests", tags=["retest"])

    # Observability: queue health, worker crashes
    from app.api.v1.observability import router as observability_router

    app.include_router(observability_router, tags=["observability"])

    # Backup & DR
    from app.api.v1.backup import router as backup_router

    app.include_router(backup_router, prefix="/api/v1", tags=["backup"])

    # Legal docs (public)
    from app.api.v1.legal import router as legal_router

    app.include_router(legal_router, prefix="/api/v1", tags=["legal"])

    # Onboarding first-run
    from app.api.v1.onboarding import router as onboarding_router

    app.include_router(onboarding_router, prefix="/api/v1", tags=["onboarding"])

    # Temporary me endpoint for auth testing
    @app.get("/api/v1/me", tags=["auth"])
    async def get_me(current_user: User = Depends(get_current_user)) -> dict:
        return {"id": current_user.id, "email": current_user.email, "is_active": current_user.is_active}

    # Global exception handler for ScopeViolation
    @app.exception_handler(ScopeViolation)
    async def scope_violation_handler(request: Request, exc: ScopeViolation):
        return JSONResponse(
            status_code=status.HTTP_403_FORBIDDEN,
            content={"detail": exc.detail},
        )

    return app