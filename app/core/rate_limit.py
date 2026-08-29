"""RedPulse - Rate Limiting Configuration.

Uses SlowAPI with in-memory or Redis-backed storage to prevent API abuse.
Configurable per-endpoint limits via environment variables.
"""
from __future__ import annotations

import os
from typing import Optional

from slowapi import Limiter
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
from slowapi.middleware import SlowAPIMiddleware
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse


def _get_redis_url() -> Optional[str]:
    """Get Redis URL for distributed rate limiting, or None for in-memory."""
    redis_url = os.environ.get("REDIS_URL")
    if redis_url and os.environ.get("RATE_LIMIT_ENABLED", "true").lower() == "true":
        return redis_url
    return None


def create_limiter() -> Limiter:
    """Create a SlowAPI limiter instance.

    Uses Redis if REDIS_URL is set and RATE_LIMIT_ENABLED=true,
    otherwise falls back to in-memory storage (suitable for single-worker).
    """
    redis_url = _get_redis_url()

    if redis_url:
        storage_uri = redis_url
    else:
        storage_uri = "memory://"

    return Limiter(
        key_func=get_remote_address,
        storage_uri=storage_uri,
        default_limits=[
            os.environ.get("RATE_LIMIT_DEFAULT", "60/minute"),
        ],
        headers_enabled=True,
    )


# Global limiter instance
limiter = create_limiter()


# Per-endpoint limit presets
RATE_LIMITS = {
    "auth_login": "5/minute",
    "auth_signup": "3/minute",
    "auth_refresh": "10/minute",
    "pipeline_run": "2/minute",
    "scan_start": "3/minute",
    "recon_start": "3/minute",
    "report_export": "10/minute",
    "webhook_test": "2/minute",
    "monitoring_run": "2/minute",
    "public_api": "100/minute",
    "api_keys": "20/minute",
    "custom_webhooks": "20/minute",
    "audit_logs": "60/minute",
    "default_api": "60/minute",
    "read_only_api": "120/minute",
}


def rate_limit_handler(request: Request, exc: RateLimitExceeded) -> JSONResponse:
    """Custom rate limit exceeded handler returning JSON."""
    return JSONResponse(
        status_code=429,
        content={
            "error": "rate_limit_exceeded",
            "detail": f"Rate limit exceeded: {exc.detail}",
            "retry_after": getattr(exc, "retry_after", None),
        },
        headers={
            "Retry-After": str(getattr(exc, "retry_after", 60)),
        },
    )


def setup_rate_limiting(app: FastAPI) -> None:
    """Attach rate limiter to FastAPI app.

    - Adds SlowAPIMiddleware for automatic rate limiting
    - Registers custom 429 handler
    - Exposes `app.state.limiter` for endpoint decoration
    """
    enabled = os.environ.get("RATE_LIMIT_ENABLED", "true").lower() == "true"

    if not enabled:
        return

    app.state.limiter = limiter
    app.add_middleware(SlowAPIMiddleware)
    app.add_exception_handler(RateLimitExceeded, rate_limit_handler)
