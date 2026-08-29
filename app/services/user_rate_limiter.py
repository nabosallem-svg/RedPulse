"""RedPulse - Per-User/Scan Rate Limiting.

Enforces rate limits at the user and scan level to prevent abuse.
Integrates with Redis for distributed tracking across workers.

Phase 13 Safety Gate: Granular rate limiting per user/scan.
"""
from __future__ import annotations

import logging
import os
import time
from typing import Optional, Tuple

logger = logging.getLogger(__name__)

# Rate limit defaults (requests per window)
DEFAULT_USER_LIMITS = {
    "scans_per_hour": 10,
    "scans_per_day": 50,
    "recon_jobs_per_hour": 20,
    "exports_per_hour": 5,
    "api_requests_per_minute": 60,
}

# Rate limit windows (seconds)
WINDOWS = {
    "minute": 60,
    "hour": 3600,
    "day": 86400,
}


class RateLimitExceeded(Exception):
    """Raised when a user exceeds their rate limit."""
    def __init__(self, resource: str, limit: int, window: str, retry_after: int):
        self.resource = resource
        self.limit = limit
        self.window = window
        self.retry_after = retry_after
        super().__init__(
            f"Rate limit exceeded: {resource} limit of {limit}/{window} reached. "
            f"Retry after {retry_after} seconds."
        )


class UserRateLimiter:
    """Per-user rate limiter using Redis or in-memory fallback."""

    def __init__(self, redis_url: Optional[str] = None):
        self.redis_url = redis_url or os.environ.get("REDIS_URL")
        self._memory_store: dict = {}  # In-memory fallback

    def _get_redis(self):
        """Get Redis connection if available."""
        if not self.redis_url:
            return None
        try:
            import redis
            return redis.from_url(self.redis_url, decode_responses=True)
        except Exception:
            return None

    def check_rate_limit(
        self,
        user_id: str,
        resource: str,
        limit: Optional[int] = None,
        window: str = "hour",
    ) -> Tuple[bool, int]:
        """Check if user has exceeded rate limit for a resource.

        Args:
            user_id: The user ID
            resource: Resource name (e.g., "scans", "recon", "exports")
            limit: Max requests allowed (uses default if None)
            window: Time window ("minute", "hour", "day")

        Returns:
            Tuple of (allowed: bool, retry_after_seconds: int)
        """
        if limit is None:
            # Map resource to default limit
            limit_key = f"{resource}_per_{window}"
            limit = DEFAULT_USER_LIMITS.get(limit_key, 60)

        window_seconds = WINDOWS.get(window, 3600)
        now = int(time.time())
        window_start = now - (now % window_seconds)

        redis_client = self._get_redis()
        key = f"rate_limit:{user_id}:{resource}:{window_start}"

        if redis_client:
            return self._check_redis(redis_client, key, limit, window_seconds, now)
        else:
            return self._check_memory(key, limit, window_seconds, now)

    def _check_redis(self, redis_client, key: str, limit: int, window_seconds: int, now: int) -> Tuple[bool, int]:
        """Check rate limit using Redis."""
        try:
            pipe = redis_client.pipeline()
            pipe.incr(key)
            pipe.expire(key, window_seconds)
            results = pipe.execute()

            current_count = results[0]
            if current_count > limit:
                retry_after = window_seconds - (now % window_seconds)
                return False, retry_after

            return True, 0
        except Exception as e:
            logger.warning("Redis rate limit check failed, falling back to memory: %s", e)
            return self._check_memory(key, limit, window_seconds, now)

    def _check_memory(self, key: str, limit: int, window_seconds: int, now: int) -> Tuple[bool, int]:
        """Check rate limit using in-memory store (single worker only)."""
        # Clean up old entries
        cutoff = now - window_seconds * 2
        self._memory_store = {k: v for k, v in self._memory_store.items() if v["last"] > cutoff}

        if key not in self._memory_store:
            self._memory_store[key] = {"count": 0, "last": now}

        entry = self._memory_store[key]
        entry["count"] += 1
        entry["last"] = now

        if entry["count"] > limit:
            retry_after = window_seconds - (now % window_seconds)
            return False, retry_after

        return True, 0

    def get_usage(self, user_id: str, resource: str, window: str = "hour") -> dict:
        """Get current usage for a user/resource combination."""
        window_seconds = WINDOWS.get(window, 3600)
        now = int(time.time())
        window_start = now - (now % window_seconds)

        redis_client = self._get_redis()
        key = f"rate_limit:{user_id}:{resource}:{window_start}"

        if redis_client:
            try:
                count = int(redis_client.get(key) or 0)
            except Exception:
                count = 0
        else:
            entry = self._memory_store.get(key, {"count": 0})
            count = entry["count"]

        limit_key = f"{resource}_per_{window}"
        limit = DEFAULT_USER_LIMITS.get(limit_key, 60)

        return {
            "user_id": user_id,
            "resource": resource,
            "window": window,
            "current": count,
            "limit": limit,
            "remaining": max(0, limit - count),
            "reset_at": window_start + window_seconds,
        }


# Global instance
rate_limiter = UserRateLimiter()
