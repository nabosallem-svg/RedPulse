"""Async database session management for RedPulse.

Provides:
- Async engine creation with proper echo configuration
- Session factory for dependency injection
- `get_db` dependency generator for FastAPI routes
"""

import os
import socket
from urllib.parse import urlparse, urlunparse

from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from sqlalchemy.orm import sessionmaker

from app.core.config import get_settings

settings = get_settings()

ASYNC_DATABASE_URL = settings.DATABASE_URL
if ASYNC_DATABASE_URL.startswith("postgresql://"):
    ASYNC_DATABASE_URL = "postgresql+asyncpg://" + ASYNC_DATABASE_URL[len("postgresql://"):]
ASYNC_DATABASE_URL = ASYNC_DATABASE_URL.replace("pgbouncer=true", "").replace("?&", "?").replace("&&", "&").rstrip("?&")


def _force_ipv4(url: str) -> str:
    try:
        parsed = urlparse(url)
        if not parsed.hostname:
            return url
        infos = socket.getaddrinfo(
            parsed.hostname, parsed.port or 5432, socket.AF_INET, socket.SOCK_STREAM
        )
        if not infos:
            return url
        ipv4 = infos[0][4][0]
        port = parsed.port or 5432
        if "@" in parsed.netloc:
            userinfo, _, _ = parsed.netloc.rpartition("@")
            new_netloc = f"{userinfo}@{ipv4}:{port}"
        else:
            new_netloc = f"{ipv4}:{port}"
        return urlunparse(
            (parsed.scheme, new_netloc, parsed.path, parsed.params, parsed.query, parsed.fragment)
        )
    except Exception:
        return url


ASYNC_DATABASE_URL = _force_ipv4(ASYNC_DATABASE_URL)

engine = create_async_engine(
    ASYNC_DATABASE_URL,
    echo=settings.ENVIRONMENT == "development",
    pool_size=10,
    max_overflow=20,
    pool_timeout=30,
    pool_recycle=3600,
    pool_pre_ping=True,
)

# Create session factory
async_session_factory = sessionmaker(
    bind=engine,
    class_=AsyncSession,
    expire_on_commit=False,
    autoflush=False,
    autocommit=False,
)


async def get_db() -> AsyncSession:
    """Dependency generator that yields an async database session.

    Yields:
        AsyncSession: A SQLAlchemy async session scoped to the request.
    """
    async with async_session_factory() as session:
        yield session