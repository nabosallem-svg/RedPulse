"""Async database session management for RedPulse.

Provides:
- Async engine creation with proper echo configuration
- Session factory for dependency injection
- `get_db` dependency generator for FastAPI routes
"""

import os
import socket

from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from sqlalchemy.orm import sessionmaker

from app.core.config import get_settings

settings = get_settings()

# Create async engine
# echo=True logs SQL statements - useful for debugging, set to False in production
ASYNC_DATABASE_URL = settings.DATABASE_URL.replace("postgresql+asyncpg://", "postgresql+asyncpg://")

# Force IPv4: Vercel's serverless network resolves some hosts (e.g. Supabase)
# to IPv6 addresses it cannot route to, causing "Cannot assign requested
# address" (EADDRNOTAVAIL) at connect time. Pinning AF_INET avoids that.
engine = create_async_engine(
    ASYNC_DATABASE_URL,
    echo=settings.ENVIRONMENT == "development",
    pool_size=10,
    max_overflow=20,
    pool_timeout=30,
    pool_recycle=3600,
    pool_pre_ping=True,
    connect_args={"family": socket.AF_INET},
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