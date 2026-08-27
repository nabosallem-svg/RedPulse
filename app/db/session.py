"""Async database session management for RedPulse.

Provides:
- Async engine creation with proper echo configuration
- Session factory for dependency injection
- `get_db` dependency generator for FastAPI routes
"""

import os

from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from sqlalchemy.orm import sessionmaker

from app.core.config import get_settings

settings = get_settings()

# Create async engine
# echo=True logs SQL statements - useful for debugging, set to False in production
ASYNC_DATABASE_URL = settings.DATABASE_URL.replace("postgresql+asyncpg://", "postgresql+asyncpg://")

engine = create_async_engine(
    ASYNC_DATABASE_URL,
    echo=settings.ENVIRONMENT == "development",
    pool_size=20,
    max_overflow=30,
    pool_timeout=30,
    pool_recycle=3600,
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