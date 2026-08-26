import sys
import os

# Add project root to path so `app` package is findable
project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if project_root not in sys.path:
    sys.path.insert(0, project_root)

import pytest
from typing import Generator

from sqlalchemy import create_engine
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool


@pytest.fixture(scope="function")
def app():
    from app.main import create_app

    return create_app()


@pytest.fixture(scope="function")
async def test_engine():
    """Create a fresh SQLite in-memory engine for each test function."""
    from app.db.base import Base
    engine = create_async_engine(
        "sqlite+aiosqlite:///:memory:",
        echo=False,
        poolclass=StaticPool,
        connect_args={"check_same_thread": False},
    )
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    yield engine
    await engine.dispose()


@pytest.fixture(scope="function")
async def test_session(test_engine):
    """Create a fresh AsyncSession for each test function with proper cleanup."""
    session_factory = sessionmaker(
        test_engine, class_=AsyncSession, expire_on_commit=False
    )
    async with session_factory() as session:
        yield session
        await session.rollback()


@pytest.fixture(scope="function", autouse=True)
async def override_db_dependency(app, test_session):
    from app.api.deps import get_db

    async def _get_test_db():
        yield test_session

    app.dependency_overrides[get_db] = _get_test_db
    yield
    app.dependency_overrides.clear()


@pytest.fixture(scope="function")
def client(app):
    from fastapi.testclient import TestClient

    return TestClient(app)