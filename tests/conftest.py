import sys
import os
import tempfile

# Add project root to path so `app` package is findable
project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if project_root not in sys.path:
    sys.path.insert(0, project_root)

import pytest
from typing import Generator

from sqlalchemy import create_engine, text
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool


# Store the test database engine per test function
_test_engines = {}


def _get_or_create_test_engine(request):
    """Get or create a shared test engine for the current test function."""
    key = request.node.name
    if key not in _test_engines:
        db_path = tempfile.mktemp(suffix=".db")
        # Use file-based SQLite with default pool (not StaticPool) to avoid loop-binding issues with TestClient
        # StaticPool is for :memory: only; file-based should use NullPool/default to allow cross-thread visibility
        engine = create_async_engine(
            f"sqlite+aiosqlite:///{db_path}",
            echo=False,
            connect_args={"check_same_thread": False},
        )
        _test_engines[key] = (engine, db_path)
    return _test_engines[key][0]


def _get_test_db_url(request):
    """Get the database URL for the current test's engine."""
    engine, db_path = _test_engines[request.node.name]
    return f"sqlite+aiosqlite:///{db_path}"


def _cleanup_test_engine(request):
    """Clean up the test engine and database file."""
    key = request.node.name
    if key in _test_engines:
        engine, db_path = _test_engines[key]
        # Engine disposal is handled by the fixture that created it
        if os.path.exists(db_path):
            try:
                os.unlink(db_path)
            except:
                pass
        del _test_engines[key]


@pytest.fixture(scope="function")
async def shared_test_engine(request):
    """Create a shared test engine and tables for the current test function."""
    from app.db.base import Base
    engine = _get_or_create_test_engine(request)
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    yield engine
    # Cleanup handled by app fixture


# Per-test postgres engine cache to share between app and postgres_test_engine within same test
# Keyed by request.node.name, ensures same engine/loop for both fixtures and proper isolation
_postgres_test_engines = {}

async def _get_postgres_engine_for_request(request):
    """Get or create postgres engine for this test request (priority is always real PostgreSQL)."""
    key = request.node.name
    if key in _postgres_test_engines:
        return _postgres_test_engines[key]
    postgres_url = os.getenv("POSTGRES_TEST_URL", "postgresql+asyncpg://RedPulse:test_password@localhost:5433/RedPulse")
    try:
        eng = create_async_engine(postgres_url, echo=False, pool_pre_ping=True)
        import app.db.models  # ensure Base is populated
        from app.db.base import Base
        async with eng.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)
        _postgres_test_engines[key] = eng
        return eng
    except Exception:
        try:
            await eng.dispose()
        except:
            pass
        return None

async def _cleanup_postgres_engine_for_request(request):
    """Cleanup postgres engine for this request: truncate tables and dispose."""
    key = request.node.name
    eng = _postgres_test_engines.pop(key, None)
    if eng is not None:
        try:
            import app.db.models
            from app.db.base import Base
            async with eng.begin() as conn:
                for table in reversed(Base.metadata.sorted_tables):
                    try:
                        await conn.execute(text(f'TRUNCATE TABLE "{table.name}" CASCADE'))
                    except Exception:
                        try:
                            await conn.execute(text(f'DELETE FROM "{table.name}"'))
                        except Exception:
                            pass
                await conn.commit()
        except Exception:
            pass
        try:
            await eng.dispose()
        except:
            pass

@pytest.fixture(scope="function")
async def app(request, shared_test_engine):
    # Priority is always real PostgreSQL for Stripe/postgres tests, but use SQLite for TestClient-based tenant tests to avoid asyncpg loop binding issues
    # TestClient runs app in a different thread (anyio.from_thread) which conflicts with asyncpg's loop-bound connections
    # For tests that use `postgres_test_session` or have 'stripe'/'postgres' in name, use postgres; otherwise use SQLite for TestClient stability
    test_name = request.node.name.lower()
    use_postgres_for_app = any(k in test_name for k in ["stripe", "postgres", "checkout", "webhook", "billing"])
    postgres_engine = None
    if use_postgres_for_app:
        postgres_engine = await _get_postgres_engine_for_request(request)
    if postgres_engine is not None:
        engine_to_use = postgres_engine
        db_url = os.getenv("POSTGRES_TEST_URL", "postgresql+asyncpg://RedPulse:test_password@localhost:5433/RedPulse")
    else:
        engine_to_use = shared_test_engine
        db_url = _get_test_db_url(request)

    os.environ["DATABASE_URL"] = db_url
    # Need to reload app modules that cache DB engine/security, but keep models/services that define tables via Base
    # Deleting app.services.* or app.db.models would cause "Table already defined" on reimport (Base already has tables)
    import sys
    for mod_name in list(sys.modules.keys()):
        if mod_name.startswith("app.api.") or mod_name.startswith("app.core.") or mod_name in ("app.main", "app.db.session"):
            del sys.modules[mod_name]
    
    # Patch the session module BEFORE creating app (so lifespan uses correct engine)
    import app.db.session as session_module
    session_module.engine = engine_to_use
    session_module.async_session_factory = sessionmaker(
        bind=engine_to_use,
        class_=session_module.AsyncSession,
        expire_on_commit=False,
        autoflush=False,
        autocommit=False,
    )
    
    from app.main import create_app
    app_instance = create_app()
    yield app_instance
    # Cleanup postgres for this request (truncate + dispose) — ensures isolation for next test
    # Only cleanup if we were the ones who created it; postgres_test_engine may also have created it
    # Use helper to cleanup per-request engine (handles both cases)
    if postgres_engine is not None:
        # If postgres_test_engine also uses same engine, its fixture will handle cleanup; avoid double dispose
        # Check if engine is still in cache (meaning not yet cleaned)
        key = request.node.name
        if key in _postgres_test_engines:
            await _cleanup_postgres_engine_for_request(request)
    # SQLite engine cleanup handled elsewhere via _test_engines


@pytest.fixture(scope="function")
def client(app):
    from fastapi.testclient import TestClient
    with TestClient(app) as c:
        yield c


@pytest.fixture(scope="function")
async def test_engine(shared_test_engine, request):
    """Return postgres engine for stripe tests, else SQLite (to match app fixture and avoid TestClient loop issues)."""
    test_name = request.node.name.lower()
    use_postgres = any(k in test_name for k in ["stripe", "postgres", "checkout", "webhook", "billing"])
    if use_postgres:
        postgres_engine = await _get_postgres_engine_for_request(request)
        if postgres_engine is not None:
            yield postgres_engine
            # Cleanup if app didn't already (for tests without client)
            key = request.node.name
            if key in _postgres_test_engines:
                await _cleanup_postgres_engine_for_request(request)
            return
    yield shared_test_engine


@pytest.fixture(scope="function")
async def postgres_test_engine(shared_test_engine, request):
    """Try real PostgreSQL on 5433 first (postgres_test container), fallback to SQLite only if unavailable.

    Priority is always real PostgreSQL — SQLite is safety fallback for envs without Docker.
    postgres_test container: postgresql+asyncpg://RedPulse:test_password@localhost:5433/RedPulse
    Original Windows postgres on 5432 conflicts, so 5433 is used for tests.
    Shares per-test postgres engine with `app` fixture to ensure data visibility (same DB/engine).
    """
    postgres_engine = await _get_postgres_engine_for_request(request)
    if postgres_engine is not None:
        yield postgres_engine
        # Cleanup will be handled by app fixture (or here if app not used)
        # If app already cleaned, this is no-op; otherwise ensure cleanup
        key = request.node.name
        if key in _postgres_test_engines:
            await _cleanup_postgres_engine_for_request(request)
        return
    # Fallback to SQLite shared engine only if PostgreSQL unavailable
    yield shared_test_engine


@pytest.fixture(scope="function")
async def postgres_test_session(postgres_test_engine):
    """Create a fresh AsyncSession using the shared test engine."""
    session_factory = sessionmaker(
        postgres_test_engine, class_=AsyncSession, expire_on_commit=False
    )
    async with session_factory() as session:
        yield session
        await session.rollback()


# Keep SQLite session fixture for backward compatibility
@pytest.fixture(scope="function")
async def test_session(test_engine):
    """Create a fresh AsyncSession for each test function with proper cleanup (SQLite)."""
    session_factory = sessionmaker(
        test_engine, class_=AsyncSession, expire_on_commit=False
    )
    async with session_factory() as session:
        yield session
        await session.rollback()


# Optional: allow tests to choose which DB to use via marker
def pytest_addoption(parser):
    parser.addoption(
        "--stripe-db",
        action="store",
        default="sqlite",
        help="Database to use for stripe tests: sqlite or postgres",
    )