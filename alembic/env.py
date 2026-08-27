"""Alembic environment for RedPulse - supports both async (app) and sync (migrations)."""

from logging.config import fileConfig

from sqlalchemy import engine_from_config, pool

from alembic import context

# Import Base and models for autogenerate
from app.db.base import Base
from app.db import models  # noqa: F401 - ensure tables are registered

config = context.config

if config.config_file_name is not None:
    fileConfig(config.config_file_name)

target_metadata = Base.metadata


def get_url() -> str:
    """Get DB URL from settings (async) or alembic.ini fallback, converted to sync for migrations."""
    url = None
    try:
        from app.core.config import get_settings

        settings = get_settings()
        url = getattr(settings, "DATABASE_URL", None)
    except Exception:
        pass
    if not url:
        url = config.get_main_option("sqlalchemy.url")
    # Alembic runs with sync engine; convert asyncpg -> psycopg2
    if url and url.startswith("postgresql+asyncpg://"):
        url = url.replace("postgresql+asyncpg://", "postgresql+psycopg2://", 1)
    elif url and url.startswith("sqlite+aiosqlite://"):
        url = url.replace("sqlite+aiosqlite://", "sqlite://", 1)
    return url


def run_migrations_offline() -> None:
    """Run migrations in offline mode (generate SQL)."""
    url = get_url()
    context.configure(
        url=url,
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
        compare_type=True,
        compare_server_default=True,
    )
    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    """Run migrations in online mode (requires DB connection)."""
    url = get_url()
    # Use direct create_engine to avoid ConfigParser % interpolation issues with encoded passwords
    from sqlalchemy import create_engine

    connectable = create_engine(url, poolclass=pool.NullPool)
    with connectable.connect() as connection:
        context.configure(
            connection=connection,
            target_metadata=target_metadata,
            compare_type=True,
            compare_server_default=True,
        )
        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
