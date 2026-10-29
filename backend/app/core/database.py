import logging
from typing import Any, AsyncGenerator, Dict, Optional
from sqlalchemy import text
from sqlalchemy.engine.url import make_url
from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)

from app.core.config import settings

logger = logging.getLogger("zerosentinel.database")

# Build async engine targeting PostgreSQL 16 / Supabase (or custom test engine when injected)
engine_kwargs: Dict[str, Any] = {"echo": settings.APP_DEBUG}

if not settings.DATABASE_URL.startswith("sqlite"):
    engine_kwargs.update({
        "pool_size": settings.DB_POOL_SIZE,
        "max_overflow": settings.DB_MAX_OVERFLOW,
        "pool_timeout": settings.DB_POOL_TIMEOUT,
        "pool_recycle": settings.DB_POOL_RECYCLE,
        "pool_pre_ping": True,
    })
    # Configure SSL for Supabase or when SSL is explicitly set to require
    if "supabase.com" in settings.DATABASE_URL or getattr(settings, "DB_SSL", None) == "require":
        engine_kwargs["connect_args"] = {"ssl": "require"}

try:
    _masked_url = make_url(settings.DATABASE_URL).render_as_string(hide_password=True)
    logger.info("Initializing database engine with URL: %s", _masked_url)
except Exception:
    pass

engine: AsyncEngine = create_async_engine(
    settings.DATABASE_URL,
    **engine_kwargs,
)

# Async session factory
AsyncSessionLocal = async_sessionmaker(
    bind=engine,
    class_=AsyncSession,
    expire_on_commit=False,
    autocommit=False,
    autoflush=False,
)


async def get_db() -> AsyncGenerator[AsyncSession, None]:
    """Dependency for providing an async database session per request."""
    async with AsyncSessionLocal() as session:
        try:
            yield session
        finally:
            await session.close()


async def check_database_health() -> bool:
    """
    Executes an active probe ('SELECT 1') against the configured database.
    Returns True if connectivity is established, False otherwise.
    """
    try:
        async with engine.connect() as conn:
            result = await conn.execute(text("SELECT 1"))
            return result.scalar() == 1
    except Exception as exc:
        logger.warning("Database health probe failed: %s", exc)
        return False


async def get_database_diagnostic(target_engine: Optional[AsyncEngine] = None) -> Dict[str, str]:
    """
    Executes a read-only probe returning version, database name, and user.
    Never exposes passwords or sensitive credentials.
    Returns empty dict if connection cannot be established.
    """
    active_engine = target_engine or engine
    try:
        async with active_engine.connect() as conn:
            dialect_name = active_engine.dialect.name
            if dialect_name == "sqlite":
                result = await conn.execute(text("SELECT sqlite_version(), 'main', 'sqlite'"))
            else:
                result = await conn.execute(text("SELECT version(), current_database(), current_user"))
            row = result.fetchone()
            if row:
                return {
                    "version": str(row[0]),
                    "database": str(row[1]),
                    "user": str(row[2]),
                }
            return {}
    except Exception as exc:
        logger.warning("Database diagnostic check failed: %s", exc)
        return {}
