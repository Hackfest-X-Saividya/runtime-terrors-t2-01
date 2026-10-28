import os
import sys
from typing import AsyncGenerator, Generator
import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient
from sqlalchemy import event
from sqlalchemy.ext.asyncio import (
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)
from starlette.testclient import TestClient

# Ensure backend root is on Python path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from app.core.config import settings
from app.core.database import get_db
from app.main import app
from app.models.base import Base


@pytest_asyncio.fixture
async def async_client() -> AsyncGenerator[AsyncClient, None]:
    """Async HTTP client bound to the FastAPI application (without DB override)."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        yield client


@pytest_asyncio.fixture
async def isolated_test_db() -> AsyncGenerator[AsyncSession, None]:
    """
    Isolated in-memory SQLite database strictly for unit testing ORM models
    and schema definition without requiring an active PostgreSQL service.
    NOTE: This is NOT the production database and is never used in production.
    """
    test_engine = create_async_engine("sqlite+aiosqlite:///:memory:")

    # Enforce SQLite foreign keys on each new connection
    @event.listens_for(test_engine.sync_engine, "connect")
    def set_sqlite_pragma(dbapi_connection, connection_record):
        cursor = dbapi_connection.cursor()
        cursor.execute("PRAGMA foreign_keys=ON")
        cursor.close()

    async with test_engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    session_factory = async_sessionmaker(
        bind=test_engine,
        class_=AsyncSession,
        expire_on_commit=False,
    )

    async with session_factory() as session:
        yield session

    async with test_engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)

    await test_engine.dispose()


@pytest_asyncio.fixture
async def client_with_db(isolated_test_db: AsyncSession) -> AsyncGenerator[AsyncClient, None]:
    """Async HTTP client with get_db overridden to use isolated_test_db."""
    async def override_get_db():
        yield isolated_test_db

    app.dependency_overrides[get_db] = override_get_db
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        yield client
    app.dependency_overrides.clear()


@pytest.fixture
def sync_client_with_db(isolated_test_db: AsyncSession) -> Generator[TestClient, None, None]:
    """Synchronous TestClient supporting WebSocket testing with isolated_test_db."""
    async def override_get_db():
        yield isolated_test_db

    app.dependency_overrides[get_db] = override_get_db
    with TestClient(app) as client:
        yield client
    app.dependency_overrides.clear()
