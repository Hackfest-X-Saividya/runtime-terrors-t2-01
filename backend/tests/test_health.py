import pytest
from httpx import AsyncClient


@pytest.mark.asyncio
async def test_health_healthy_mocked(async_client: AsyncClient, monkeypatch):
    """
    Unit test (Mocked): GET /health returns 200 OK and healthy status
    when database probe succeeds.
    """
    async def mock_check_health_ok():
        return True

    monkeypatch.setattr("app.api.health.check_database_health", mock_check_health_ok)

    response = await async_client.get("/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "healthy"
    assert data["database"] == "connected"
    assert data["version"] == "0.1.0"
    assert "timestamp" in data
    assert data.get("error") is None


@pytest.mark.asyncio
async def test_health_degraded_mocked(async_client: AsyncClient, monkeypatch):
    """
    Unit test (Mocked): GET /health returns 503 Service Unavailable
    with structured error envelope when database probe fails.
    """
    async def mock_check_health_fail():
        return False

    monkeypatch.setattr("app.api.health.check_database_health", mock_check_health_fail)

    response = await async_client.get("/health")
    assert response.status_code == 503
    data = response.json()
    assert data["status"] == "degraded"
    assert data["database"] == "disconnected"
    assert data["version"] == "0.1.0"
    assert data["error"]["code"] == "DATABASE_UNAVAILABLE"
    assert "probe failed" in data["error"]["message"].lower()


@pytest.mark.asyncio
async def test_health_live_probe(async_client: AsyncClient):
    """
    Integration test (Live Probe): Verifies GET /health against live environment.
    If PostgreSQL 16 is reachable, returns 200; if unreachable, returns 503.
    Never returns 200 if PostgreSQL connection fails.
    """
    response = await async_client.get("/health")
    assert response.status_code in (200, 503)
    data = response.json()
    if response.status_code == 200:
        assert data["database"] == "connected"
        assert data["status"] == "healthy"
    else:
        assert data["database"] == "disconnected"
        assert data["status"] == "degraded"
