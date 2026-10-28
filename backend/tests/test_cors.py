import pytest
from httpx import AsyncClient


@pytest.mark.asyncio
async def test_cors_headers_allowed_origin(client_with_db: AsyncClient):
    """Verify that requests from authorized frontend origins receive valid CORS headers."""
    response = await client_with_db.get(
        "/health",
        headers={"Origin": "http://localhost:5173"},
    )
    assert response.status_code in (200, 503)
    assert response.headers.get("access-control-allow-origin") == "http://localhost:5173"
    assert response.headers.get("access-control-allow-credentials") == "true"


@pytest.mark.asyncio
async def test_cors_headers_disallowed_origin(client_with_db: AsyncClient):
    """Verify that unauthorized origins are not granted CORS access."""
    response = await client_with_db.get(
        "/health",
        headers={"Origin": "http://evil-attacker.example.com"},
    )
    assert response.status_code in (200, 503)
    assert "access-control-allow-origin" not in response.headers
