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
async def test_cors_headers_production_vercel_origin(client_with_db: AsyncClient):
    """Verify that requests from the production Vercel frontend receive valid CORS headers."""
    response = await client_with_db.get(
        "/health",
        headers={"Origin": "https://frontend-eta-brown-70.vercel.app"},
    )
    assert response.status_code in (200, 503)
    assert response.headers.get("access-control-allow-origin") == "https://frontend-eta-brown-70.vercel.app"
    assert response.headers.get("access-control-allow-credentials") == "true"


@pytest.mark.asyncio
async def test_cors_preflight_production_vercel_origin(client_with_db: AsyncClient):
    """Verify that OPTIONS preflight requests from the production Vercel frontend succeed with 200."""
    response = await client_with_db.options(
        "/api/stats/summary",
        headers={
            "Origin": "https://frontend-eta-brown-70.vercel.app",
            "Access-Control-Request-Method": "GET",
            "Access-Control-Request-Headers": "content-type",
        },
    )
    assert response.status_code == 200
    assert response.headers.get("access-control-allow-origin") == "https://frontend-eta-brown-70.vercel.app"
    assert "GET" in response.headers.get("access-control-allow-methods", "")
    assert response.headers.get("access-control-allow-credentials") == "true"


@pytest.mark.asyncio
async def test_cors_config_parsing(monkeypatch):
    """Verify Settings parses comma-separated CORS_ORIGINS and normalizes trailing slashes."""
    from app.core.config import Settings
    monkeypatch.setenv("CORS_ORIGINS", "https://preview.vercel.app/,https://custom-domain.com")
    s = Settings()
    assert "https://frontend-eta-brown-70.vercel.app" in s.CORS_ALLOWED_ORIGINS
    assert "https://preview.vercel.app" in s.CORS_ALLOWED_ORIGINS
    assert "https://custom-domain.com" in s.CORS_ALLOWED_ORIGINS
    assert "https://preview.vercel.app/" not in s.CORS_ALLOWED_ORIGINS


@pytest.mark.asyncio
async def test_cors_headers_disallowed_origin(client_with_db: AsyncClient):
    """Verify that unauthorized origins are not granted CORS access."""
    response = await client_with_db.get(
        "/health",
        headers={"Origin": "http://evil-attacker.example.com"},
    )
    assert response.status_code in (200, 503)
    assert "access-control-allow-origin" not in response.headers
