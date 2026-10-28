import pytest
from urllib.parse import quote_plus
from sqlalchemy.ext.asyncio import create_async_engine
from app.core.config import Settings
from app.core.database import get_database_diagnostic


def test_settings_supabase_password_assembly():
    """Verify Settings properly assembles DATABASE_URL and URL-encodes special characters."""
    special_password = "P@ss/word:with#special%chars!"
    settings = Settings(
        SUPABASE_DB_PASSWORD=special_password,
        DB_HOST="aws-0-ap-southeast-1.pooler.supabase.com",
        DB_USER="postgres.wwrhgsyemoqfnujnxuui",
        DB_NAME="postgres",
        DB_PORT=5432,
    )
    encoded = quote_plus(special_password)
    assert encoded in settings.DATABASE_URL
    assert "aws-0-ap-southeast-1.pooler.supabase.com" in settings.DATABASE_URL
    assert "postgres.wwrhgsyemoqfnujnxuui" in settings.DATABASE_URL
    assert settings.DB_SSL == "require"


def test_settings_explicit_database_url_not_overwritten():
    """Verify that an explicitly provided complete DATABASE_URL is preserved intact."""
    explicit_url = "postgresql+asyncpg://custom_user:custom_pass@custom_db.internal:5432/custom_database"
    settings = Settings(DATABASE_URL=explicit_url)
    assert settings.DATABASE_URL == explicit_url


@pytest.mark.asyncio
async def test_database_diagnostic_read_only():
    """
    Verify get_database_diagnostic returns safe metadata without leaking credentials.
    Tested using an in-memory SQLite engine.
    """
    test_engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    diag = await get_database_diagnostic(target_engine=test_engine)
    assert "version" in diag
    assert diag["database"] == "main"
    assert diag["user"] == "sqlite"
    # Ensure no credential keys are present in diagnostic output
    assert "password" not in diag
    assert "url" not in diag
    await test_engine.dispose()


@pytest.mark.asyncio
async def test_database_diagnostic_unreachable_safe():
    """Verify get_database_diagnostic handles connection failures gracefully without crashing."""
    diag = await get_database_diagnostic()
    assert isinstance(diag, dict)
