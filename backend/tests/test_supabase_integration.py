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


def test_settings_recovers_from_https_database_url_when_password_provided():
    """Verify Settings recovers from an HTTPS Supabase project URL by reconstructing postgresql+asyncpg://."""
    settings = Settings(
        DATABASE_URL="https://wwrhgsyemoqfnujnxuui.supabase.co",
        SUPABASE_DB_PASSWORD="my_render_secret_password",
        DB_HOST="aws-0-ap-southeast-1.pooler.supabase.com",
        DB_USER="postgres.wwrhgsyemoqfnujnxuui",
        DB_NAME="postgres",
        DB_PORT=5432,
    )
    assert settings.DATABASE_URL.startswith("postgresql+asyncpg://")
    assert "https://" not in settings.DATABASE_URL
    assert "aws-0-ap-southeast-1.pooler.supabase.com" in settings.DATABASE_URL
    assert "postgres.wwrhgsyemoqfnujnxuui" in settings.DATABASE_URL
    assert "my_render_secret_password" in settings.DATABASE_URL
    # Ensure create_async_engine succeeds without NoSuchModuleError: https
    test_engine = create_async_engine(settings.DATABASE_URL)
    assert test_engine.dialect.name == "postgresql"
    assert test_engine.dialect.driver == "asyncpg"


def test_settings_rejects_https_database_url_without_password():
    """Verify Settings raises a descriptive ValueError when DATABASE_URL is an HTTPS endpoint without credentials."""
    with pytest.raises(ValueError, match="Invalid database URL.*Scheme 'https'"):
        Settings(
            DATABASE_URL="https://wwrhgsyemoqfnujnxuui.supabase.co",
            SUPABASE_DB_PASSWORD=None,
            DB_PASSWORD=None,
        )


def test_settings_sanitizes_http_and_https_in_db_host():
    """Verify Settings strips protocol schemes and trailing paths/ports from DB_HOST."""
    settings = Settings(
        DB_HOST="https://aws-0-ap-southeast-1.pooler.supabase.com:5432/",
        SUPABASE_DB_PASSWORD="secret_password",
    )
    assert settings.DB_HOST == "aws-0-ap-southeast-1.pooler.supabase.com"
    assert settings.DB_PORT == 5432
    assert settings.DATABASE_URL.startswith("postgresql+asyncpg://")
    assert "https://" not in settings.DATABASE_URL


def test_settings_normalizes_postgres_and_postgresql_schemes():
    """Verify Settings normalizes postgres:// and postgresql:// to postgresql+asyncpg://."""
    pg1 = Settings(DATABASE_URL="postgres://user:pass@db.internal:5432/app")
    assert pg1.DATABASE_URL == "postgresql+asyncpg://user:pass@db.internal:5432/app"

    pg2 = Settings(DATABASE_URL="postgresql://user:pass@db.internal:5432/app")
    assert pg2.DATABASE_URL == "postgresql+asyncpg://user:pass@db.internal:5432/app"

    sqlite_norm = Settings(DATABASE_URL="sqlite:///./test.db")
    assert sqlite_norm.DATABASE_URL == "sqlite+aiosqlite:///./test.db"


def test_settings_substitutes_various_password_placeholders():
    """Verify Settings replaces common password placeholders in connection strings."""
    url_template = "postgresql+asyncpg://postgres.ref:[YOUR-PASSWORD]@aws-0.pooler.supabase.com:6543/postgres"
    s1 = Settings(DATABASE_URL=url_template, SUPABASE_DB_PASSWORD="p@ss#word!")
    encoded = quote_plus("p@ss#word!")
    assert encoded in s1.DATABASE_URL
    assert "[YOUR-PASSWORD]" not in s1.DATABASE_URL

    url_template2 = "postgresql+asyncpg://postgres.ref:<password>@aws-0.pooler.supabase.com:6543/postgres"
    s2 = Settings(DATABASE_URL=url_template2, SUPABASE_DB_PASSWORD="p@ss#word!")
    assert encoded in s2.DATABASE_URL
    assert "<password>" not in s2.DATABASE_URL


def test_settings_rejects_unsupported_schemes():
    """Verify Settings fails fast on unsupported schemes such as mysql, ftp, etc."""
    with pytest.raises(ValueError, match="Unsupported database URL scheme 'mysql'"):
        Settings(DATABASE_URL="mysql://root:pass@localhost:3306/zerosentinel")

    with pytest.raises(ValueError, match="Unsupported database URL scheme 'ftp'"):
        Settings(DATABASE_URL="ftp://storage.host/zerosentinel")


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
