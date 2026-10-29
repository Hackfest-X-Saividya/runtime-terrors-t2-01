import pytest
from app.core.config import Settings


def test_default_configuration():
    """Verify default configuration values match CONTRACT.md and PROJECT_CONTEXT.md."""
    config = Settings()
    assert config.APP_VERSION == "0.1.0"
    assert config.MAX_UPLOAD_SIZE_BYTES == 25 * 1024 * 1024
    assert config.MAX_UNCOMPRESSED_BYTES == 100 * 1024 * 1024
    assert config.MAX_ARCHIVE_FILES == 500
    assert config.GIT_CLONE_TIMEOUT_SECONDS == 30
    assert config.MAX_REPO_SIZE_BYTES == 50 * 1024 * 1024
    assert config.ML_STANDALONE_THRESHOLD == 0.70
    assert "postgresql+asyncpg://" in config.DATABASE_URL


def test_configuration_override(monkeypatch):
    """Verify environment variables successfully override defaults."""
    monkeypatch.setenv("APP_PORT", "9000")
    monkeypatch.setenv("ML_STANDALONE_THRESHOLD", "0.85")
    custom_config = Settings()
    assert custom_config.APP_PORT == 9000
    assert custom_config.ML_STANDALONE_THRESHOLD == 0.85
