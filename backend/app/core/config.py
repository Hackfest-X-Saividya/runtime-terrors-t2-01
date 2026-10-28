import os
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    # Application Info
    APP_NAME: str = "ZeroSentinel Backend"
    APP_VERSION: str = "0.1.0"
    APP_ENV: str = "development"
    APP_DEBUG: bool = True
    APP_HOST: str = "0.0.0.0"
    APP_PORT: int = 8000

    # PostgreSQL 16 Database
    DATABASE_URL: str = "postgresql+asyncpg://postgres:postgres@localhost:5432/zerosentinel"
    DB_POOL_SIZE: int = 10
    DB_MAX_OVERFLOW: int = 20
    DB_POOL_TIMEOUT: float = 30.0
    DB_PING_TIMEOUT: float = 2.0

    # ML Detector Configuration
    ML_ARTIFACTS_PATH: str = "ml/artifacts"
    ML_STANDALONE_THRESHOLD: float = 0.70

    # Ingestion & Security Limits
    MAX_UPLOAD_SIZE_BYTES: int = 25 * 1024 * 1024       # 25 MB
    MAX_UNCOMPRESSED_BYTES: int = 100 * 1024 * 1024    # 100 MB
    MAX_ARCHIVE_FILES: int = 500
    GIT_CLONE_TIMEOUT_SECONDS: int = 30
    MAX_REPO_SIZE_BYTES: int = 50 * 1024 * 1024         # 50 MB

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore"
    )


settings = Settings()
