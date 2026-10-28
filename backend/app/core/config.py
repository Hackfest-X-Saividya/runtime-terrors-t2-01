import os
from typing import Optional
from urllib.parse import quote_plus
from pydantic import model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    # Application Info
    APP_NAME: str = "ZeroSentinel Backend"
    APP_VERSION: str = "0.1.0"
    APP_ENV: str = "development"
    APP_DEBUG: bool = True
    APP_HOST: str = "0.0.0.0"
    APP_PORT: int = 8000

    # PostgreSQL / Supabase Database Configuration
    DATABASE_URL: str = "postgresql+asyncpg://postgres:postgres@localhost:5432/zerosentinel"
    SUPABASE_DB_PASSWORD: Optional[str] = None
    DB_PASSWORD: Optional[str] = None
    DB_HOST: str = "aws-0-ap-southeast-1.pooler.supabase.com"
    DB_PORT: int = 5432
    DB_USER: str = "postgres.wwrhgsyemoqfnujnxuui"
    DB_NAME: str = "postgres"
    DB_SSL: str = "require"
    DB_POOL_SIZE: int = 5
    DB_MAX_OVERFLOW: int = 5
    DB_POOL_TIMEOUT: float = 30.0
    DB_POOL_RECYCLE: int = 1800
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

    # CORS Allowed Origins
    CORS_ALLOWED_ORIGINS: list[str] = [
        "http://localhost:5173",
        "http://127.0.0.1:5173",
        "http://localhost:3000",
        "http://127.0.0.1:3000",
    ]

    model_config = SettingsConfigDict(
        env_file=(".env", "backend/.env", "../.env"),
        env_file_encoding="utf-8",
        extra="ignore"
    )

    @model_validator(mode="after")
    def assemble_db_url(self) -> "Settings":
        password = self.SUPABASE_DB_PASSWORD or self.DB_PASSWORD
        if password:
            enc_pwd = quote_plus(password)
            # If user provided password separately or has placeholder/default in DATABASE_URL
            if "localhost:5432" in self.DATABASE_URL or "YOUR_SUPABASE_PASSWORD" in self.DATABASE_URL:
                self.DATABASE_URL = (
                    f"postgresql+asyncpg://{self.DB_USER}:{enc_pwd}@{self.DB_HOST}:{self.DB_PORT}/{self.DB_NAME}"
                )
            elif "<password>" in self.DATABASE_URL:
                self.DATABASE_URL = self.DATABASE_URL.replace("<password>", enc_pwd)
        return self


settings = Settings()
