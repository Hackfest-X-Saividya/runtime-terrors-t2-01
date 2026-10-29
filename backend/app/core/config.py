import json
import os
from typing import Any, Optional, Union
from urllib.parse import quote_plus
from pydantic import field_validator, model_validator
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
    CORS_ALLOWED_ORIGINS: Union[list[str], str] = [
        "https://frontend-eta-brown-70.vercel.app",
        "http://localhost:5173",
        "http://127.0.0.1:5173",
        "http://localhost:3000",
        "http://127.0.0.1:3000",
    ]
    CORS_ORIGINS: Optional[Union[list[str], str]] = None

    model_config = SettingsConfigDict(
        env_file=(".env", "backend/.env", "../.env"),
        env_file_encoding="utf-8",
        extra="ignore"
    )

    @field_validator("CORS_ALLOWED_ORIGINS", "CORS_ORIGINS", mode="before")
    @classmethod
    def parse_cors_origins_input(cls, v: Any) -> Any:
        if v is None:
            return None
        if isinstance(v, str):
            clean = v.strip()
            if clean.startswith("[") and clean.endswith("]"):
                try:
                    parsed = json.loads(clean)
                    if isinstance(parsed, list):
                        return [str(o).strip().rstrip("/") for o in parsed if str(o).strip()]
                except Exception:
                    pass
            return [o.strip().rstrip("/") for o in clean.split(",") if o.strip()]
        if isinstance(v, (list, tuple, set)):
            return [str(o).strip().rstrip("/") for o in v if str(o).strip()]
        return v

    @model_validator(mode="after")
    def assemble_cors_origins(self) -> "Settings":
        origins: list[str] = []
        if isinstance(self.CORS_ALLOWED_ORIGINS, list):
            origins.extend(self.CORS_ALLOWED_ORIGINS)
        elif isinstance(self.CORS_ALLOWED_ORIGINS, str):
            origins.extend([o.strip() for o in self.CORS_ALLOWED_ORIGINS.split(",") if o.strip()])

        if self.CORS_ORIGINS:
            if isinstance(self.CORS_ORIGINS, list):
                origins.extend(self.CORS_ORIGINS)
            elif isinstance(self.CORS_ORIGINS, str):
                origins.extend([o.strip() for o in self.CORS_ORIGINS.split(",") if o.strip()])

        # Guarantee the production Vercel frontend origin is always present
        production_origin = "https://frontend-eta-brown-70.vercel.app"
        if production_origin not in origins:
            origins.insert(0, production_origin)

        # Normalize: strip whitespace, remove trailing slashes, deduplicate
        normalized: list[str] = []
        for o in origins:
            clean = str(o).strip().rstrip("/")
            if clean and clean not in normalized:
                normalized.append(clean)

        self.CORS_ALLOWED_ORIGINS = normalized
        return self

    @model_validator(mode="after")
    def assemble_db_url(self) -> "Settings":
        # 1. Sanitize DB_HOST if user provided host with protocol or trailing path/port
        if self.DB_HOST:
            clean_host = self.DB_HOST.strip()
            if clean_host.startswith(("http://", "https://")):
                clean_host = clean_host.split("://", 1)[1]
            clean_host = clean_host.split("/")[0]
            if ":" in clean_host:
                host_part, port_part = clean_host.split(":", 1)
                clean_host = host_part
                try:
                    self.DB_PORT = int(port_part)
                except ValueError:
                    pass
            # If user passed a bare supabase project ref domain without db. prefix
            if clean_host.endswith(".supabase.co") and not clean_host.startswith(("db.", "aws-")):
                clean_host = f"db.{clean_host}"
            self.DB_HOST = clean_host

        # 2. Check for password and URL-encode special characters
        password = self.SUPABASE_DB_PASSWORD or self.DB_PASSWORD
        enc_pwd = quote_plus(password) if password else None

        # 3. Detect if DATABASE_URL was set to an HTTP/HTTPS URL (e.g. Supabase Project REST URL)
        raw_url = self.DATABASE_URL.strip()
        is_http_url = raw_url.startswith(("http://", "https://"))

        # If DATABASE_URL is an HTTP/HTTPS endpoint:
        if is_http_url:
            # Check if it contains a Supabase project reference
            if ".supabase.co" in raw_url:
                try:
                    extracted_ref = raw_url.split("://", 1)[1].split(".supabase.co")[0].split("/")[0]
                    # If DB_USER is still default or generic postgres, bind project ref
                    if extracted_ref and (self.DB_USER == "postgres" or self.DB_USER == "postgres.wwrhgsyemoqfnujnxuui"):
                        self.DB_USER = f"postgres.{extracted_ref}"
                except Exception:
                    pass

            if enc_pwd:
                # Reconstruct proper async PostgreSQL URL from discrete components
                self.DATABASE_URL = (
                    f"postgresql+asyncpg://{self.DB_USER}:{enc_pwd}@{self.DB_HOST}:{self.DB_PORT}/{self.DB_NAME}"
                )
            else:
                # HTTP/HTTPS cannot be used as an asyncpg/SQLAlchemy dialect
                scheme = raw_url.split("://", 1)[0]
                raise ValueError(
                    f"Invalid database URL: '{self.DATABASE_URL}'. Scheme '{scheme}' is not a valid SQLAlchemy database dialect. "
                    "SQLAlchemy requires an async database connection string (e.g. 'postgresql+asyncpg://...'), not an HTTP/HTTPS REST API endpoint. "
                    "For Supabase, provide a valid connection string in DATABASE_URL or set SUPABASE_DB_PASSWORD along with DB_HOST/DB_USER."
                )

        # 4. Normalize postgres schemes: postgres:// and postgresql:// -> postgresql+asyncpg://
        if self.DATABASE_URL.startswith("postgres://"):
            self.DATABASE_URL = "postgresql+asyncpg://" + self.DATABASE_URL[len("postgres://"):]
        elif self.DATABASE_URL.startswith("postgresql://") and not self.DATABASE_URL.startswith("postgresql+asyncpg://"):
            self.DATABASE_URL = "postgresql+asyncpg://" + self.DATABASE_URL[len("postgresql://"):]
        elif self.DATABASE_URL.startswith("sqlite:///") and not self.DATABASE_URL.startswith("sqlite+aiosqlite:///"):
            self.DATABASE_URL = "sqlite+aiosqlite:///" + self.DATABASE_URL[len("sqlite:///"):]

        # 5. Substitute password placeholders or rebuild if default localhost placeholder
        if enc_pwd:
            placeholders = [
                "[YOUR-PASSWORD]",
                "[your-password]",
                "[PASSWORD]",
                "[password]",
                "<password>",
                "<YOUR_PASSWORD>",
                "YOUR_SUPABASE_PASSWORD",
            ]
            substituted = False
            for ph in placeholders:
                if ph in self.DATABASE_URL:
                    self.DATABASE_URL = self.DATABASE_URL.replace(ph, enc_pwd)
                    substituted = True

            # If user provided password separately and DATABASE_URL is still local default
            if not substituted and "localhost:5432" in self.DATABASE_URL:
                self.DATABASE_URL = (
                    f"postgresql+asyncpg://{self.DB_USER}:{enc_pwd}@{self.DB_HOST}:{self.DB_PORT}/{self.DB_NAME}"
                )

        # 6. Final scheme validation to fail fast before SQLAlchemy dialect lookup
        valid_prefixes = ("postgresql+asyncpg://", "sqlite+aiosqlite://")
        if not self.DATABASE_URL.startswith(valid_prefixes):
            scheme = self.DATABASE_URL.split("://", 1)[0] if "://" in self.DATABASE_URL else self.DATABASE_URL
            raise ValueError(
                f"Unsupported database URL scheme '{scheme}' in '{self.DATABASE_URL}'. "
                "ZeroSentinel requires an async database dialect: 'postgresql+asyncpg://' or 'sqlite+aiosqlite://'."
            )

        return self


settings = Settings()
