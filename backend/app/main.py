import logging
from contextlib import asynccontextmanager
from fastapi import FastAPI, Request, status
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from app.api.findings import router as findings_router
from app.api.health import router as health_router
from app.api.model import router as model_router
from app.api.scans import router as scans_router
from app.api.stats import router as stats_router
from app.api.websocket import router as websocket_router
from app.core.config import settings
from app.core.database import check_database_health, engine
from app.core.exceptions import ZeroSentinelException
from app.schemas.error import ErrorDetail, ErrorEnvelope

logger = logging.getLogger("zerosentinel")
logging.basicConfig(
    level=logging.INFO if not settings.APP_DEBUG else logging.DEBUG,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup: probe database
    logger.info("Initializing %s v%s...", settings.APP_NAME, settings.APP_VERSION)
    db_ok = await check_database_health()
    if db_ok:
        logger.info("Database connectivity established successfully.")
        try:
            from app.models.base import Base
            import app.models.finding
            import app.models.mitigation
            import app.models.scan
            async with engine.begin() as conn:
                await conn.run_sync(Base.metadata.create_all)
            logger.info("Database schema initialized.")
        except Exception as exc:
            logger.warning("Database schema initialization skipped: %s", exc)
    else:
        logger.warning(
            "Database connectivity check failed on startup. Server running in degraded mode."
        )

    yield

    # Shutdown: clean up engine
    logger.info("Disposing database connection pool...")
    await engine.dispose()
    logger.info("ZeroSentinel shutdown complete.")


def create_application() -> FastAPI:
    app = FastAPI(
        title=settings.APP_NAME,
        version=settings.APP_VERSION,
        lifespan=lifespan,
    )

    # CORS configuration narrowly scoped for Member 2 frontend origins
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.CORS_ALLOWED_ORIGINS,
        allow_credentials=True,
        allow_methods=["GET", "POST", "PATCH", "OPTIONS"],
        allow_headers=["*"],
    )

    # Global Exception Handlers conforming to CONTRACT.md error envelope
    @app.exception_handler(ZeroSentinelException)
    async def zerosentinel_exception_handler(request: Request, exc: ZeroSentinelException):
        return JSONResponse(
            status_code=exc.status_code,
            content=ErrorEnvelope(
                error=ErrorDetail(code=exc.code, message=exc.message, details=exc.details)
            ).model_dump(),
        )

    @app.exception_handler(RequestValidationError)
    async def validation_exception_handler(request: Request, exc: RequestValidationError):
        return JSONResponse(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            content=ErrorEnvelope(
                error=ErrorDetail(
                    code="VALIDATION_ERROR",
                    message="Request schema validation failed.",
                    details=exc.errors(),
                )
            ).model_dump(),
        )

    # Mount routers
    app.include_router(health_router)
    app.include_router(scans_router)
    app.include_router(findings_router)
    app.include_router(stats_router)
    app.include_router(model_router)
    app.include_router(websocket_router)

    return app


app = create_application()
