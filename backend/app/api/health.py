from datetime import datetime, timezone
from fastapi import APIRouter, status
from fastapi.responses import JSONResponse

from app.core.config import settings
from app.core.database import check_database_health
from app.schemas.health import ErrorDetail, HealthResponse

router = APIRouter(tags=["health"])


@router.get(
    "/health",
    response_model=HealthResponse,
    status_code=status.HTTP_200_OK,
    responses={
        status.HTTP_200_OK: {"model": HealthResponse},
        status.HTTP_503_SERVICE_UNAVAILABLE: {"model": HealthResponse},
    },
)
async def get_health():
    """
    Service health & database readiness check.
    Returns 200 if PostgreSQL connection succeeds, 503 if unreachable.
    """
    now = datetime.now(timezone.utc)
    db_connected = await check_database_health()

    if db_connected:
        return HealthResponse(
            ok=True,
            status="healthy",
            database="connected",
            version=settings.APP_VERSION,
            timestamp=now,
        )

    response_content = HealthResponse(
        ok=False,
        status="degraded",
        database="disconnected",
        version=settings.APP_VERSION,
        timestamp=now,
        error=ErrorDetail(
            code="DATABASE_UNAVAILABLE",
            message="PostgreSQL 16 connection probe failed.",
            details=None,
        ),
    )
    return JSONResponse(
        status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
        content=response_content.model_dump(mode="json"),
    )
