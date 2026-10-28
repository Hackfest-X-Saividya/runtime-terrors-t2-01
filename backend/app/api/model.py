from fastapi import APIRouter, status

from app.schemas.model import ModelInfoResponse
from app.services.ml_detector import ml_service

router = APIRouter(prefix="/api", tags=["model"])


@router.get(
    "/model/info",
    response_model=ModelInfoResponse,
    status_code=status.HTTP_200_OK,
)
async def get_model_info():
    """
    Exposes the actual runtime status of the ML inference subsystem,
    dynamically derived from live environment checks and detector availability.
    """
    info = ml_service.get_runtime_info()
    return ModelInfoResponse(**info)
