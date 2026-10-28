from datetime import datetime
from typing import Any, Optional
from pydantic import BaseModel, Field


class ErrorDetail(BaseModel):
    code: str
    message: str
    details: Optional[Any] = None


class HealthResponse(BaseModel):
    status: str = Field(..., description="'healthy' or 'degraded'")
    database: str = Field(..., description="'connected' or 'disconnected'")
    version: str
    timestamp: datetime
    error: Optional[ErrorDetail] = None
