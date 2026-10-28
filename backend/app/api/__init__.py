from app.api.findings import router as findings_router
from app.api.health import router as health_router
from app.api.model import router as model_router
from app.api.scans import router as scans_router
from app.api.stats import router as stats_router
from app.api.websocket import router as websocket_router

__all__ = [
    "findings_router",
    "health_router",
    "model_router",
    "scans_router",
    "stats_router",
    "websocket_router",
]
