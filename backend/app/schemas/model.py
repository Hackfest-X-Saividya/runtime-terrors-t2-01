from typing import Literal, Optional
from pydantic import BaseModel


class ModelInfoResponse(BaseModel):
    model_name: str
    version: str
    is_stub: bool
    artifacts_present: bool
    artifacts_path: str
    device: str = "cpu"
    status: Literal["ready", "stub_fallback", "load_failed"]
    feedback_supported: Optional[bool] = False

    model_config = {"protected_namespaces": ()}
