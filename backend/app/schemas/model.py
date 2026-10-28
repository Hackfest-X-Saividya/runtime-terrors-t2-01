from typing import Literal
from pydantic import BaseModel


class ModelInfoResponse(BaseModel):
    model_name: str
    version: str
    is_stub: bool
    artifacts_present: bool
    artifacts_path: str
    device: str = "cpu"
    status: Literal["ready", "stub_fallback", "load_failed"]

    model_config = {"protected_namespaces": ()}
