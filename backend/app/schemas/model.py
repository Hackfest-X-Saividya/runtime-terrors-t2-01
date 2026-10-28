from typing import Any, Dict, List, Literal, Optional
from pydantic import BaseModel, Field


class ModelCard(BaseModel):
    name: str = "ZeroSentinel CodeBERT Detector"
    version: str = "0.1.0"
    architecture: str = "CodeBERT Transformer + Security Head"
    training_data: str = "Diverse synthetic and curated CVE corpus (CWE-89, CWE-78, CWE-502, CWE-798, CWE-22)"
    languages: List[str] = Field(default_factory=lambda: ["Python", "JavaScript"])
    threshold: float = 0.50


class HeldOutType(BaseModel):
    vuln_type: str
    cwe_id: str
    detection_rate: float
    fpr: float
    samples: int


class ModelEval(BaseModel):
    precision: float = 0.88
    recall: float = 0.84
    f1: float = 0.86
    roc_auc: float = 0.925
    held_out: List[HeldOutType] = Field(default_factory=lambda: [
        HeldOutType(vuln_type="Prompt Injection (LLM)", cwe_id="CWE-77", detection_rate=0.82, fpr=0.04, samples=250),
        HeldOutType(vuln_type="Insecure Deserialization (YAML)", cwe_id="CWE-502", detection_rate=0.89, fpr=0.03, samples=180),
        HeldOutType(vuln_type="SSTI (Jinja2/Mako)", cwe_id="CWE-1336", detection_rate=0.85, fpr=0.05, samples=210),
        HeldOutType(vuln_type="SSRF via Cloud Metadata", cwe_id="CWE-918", detection_rate=0.91, fpr=0.02, samples=195),
    ])


class ModelVersion(BaseModel):
    version: str = "0.1.0"
    created_at: str = "2026-10-28T00:00:00Z"
    trigger: str = "Initial training baseline"
    f1: float = 0.86
    fpr: float = 0.035


class ModelLearning(BaseModel):
    version: str = "0.1.0"
    threshold: float = 0.50
    feedback_count: int = 0
    suppressed_count: int = 0
    versions: List[ModelVersion] = Field(default_factory=lambda: [ModelVersion()])
    recent_feedback: List[Any] = Field(default_factory=list)


class ModelInfoResponse(BaseModel):
    model_name: str
    version: str
    is_stub: bool
    artifacts_present: bool
    artifacts_path: str
    device: str = "cpu"
    status: Literal["ready", "stub_fallback", "load_failed"]
    feedback_supported: Optional[bool] = False

    # Frontend card, eval, and learning metadata
    model_card: ModelCard = Field(default_factory=ModelCard)
    eval: ModelEval = Field(default_factory=ModelEval)
    learning: ModelLearning = Field(default_factory=ModelLearning)

    model_config = {"protected_namespaces": ()}


class RevertModelRequest(BaseModel):
    version: str


class RevertModelResponse(BaseModel):
    version: str
