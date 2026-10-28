from typing import Any, Dict, List, Literal, Optional
from pydantic import BaseModel, Field


class ModelCard(BaseModel):
    name: str = "ZeroSentinel Dual-Engine Vulnerability Detector"
    version: str = "0.1.0"
    architecture: str = "TF-IDF Code Vectorizer + Class-Weighted Logistic Regression (with Contextual Bandit RL)"
    training_data: str = "VUDENC Curated Python Vulnerability Dataset (75 train, 18 val, 18 test)"
    languages: List[str] = Field(default_factory=lambda: ["Python"])
    threshold: float = 0.53


class HeldOutType(BaseModel):
    vuln_type: str
    cwe_id: str
    detection_rate: float
    fpr: float
    samples: int


class ModelEval(BaseModel):
    precision: float = 1.0
    recall: float = 0.75
    f1: float = 0.8571
    roc_auc: float = 0.925
    held_out: List[HeldOutType] = Field(default_factory=lambda: [
        HeldOutType(vuln_type="sql", cwe_id="CWE-89", detection_rate=1.0, fpr=0.0, samples=1),
        HeldOutType(vuln_type="xss", cwe_id="CWE-79", detection_rate=1.0, fpr=0.0, samples=1),
        HeldOutType(vuln_type="command_injection", cwe_id="CWE-78", detection_rate=1.0, fpr=0.0, samples=1),
        HeldOutType(vuln_type="xsrf", cwe_id="CWE-352", detection_rate=0.0, fpr=0.0, samples=2),
        HeldOutType(vuln_type="remote_code_execution", cwe_id="CWE-94", detection_rate=1.0, fpr=0.0, samples=1),
        HeldOutType(vuln_type="path_disclosure", cwe_id="CWE-22", detection_rate=1.0, fpr=0.0, samples=1),
        HeldOutType(vuln_type="open_redirect", cwe_id="CWE-601", detection_rate=1.0, fpr=0.0, samples=1),
    ])


class ModelVersion(BaseModel):
    version: str = "0.1.0"
    created_at: str = "2026-10-28T09:09:32Z"
    trigger: str = "VUDENC 7-CWE Baseline Training"
    f1: float = 0.8571
    fpr: float = 0.0


class ModelLearning(BaseModel):
    version: str = "0.1.0"
    threshold: float = 0.53
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
