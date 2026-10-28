import uuid
from typing import List, Literal, Optional
from pydantic import BaseModel, Field


class MitigationDetail(BaseModel):
    id: uuid.UUID
    title: str
    remediation_guidance: str
    code_diff: Optional[str] = None
    references_json: Optional[List[str]] = None

    model_config = {"from_attributes": True}


class FindingResponse(BaseModel):
    id: uuid.UUID
    scan_id: uuid.UUID
    file_path: str
    start_line: int
    end_line: int
    title: str
    cwe_id: Optional[str] = None
    owasp: Optional[str] = None
    source: Literal["rule", "ml", "both"]
    rule_id: Optional[str] = None
    snippet: str
    ml_score: Optional[float] = None
    severity: Literal["critical", "high", "medium", "low"]
    risk_score: float
    mitigation: str
    status: Literal["open", "fixed", "false_positive", "accepted"]

    # Frontend contract compatibility
    ml_score_before: Optional[float] = None
    suppressed: bool = False
    feedback: Optional[dict] = None

    model_config = {"from_attributes": True}


class FindingDetailResponse(FindingResponse):
    mitigation_detail: Optional[MitigationDetail] = None


class FindingUpdateRequest(BaseModel):
    status: Literal["open", "fixed", "false_positive", "accepted"] = Field(
        ...,
        description="New triage status for the finding: open, fixed, false_positive, or accepted",
    )
