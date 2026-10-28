import uuid
from datetime import datetime
from typing import Literal, Optional
from pydantic import BaseModel, Field, model_validator


class ScanCreateRequest(BaseModel):
    submission_type: Literal["code", "git"] = Field(
        ...,
        description="Type of submission ('code' for snippet, 'git' for repository URL)",
    )
    project_name: str = Field(..., min_length=1, max_length=255)
    language: str = Field(default="python", max_length=50)

    # For 'code' submission
    source_code: Optional[str] = Field(default=None, max_length=25 * 1024 * 1024)

    # For 'git' submission
    git_url: Optional[str] = Field(default=None, max_length=1000)
    branch: Optional[str] = Field(default="main", max_length=255)

    @model_validator(mode="after")
    def validate_submission_payload(self) -> "ScanCreateRequest":
        if self.submission_type == "code":
            if not self.source_code or not self.source_code.strip():
                raise ValueError("source_code must not be empty for 'code' submission.")
        elif self.submission_type == "git":
            if not self.git_url or not self.git_url.strip():
                raise ValueError("git_url must not be empty for 'git' submission.")
        return self


class ScanResponse(BaseModel):
    scan_id: uuid.UUID
    project_name: str
    submission_type: str
    language: str
    status: str
    risk_score: float = 0.0
    findings_count: int = 0
    created_at: datetime
    completed_at: Optional[datetime] = None

    model_config = {"from_attributes": True}
