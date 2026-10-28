import uuid
from datetime import datetime
from typing import Literal, Optional
from pydantic import BaseModel, Field, model_validator


class SeverityBreakdown(BaseModel):
    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0


class ScanCreateRequest(BaseModel):
    submission_type: Optional[Literal["code", "git", "zip", "rescan"]] = Field(
        default=None,
        description="Type of submission ('code' for snippet, 'git' for repository URL)",
    )
    project_name: Optional[str] = Field(default=None, max_length=255)
    language: str = Field(default="python", max_length=50)

    # For 'code' submission
    source_code: Optional[str] = Field(default=None, max_length=25 * 1024 * 1024)
    code: Optional[str] = Field(default=None, max_length=25 * 1024 * 1024)
    filename: Optional[str] = Field(default=None, max_length=255)

    # For 'git' submission
    git_url: Optional[str] = Field(default=None, max_length=1000)
    branch: Optional[str] = Field(default="main", max_length=255)

    # For 'rescan' submission
    rescan_of: Optional[str] = Field(default=None, max_length=255)

    @model_validator(mode="after")
    def validate_submission_payload(self) -> "ScanCreateRequest":
        # Resolve shorthand code paste from frontend
        if not self.submission_type:
            if self.code or self.source_code:
                self.submission_type = "code"
            elif self.git_url:
                self.submission_type = "git"
            elif self.rescan_of:
                self.submission_type = "rescan"
            else:
                raise ValueError("Must provide code, git_url, or rescan_of.")

        if self.submission_type == "code":
            if not self.source_code and self.code:
                self.source_code = self.code
            if not self.source_code or not self.source_code.strip():
                raise ValueError("source_code must not be empty for 'code' submission.")
            if not self.project_name:
                self.project_name = self.filename or "PastedSnippet"
        elif self.submission_type == "git":
            if not self.git_url or not self.git_url.strip():
                raise ValueError("git_url must not be empty for 'git' submission.")
            if not self.project_name:
                repo_name = self.git_url.rstrip("/").split("/")[-1].replace(".git", "")
                self.project_name = repo_name or "GitProject"
        elif self.submission_type == "rescan":
            if not self.rescan_of or not self.rescan_of.strip():
                raise ValueError("rescan_of must not be empty for 'rescan' submission.")
            if not self.project_name:
                self.project_name = f"Rescan-{self.rescan_of[:8]}"
        return self


class ScanResponse(BaseModel):
    scan_id: uuid.UUID
    project_name: str
    submission_type: str
    language: str = "python"
    status: str
    risk_score: float = 0.0
    findings_count: int = 0
    created_at: datetime
    completed_at: Optional[datetime] = None

    # Frontend compatibility fields
    id: Optional[str] = None
    name: Optional[str] = None
    source_type: Optional[str] = None
    stage: str = "ranking"
    files_scanned: int = 1
    functions_scanned: int = 1
    counts_by_severity: SeverityBreakdown = Field(default_factory=SeverityBreakdown)
    severity_breakdown: SeverityBreakdown = Field(default_factory=SeverityBreakdown)
    started_at: Optional[datetime] = None
    finished_at: Optional[datetime] = None
    rescan_of: Optional[str] = None
    model_version: str = "0.1.0"

    model_config = {"protected_namespaces": (), "from_attributes": True}

    @model_validator(mode="after")
    def sync_aliases(self) -> "ScanResponse":
        if self.id is None and self.scan_id is not None:
            self.id = str(self.scan_id)
        if self.name is None:
            self.name = self.project_name
        if self.source_type is None:
            self.source_type = self.submission_type
        if self.started_at is None:
            self.started_at = self.created_at
        if self.finished_at is None and self.completed_at is not None:
            self.finished_at = self.completed_at
        return self


class ScanDetailResponse(BaseModel):
    scan_id: uuid.UUID
    project_name: str
    submission_type: str
    language: str
    status: str
    risk_score: float = 0.0
    findings_count: int = 0
    severity_breakdown: SeverityBreakdown
    created_at: datetime
    completed_at: Optional[datetime] = None

    # Frontend compatibility fields
    id: Optional[str] = None
    name: Optional[str] = None
    source_type: Optional[str] = None
    stage: str = "ranking"
    files_scanned: int = 1
    functions_scanned: int = 1
    counts_by_severity: SeverityBreakdown = Field(default_factory=SeverityBreakdown)
    started_at: Optional[datetime] = None
    finished_at: Optional[datetime] = None
    rescan_of: Optional[str] = None
    model_version: str = "0.1.0"

    model_config = {"protected_namespaces": (), "from_attributes": True}

    @model_validator(mode="after")
    def sync_aliases(self) -> "ScanDetailResponse":
        if self.id is None and self.scan_id is not None:
            self.id = str(self.scan_id)
        if self.name is None:
            self.name = self.project_name
        if self.source_type is None:
            self.source_type = self.submission_type
        if self.started_at is None:
            self.started_at = self.created_at
        if self.finished_at is None and self.completed_at is not None:
            self.finished_at = self.completed_at
        if self.counts_by_severity == SeverityBreakdown() and self.severity_breakdown != SeverityBreakdown():
            self.counts_by_severity = self.severity_breakdown
        return self
