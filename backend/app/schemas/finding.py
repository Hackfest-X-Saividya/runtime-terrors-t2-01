import uuid
from typing import Any, Dict, List, Literal, Optional
from pydantic import BaseModel, Field, model_validator


class MitigationDetail(BaseModel):
    id: uuid.UUID
    title: str
    remediation_guidance: str
    code_diff: Optional[str] = None
    references_json: Optional[List[str]] = None

    model_config = {"from_attributes": True}


class CVSSDetail(BaseModel):
    version: str = "3.1"
    score: Optional[float] = None
    vector: Optional[str] = None
    severity: Optional[str] = None
    provenance: Literal["analyst_assessed", "rule_estimated", "unassessed"] = "unassessed"
    metrics: Optional[Dict[str, str]] = None


class OWASPMapping(BaseModel):
    version: str = "2025"
    category_id: str
    category_name: str
    confidence: Literal["high", "medium", "low"]
    rationale: str
    primary: bool = True
    cwe_id: Optional[str] = None


class NISTCSFMapping(BaseModel):
    version: str = "2.0"
    function_code: str
    function_name: str
    category_code: str
    category_name: str
    subcategory_id: str
    subcategory_title: str
    rationale: str
    reference: str


class CorrelationEvidenceItemSchema(BaseModel):
    source: str
    evidence_type: str
    detail: str


class CorrelationDetailSchema(BaseModel):
    cluster_id: str
    correlation_type: Literal[
        "exact_duplicate",
        "corroborated",
        "related_risk",
        "standalone_candidate",
        "unassigned",
    ]
    primary_finding_id: Optional[str] = None
    is_primary: bool = True
    confidence: float = 0.0
    rationale: str = ""
    evidence: List[CorrelationEvidenceItemSchema] = Field(default_factory=list)
    limitations: Optional[str] = None
    related_finding_ids: List[str] = Field(default_factory=list)


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

    # Phase 16 Additive Fields: CVSS v3.1
    cvss_score: Optional[float] = None
    cvss_vector: Optional[str] = None
    cvss_severity: Optional[str] = None
    cvss_provenance: Optional[str] = "unassessed"
    cvss: Optional[CVSSDetail] = None

    # Phase 16 Additive Fields: Security Frameworks
    security_frameworks: Optional[Dict[str, Any]] = None
    owasp_mappings: Optional[List[OWASPMapping]] = None
    nist_csf_mappings: Optional[List[NISTCSFMapping]] = None

    # Phase 16 Additive Fields: Explainable Correlation
    correlation_data: Optional[Dict[str, Any]] = None
    correlation: Optional[CorrelationDetailSchema] = None

    model_config = {"from_attributes": True}

    @model_validator(mode="after")
    def populate_nested_security_objects(self) -> "FindingResponse":
        # 1. Populate cvss if not already provided
        if not self.cvss:
            self.cvss = CVSSDetail(
                version="3.1",
                score=self.cvss_score,
                vector=self.cvss_vector,
                severity=self.cvss_severity,
                provenance=self.cvss_provenance or "unassessed",  # type: ignore
            )

        # 2. Extract framework mappings from security_frameworks if present
        if self.security_frameworks:
            if not self.owasp_mappings and "owasp_2025" in self.security_frameworks:
                self.owasp_mappings = [
                    OWASPMapping(**m) for m in self.security_frameworks["owasp_2025"]
                ]
            if not self.nist_csf_mappings and "nist_csf_20" in self.security_frameworks:
                self.nist_csf_mappings = [
                    NISTCSFMapping(**m) for m in self.security_frameworks["nist_csf_20"]
                ]

        # 3. Extract correlation from correlation_data if present
        if self.correlation_data and not self.correlation:
            try:
                self.correlation = CorrelationDetailSchema(**self.correlation_data)
            except Exception:
                pass

        return self


class FindingDetailResponse(FindingResponse):
    mitigation_detail: Optional[MitigationDetail] = None


class FindingUpdateRequest(BaseModel):
    status: Literal["open", "fixed", "false_positive", "accepted"] = Field(
        ...,
        description="New triage status for the finding: open, fixed, false_positive, or accepted",
    )
