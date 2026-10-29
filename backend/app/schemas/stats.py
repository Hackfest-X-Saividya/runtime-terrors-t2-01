from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field

from app.schemas.finding import FindingResponse
from app.schemas.scan import ScanResponse


class SeverityDistribution(BaseModel):
    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0


class TopCweItem(BaseModel):
    cwe_id: str
    count: int


class StatsSummaryResponse(BaseModel):
    total_scans: int
    total_findings: int
    severity_distribution: SeverityDistribution
    top_cwes: List[TopCweItem]
    average_risk_score: float

    # Frontend compatibility fields
    by_severity: SeverityDistribution = Field(default_factory=SeverityDistribution)
    by_source: Dict[str, int] = Field(default_factory=lambda: {"rule": 0, "ml": 0, "both": 0})
    by_owasp: Dict[str, int] = Field(default_factory=dict)
    novel_count: int = 0
    top_findings: List[FindingResponse] = Field(default_factory=list)
    last_scan: Optional[ScanResponse] = None
