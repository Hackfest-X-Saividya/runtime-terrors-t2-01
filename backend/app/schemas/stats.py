from typing import List
from pydantic import BaseModel


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
