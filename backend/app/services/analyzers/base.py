from dataclasses import dataclass
from typing import Any, Dict, Optional


@dataclass
class FindingDraft:
    """Internal normalized finding before database persistence."""
    file_path: str
    start_line: int
    end_line: int
    title: str
    severity: str                   # "critical", "high", "medium", "low"
    risk_score: float              # 0.0 - 10.0
    mitigation: str                # Summary guidance
    snippet: str
    cwe_id: Optional[str] = None
    owasp: Optional[str] = None    # Provisional OWASP 2025 or None
    source: str = "rule"           # "rule", "ml", "both"
    rule_id: Optional[str] = None
    ml_score: Optional[float] = None

    # Phase 16 Additive Fields
    cvss_score: Optional[float] = None
    cvss_vector: Optional[str] = None
    cvss_severity: Optional[str] = None
    cvss_provenance: str = "unassessed"
    security_frameworks: Optional[Dict[str, Any]] = None
    correlation_data: Optional[Dict[str, Any]] = None
