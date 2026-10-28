from dataclasses import dataclass
from typing import Optional


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
