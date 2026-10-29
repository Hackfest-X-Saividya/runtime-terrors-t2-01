"""
ZeroSentinel Security Frameworks & Correlation Module.
Provides official CVSS v3.1 calculation, OWASP Top 10:2025 mappings,
NIST CSF 2.0 taxonomy alignment, and explainable multi-source correlation.
"""

from app.services.security.cvss import (
    CVSSCalculator,
    CVSSAssessment,
    cvss_roundup,
    parse_cvss_vector,
)
from app.services.security.owasp_2025 import (
    OWASP2025Mapper,
    OWASPCategoryMapping,
)
from app.services.security.nist_csf import (
    NISTCSFMapper,
    NISTCSFMapping,
)
from app.services.security.correlation import (
    CorrelationEngine,
    CorrelatedCluster,
    CorrelationResult,
)

__all__ = [
    "CVSSCalculator",
    "CVSSAssessment",
    "cvss_roundup",
    "parse_cvss_vector",
    "OWASP2025Mapper",
    "OWASPCategoryMapping",
    "NISTCSFMapper",
    "NISTCSFMapping",
    "CorrelationEngine",
    "CorrelatedCluster",
    "CorrelationResult",
]
