from typing import Dict, Optional

# Provisional working mappings for OWASP Top 10 (2025)
PROVISIONAL_OWASP_2025_MAP: Dict[str, str] = {
    "CWE-22": "A01:2025-Broken Access Control",
    "CWE-918": "A01:2025-Broken Access Control",
    "CWE-798": "A02:2025-Security Misconfiguration",
    "CWE-1188": "A02:2025-Security Misconfiguration",
    "CWE-1357": "A03:2025-Software Supply Chain Failures",
    "CWE-327": "A04:2025-Cryptographic Failures",
    "CWE-338": "A04:2025-Cryptographic Failures",
    "CWE-89": "A05:2025-Injection",
    "CWE-78": "A05:2025-Injection",
    "CWE-79": "A05:2025-Injection",
    "CWE-77": "A05:2025-Injection",
    "CWE-287": "A07:2025-Authentication Failures",
    "CWE-384": "A07:2025-Authentication Failures",
    "CWE-502": "A08:2025-Software or Data Integrity Failures",
    "CWE-117": "A09:2025-Security Logging and Alerting Failures",
    "CWE-755": "A10:2025-Mishandling of Exceptional Conditions",
    "CWE-703": "A10:2025-Mishandling of Exceptional Conditions",
}


def map_cwe_to_owasp_2025(cwe_id: Optional[str]) -> Optional[str]:
    """
    Returns the provisional OWASP Top 10 (2025) category for a given CWE ID.
    If the CWE is unverified, missing, or unrecognized, returns None.
    """
    if not cwe_id:
        return None

    normalized_cwe = cwe_id.strip().upper()
    if not normalized_cwe.startswith("CWE-"):
        normalized_cwe = f"CWE-{normalized_cwe}"

    return PROVISIONAL_OWASP_2025_MAP.get(normalized_cwe, None)
