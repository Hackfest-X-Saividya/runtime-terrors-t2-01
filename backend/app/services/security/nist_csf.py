from dataclasses import dataclass
from typing import Dict, List, Literal, Optional, Tuple

NIST_CSF_VERSION = "2.0"
NIST_CSF_REFERENCE = "NIST Cybersecurity Framework 2.0 (NIST CSWP 29)"

NIST_FUNCTIONS: Dict[str, str] = {
    "GV": "Govern",
    "ID": "Identify",
    "PR": "Protect",
    "DE": "Detect",
    "RS": "Respond",
    "RC": "Recover",
}

NIST_CATEGORIES: Dict[str, Tuple[str, str]] = {
    # Category Code -> (Function Code, Official Category Name)
    "GV.SC": ("GV", "Cybersecurity Supply Chain Risk Management"),
    "ID.RA": ("ID", "Risk Assessment"),
    "PR.AA": ("PR", "Identity Management, Authentication, and Access Control"),
    "PR.DS": ("PR", "Data Security"),
    "PR.PS": ("PR", "Platform Security"),
    "PR.IR": ("PR", "Technology Infrastructure Resilience"),
    "DE.AE": ("DE", "Adverse Event Analysis"),
    "DE.CM": ("DE", "Continuous Monitoring"),
}

# Defensible Subcategory mappings for software-level findings
# Format: CWE -> (Subcategory ID, Official Subcategory Title, Function Code, Category Code, Defensible Rationale)
CWE_TO_NIST_CSF_20: Dict[str, Tuple[str, str, str, str, str]] = {
    # Injection flaws -> Platform Security: unauthorized execution
    "CWE-89": (
        "PR.PS-01",
        "Configuration and execution of software platforms are managed to protect against unauthorized modification and code execution.",
        "PR",
        "PR.PS",
        "SQL injection violates platform execution boundaries by allowing untrusted SQL commands to execute.",
    ),
    "CWE-78": (
        "PR.PS-01",
        "Configuration and execution of software platforms are managed to protect against unauthorized modification and code execution.",
        "PR",
        "PR.PS",
        "OS command injection bypasses application isolation to run arbitrary host shell commands.",
    ),
    "CWE-77": (
        "PR.PS-01",
        "Configuration and execution of software platforms are managed to protect against unauthorized modification and code execution.",
        "PR",
        "PR.PS",
        "Command injection alters host process invocation controls.",
    ),
    "CWE-79": (
        "PR.PS-01",
        "Configuration and execution of software platforms are managed to protect against unauthorized modification and code execution.",
        "PR",
        "PR.PS",
        "Cross-site scripting allows execution of untrusted scripts within client web runtime contexts.",
    ),
    "CWE-94": (
        "PR.PS-01",
        "Configuration and execution of software platforms are managed to protect against unauthorized modification and code execution.",
        "PR",
        "PR.PS",
        "Dynamic code evaluation compromises platform execution integrity.",
    ),

    # Authentication & Access Control
    "CWE-287": (
        "PR.AA-01",
        "Identities and credentials are authenticated and managed.",
        "PR",
        "PR.AA",
        "Authentication weakness permits unverified or impersonated identity assertions.",
    ),
    "CWE-798": (
        "PR.AA-01",
        "Identities and credentials are authenticated and managed.",
        "PR",
        "PR.AA",
        "Hardcoded credentials expose secrets in static code, undermining credential protection policies.",
    ),
    "CWE-384": (
        "PR.AA-01",
        "Identities and credentials are authenticated and managed.",
        "PR",
        "PR.AA",
        "Session fixation vulnerabilities allow attackers to hijack authenticated user sessions.",
    ),
    "CWE-22": (
        "PR.AA-05",
        "Access permissions and authorizations are defined, granted, and managed.",
        "PR",
        "PR.AA",
        "Path traversal bypasses file-system boundary permissions and authorization controls.",
    ),
    "CWE-918": (
        "PR.AA-05",
        "Access permissions and authorizations are defined, granted, and managed.",
        "PR",
        "PR.AA",
        "SSRF abuses server authority to bypass internal network segment access restrictions.",
    ),

    # Data Security & Cryptography
    "CWE-327": (
        "PR.DS-02",
        "The confidentiality and integrity of data-in-transit and cryptographic operations are protected.",
        "PR",
        "PR.DS",
        "Broken cryptographic algorithms fail to guarantee the confidentiality or integrity of protected data.",
    ),
    "CWE-338": (
        "PR.DS-02",
        "The confidentiality and integrity of data-in-transit and cryptographic operations are protected.",
        "PR",
        "PR.DS",
        "Predictable pseudo-random number generators undermine cryptographic session and token security.",
    ),
    "CWE-319": (
        "PR.DS-02",
        "The confidentiality and integrity of data-in-transit and cryptographic operations are protected.",
        "PR",
        "PR.DS",
        "Cleartext data transmission fails to protect sensitive data across communications networks.",
    ),
    "CWE-502": (
        "PR.DS-10",
        "Software and data integrity are protected against unauthorized modification or tampering.",
        "PR",
        "PR.DS",
        "Untrusted deserialization compromises software data integrity and object instantiation safeguards.",
    ),

    # Logging & Monitoring
    "CWE-117": (
        "DE.AE-02",
        "Anomalous activities and events are analyzed to determine their nature and potential impact.",
        "DE",
        "DE.AE",
        "Log injection corrupts audit trails, impairing accurate adverse event analysis and forensic integrity.",
    ),
    "CWE-755": (
        "DE.AE-02",
        "Anomalous activities and events are analyzed to determine their nature and potential impact.",
        "DE",
        "DE.AE",
        "Improper exception handling creates blind spots in adverse event detection and system stability.",
    ),

    # Supply Chain
    "CWE-1357": (
        "GV.SC-04",
        "Suppliers and third-party components are evaluated and managed throughout their lifecycle.",
        "GV",
        "GV.SC",
        "Third-party component dependency vulnerabilities require cybersecurity supply chain risk controls.",
    ),
}


@dataclass(frozen=True)
class NISTCSFMapping:
    """Represents a validated finding alignment with the NIST Cybersecurity Framework 2.0."""
    version: str = NIST_CSF_VERSION
    function_code: str = ""                   # "GV", "ID", "PR", "DE", "RS", "RC"
    function_name: str = ""                   # "Govern", "Protect", etc.
    category_code: str = ""                   # "PR.PS", "PR.AA", etc.
    category_name: str = ""                   # "Platform Security", etc.
    subcategory_id: str = ""                  # "PR.PS-01", etc.
    subcategory_title: str = ""
    rationale: str = ""
    reference: str = NIST_CSF_REFERENCE

    def to_dict(self) -> dict:
        return {
            "version": self.version,
            "function_code": self.function_code,
            "function_name": self.function_name,
            "category_code": self.category_code,
            "category_name": self.category_name,
            "subcategory_id": self.subcategory_id,
            "subcategory_title": self.subcategory_title,
            "rationale": self.rationale,
            "reference": self.reference,
        }


class NISTCSFMapper:
    """
    Maps code-level vulnerabilities to defensible NIST CSF 2.0 controls.
    Explicitly non-evaluative: does not treat NIST CSF as a vulnerability severity score.
    """

    @classmethod
    def map_finding(
        cls,
        cwe_id: Optional[str] = None,
        rule_id: Optional[str] = None,
    ) -> List[NISTCSFMapping]:
        """
        Maps a finding to relevant NIST CSF 2.0 subcategories based strictly on verifiable CWE evidence.
        Returns empty list if no defensible relationship can be established.
        """
        if not cwe_id:
            return []

        norm = cwe_id.strip().upper()
        if not norm.startswith("CWE-"):
            norm = f"CWE-{norm}"

        rule = CWE_TO_NIST_CSF_20.get(norm)
        if not rule:
            return []

        sub_id, sub_title, fn_code, cat_code, rationale = rule
        fn_name = NIST_FUNCTIONS.get(fn_code, fn_code)

        # Category Name lookup
        cat_info = {
            "PR.PS": "Platform Security",
            "PR.AA": "Identity Management, Authentication, and Access Control",
            "PR.DS": "Data Security",
            "DE.AE": "Adverse Event Analysis",
            "GV.SC": "Cybersecurity Supply Chain Risk Management",
            "ID.RA": "Risk Assessment",
        }
        cat_name = cat_info.get(cat_code, cat_code)

        return [
            NISTCSFMapping(
                version=NIST_CSF_VERSION,
                function_code=fn_code,
                function_name=fn_name,
                category_code=cat_code,
                category_name=cat_name,
                subcategory_id=sub_id,
                subcategory_title=sub_title,
                rationale=rationale,
                reference=NIST_CSF_REFERENCE,
            )
        ]
