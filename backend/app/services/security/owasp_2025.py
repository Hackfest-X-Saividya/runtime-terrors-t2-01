from dataclasses import dataclass, field
from typing import Dict, List, Literal, Optional, Tuple

OWASP_2025_CATEGORIES: Dict[str, str] = {
    "A01:2025": "Broken Access Control",
    "A02:2025": "Security Misconfiguration",
    "A03:2025": "Software Supply Chain Failures",
    "A04:2025": "Cryptographic Failures",
    "A05:2025": "Injection",
    "A06:2025": "Insecure Design",
    "A07:2025": "Authentication Failures",
    "A08:2025": "Software or Data Integrity Failures",
    "A09:2025": "Security Logging and Alerting Failures",
    "A10:2025": "Mishandling of Exceptional Conditions",
}

# Authoritative CWE -> OWASP 2025 definitions with primary and secondary mappings
# Tuple format: (category_id, confidence, rationale, is_primary)
CWE_TO_OWASP_2025_RULES: Dict[str, List[Tuple[str, str, str, bool]]] = {
    # A01:2025 - Broken Access Control (absorbed SSRF & Directory Traversal)
    "CWE-22": [
        ("A01:2025", "high", "Path traversal enables unauthorized file system access across boundary controls.", True),
    ],
    "CWE-23": [
        ("A01:2025", "high", "Relative path traversal bypasses directory restriction policies.", True),
    ],
    "CWE-73": [
        ("A01:2025", "high", "External control of file name or path undermines file system access control.", True),
    ],
    "CWE-918": [
        ("A01:2025", "high", "Server-Side Request Forgery allows an attacker to induce server-side requests to unintended network resources.", True),
    ],
    "CWE-639": [
        ("A01:2025", "high", "Insecure Direct Object Reference (IDOR) bypasses authorization enforcement.", True),
    ],

    # A02:2025 - Security Misconfiguration
    "CWE-798": [
        ("A02:2025", "high", "Hardcoded credentials in source code constitute an insecure deployment configuration.", True),
        ("A07:2025", "medium", "Hardcoded secrets compromise authentication identity verification.", False),
    ],
    "CWE-1188": [
        ("A02:2025", "high", "Initialization of resource with insecure default configuration values.", True),
    ],
    "CWE-200": [
        ("A02:2025", "medium", "Information exposure through error messages or debug configurations.", True),
    ],
    "CWE-16": [
        ("A02:2025", "high", "Configuration weakness in software environment or runtime profile.", True),
    ],

    # A03:2025 - Software Supply Chain Failures
    "CWE-1357": [
        ("A03:2025", "high", "Reliance on untrusted components or insecure supply chain dependencies.", True),
    ],
    "CWE-829": [
        ("A03:2025", "high", "Inclusion of functionality from untrusted control sphere / dependency.", True),
    ],
    "CWE-1104": [
        ("A03:2025", "medium", "Use of unmaintained third-party library or component.", True),
    ],

    # A04:2025 - Cryptographic Failures
    "CWE-327": [
        ("A04:2025", "high", "Use of a broken, deprecated, or risky cryptographic algorithm (e.g. MD5, SHA1).", True),
    ],
    "CWE-328": [
        ("A04:2025", "high", "Use of weak cryptographic hash function susceptible to collision attacks.", True),
    ],
    "CWE-338": [
        ("A04:2025", "high", "Use of cryptographically weak Pseudo-Random Number Generator (PRNG) for security context.", True),
    ],
    "CWE-319": [
        ("A04:2025", "high", "Cleartext transmission of sensitive data over unencrypted channel.", True),
    ],
    "CWE-326": [
        ("A04:2025", "high", "Inadequate encryption strength or undersized cryptographic key length.", True),
    ],

    # A05:2025 - Injection
    "CWE-89": [
        ("A05:2025", "high", "SQL command interpreter receives unescaped, untrusted input altering SQL execution logic.", True),
    ],
    "CWE-78": [
        ("A05:2025", "high", "OS command injection allows execution of arbitrary shell commands on the host environment.", True),
    ],
    "CWE-77": [
        ("A05:2025", "high", "Command injection via improper neutralization of special elements in command strings.", True),
    ],
    "CWE-79": [
        ("A05:2025", "high", "Cross-site scripting (XSS) permits injection of malicious client-side script payloads.", True),
    ],
    "CWE-94": [
        ("A05:2025", "high", "Code injection through dynamic interpretation of untrusted script data.", True),
    ],
    "CWE-95": [
        ("A05:2025", "high", "Improper neutralization of directives in dynamically evaluated code (e.g. eval).", True),
    ],

    # A06:2025 - Insecure Design
    "CWE-657": [
        ("A06:2025", "medium", "Violation of secure design principles in component architecture.", True),
    ],
    "CWE-799": [
        ("A06:2025", "medium", "Improper control of interaction frequency (missing rate limiting design).", True),
    ],

    # A07:2025 - Authentication Failures
    "CWE-287": [
        ("A07:2025", "high", "Improper authentication mechanism allows actors to claim false identities.", True),
    ],
    "CWE-384": [
        ("A07:2025", "high", "Session fixation or improper session lifecycle token regeneration.", True),
    ],
    "CWE-306": [
        ("A07:2025", "high", "Missing authentication for critical function or service interface.", True),
    ],

    # A08:2025 - Software and Data Integrity Failures
    "CWE-502": [
        ("A08:2025", "high", "Deserialization of untrusted data allows execution of arbitrary object graphs or payload execution.", True),
    ],
    "CWE-494": [
        ("A08:2025", "high", "Download of code without integrity check facilitates tamper attacks.", True),
    ],
    "CWE-345": [
        ("A08:2025", "high", "Insufficient verification of data authenticity or integrity signatures.", True),
    ],

    # A09:2025 - Security Logging and Alerting Failures
    "CWE-117": [
        ("A09:2025", "high", "Improper output neutralization for logs allows log injection and log forging.", True),
    ],
    "CWE-778": [
        ("A09:2025", "high", "Insufficient logging of security-critical operational events.", True),
    ],

    # A10:2025 - Mishandling of Exceptional Conditions
    "CWE-755": [
        ("A10:2025", "high", "Improper handling of exceptional conditions induces insecure fallback states.", True),
    ],
    "CWE-703": [
        ("A10:2025", "high", "Improper check or handling of exceptional conditions leads to fail-open vulnerabilities.", True),
    ],
    "CWE-248": [
        ("A10:2025", "medium", "Uncaught exception propagates to crash or leak execution state.", True),
    ],
    "CWE-391": [
        ("A10:2025", "medium", "Unchecked error condition causes silent failure in security control.", True),
    ],
}


@dataclass(frozen=True)
class OWASPCategoryMapping:
    """Represents a validated finding mapping to an OWASP Top 10 (2025) category."""
    version: str = "2025"
    category_id: str = ""
    category_name: str = ""
    confidence: Literal["high", "medium", "low"] = "medium"
    rationale: str = ""
    primary: bool = True
    cwe_id: Optional[str] = None

    @property
    def label(self) -> str:
        """Standard formatted label: 'A05:2025-Injection'."""
        return f"{self.category_id}-{self.category_name}"

    def to_dict(self) -> dict:
        return {
            "version": self.version,
            "category_id": self.category_id,
            "category_name": self.category_name,
            "label": self.label,
            "confidence": self.confidence,
            "rationale": self.rationale,
            "primary": self.primary,
            "cwe_id": self.cwe_id,
        }


class OWASP2025Mapper:
    """
    Evidence-based mapper from static rule and ML evidence to official OWASP Top 10 (2025) categories.
    Ensures that unmapped or unverified findings return an explicit empty mapping without forcing assumptions.
    """

    @classmethod
    def map_finding(
        cls,
        cwe_id: Optional[str] = None,
        rule_id: Optional[str] = None,
        title: Optional[str] = None,
        snippet: Optional[str] = None,
    ) -> List[OWASPCategoryMapping]:
        """
        Maps a finding to OWASP 2025 categories based strictly on verifiable evidence.
        Returns a list of OWASPCategoryMapping (primary first, then secondary if applicable).
        Returns an empty list if evidence is absent or unrecognized.
        """
        results: List[OWASPCategoryMapping] = []

        if cwe_id:
            norm_cwe = cwe_id.strip().upper()
            if not norm_cwe.startswith("CWE-"):
                norm_cwe = f"CWE-{norm_cwe}"

            rules = CWE_TO_OWASP_2025_RULES.get(norm_cwe)
            if rules:
                for cat_id, conf, rationale, is_primary in rules:
                    cat_name = OWASP_2025_CATEGORIES.get(cat_id, "Unknown Category")
                    results.append(
                        OWASPCategoryMapping(
                            version="2025",
                            category_id=cat_id,
                            category_name=cat_name,
                            confidence=conf,  # type: ignore
                            rationale=rationale,
                            primary=is_primary,
                            cwe_id=norm_cwe,
                        )
                    )
                # Sort primary first
                results.sort(key=lambda m: 0 if m.primary else 1)
                return results

        # Fallback heuristic: check rule_id patterns if CWE was not provided
        if rule_id:
            rule_upper = rule_id.strip().upper()
            if rule_upper in ("B605", "B601", "B602", "B607"):
                results.append(
                    OWASPCategoryMapping(
                        version="2025",
                        category_id="A05:2025",
                        category_name=OWASP_2025_CATEGORIES["A05:2025"],
                        confidence="medium",
                        rationale=f"Static analyzer rule '{rule_id}' identifies system command execution / process invocation.",
                        primary=True,
                        cwe_id="CWE-78",
                    )
                )
                return results
            if rule_upper in ("B105", "B106", "B107"):
                results.append(
                    OWASPCategoryMapping(
                        version="2025",
                        category_id="A02:2025",
                        category_name=OWASP_2025_CATEGORIES["A02:2025"],
                        confidence="medium",
                        rationale=f"Static analyzer rule '{rule_id}' identifies hardcoded credentials or passwords in source.",
                        primary=True,
                        cwe_id="CWE-798",
                    )
                )
                return results
            if rule_upper in ("B301", "B302", "B403"):
                results.append(
                    OWASPCategoryMapping(
                        version="2025",
                        category_id="A08:2025",
                        category_name=OWASP_2025_CATEGORIES["A08:2025"],
                        confidence="medium",
                        rationale=f"Static analyzer rule '{rule_id}' identifies unsafe pickle / serialization operations.",
                        primary=True,
                        cwe_id="CWE-502",
                    )
                )
                return results

        # If evidence cannot establish a defensible mapping, return empty list
        return []

    @classmethod
    def get_primary_label(cls, mappings: List[OWASPCategoryMapping]) -> Optional[str]:
        """Returns standard single label for legacy contract compatibility (e.g. 'A05:2025-Injection')."""
        if not mappings:
            return None
        primary = next((m for m in mappings if m.primary), mappings[0])
        return primary.label
