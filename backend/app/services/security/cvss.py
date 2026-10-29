import math
import re
from dataclasses import dataclass, field
from typing import Dict, Literal, Optional

CVSS_PREFIX = "CVSS:3.1"

# Numerical Metric Weights per FIRST CVSS v3.1 Specification Section 7.1
WEIGHTS_AV = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.20}
WEIGHTS_AC = {"L": 0.77, "H": 0.44}
WEIGHTS_PR_UNCHANGED = {"N": 0.85, "L": 0.62, "H": 0.27}
WEIGHTS_PR_CHANGED = {"N": 0.85, "L": 0.68, "H": 0.50}
WEIGHTS_UI = {"N": 0.85, "R": 0.62}
WEIGHTS_IMPACT = {"N": 0.0, "L": 0.22, "H": 0.56}

METRIC_NAMES = ("AV", "AC", "PR", "UI", "S", "C", "I", "A")

VECTOR_REGEX = re.compile(
    r"^CVSS:3\.1"
    r"/AV:(?P<AV>[NALP])"
    r"/AC:(?P<AC>[LH])"
    r"/PR:(?P<PR>[NLH])"
    r"/UI:(?P<UI>[NR])"
    r"/S:(?P<S>[UC])"
    r"/C:(?P<C>[NLH])"
    r"/I:(?P<I>[NLH])"
    r"/A:(?P<A>[NLH])$",
    re.IGNORECASE,
)


def cvss_roundup(input_val: float) -> float:
    """
    Official CVSS v3.1 Appendix A Roundup function.
    Returns the smallest number, specified to one decimal place, that is >= input.
    Uses 100,000 integer math to eliminate IEEE-754 precision artifacts.
    """
    int_input = round(input_val * 100000)
    if int_input % 10000 == 0:
        return int_input / 100000.0
    return (math.floor(int_input / 10000) + 1) / 10.0


def score_to_severity(score: float) -> str:
    """Returns official qualitative severity rating from score."""
    if score == 0.0:
        return "none"
    if 0.1 <= score <= 3.9:
        return "low"
    if 4.0 <= score <= 6.9:
        return "medium"
    if 7.0 <= score <= 8.9:
        return "high"
    if 9.0 <= score <= 10.0:
        return "critical"
    raise ValueError(f"Score {score} is out of valid CVSS range [0.0, 10.0]")


@dataclass(frozen=True)
class CVSSAssessment:
    """Immutable representation of a CVSS v3.1 Base Score assessment."""
    version: str = "3.1"
    score: Optional[float] = None
    vector: Optional[str] = None
    severity: Optional[str] = None
    provenance: Literal["analyst_assessed", "rule_estimated", "unassessed"] = "unassessed"
    metrics: Dict[str, str] = field(default_factory=dict)
    is_valid: bool = True
    error_message: Optional[str] = None

    @classmethod
    def unassessed(cls, reason: str = "No CVSS metrics provided") -> "CVSSAssessment":
        return cls(
            version="3.1",
            score=None,
            vector=None,
            severity="none",
            provenance="unassessed",
            metrics={},
            is_valid=True,
            error_message=reason,
        )

    def to_dict(self) -> dict:
        return {
            "version": self.version,
            "score": self.score,
            "vector": self.vector,
            "severity": self.severity,
            "provenance": self.provenance,
            "metrics": dict(self.metrics),
            "is_valid": self.is_valid,
        }


def parse_cvss_vector(vector_str: str) -> Dict[str, str]:
    """
    Parses and validates a CVSS v3.1 Base vector string.
    Raises ValueError with a specific description if the vector format or values are invalid.
    """
    if not vector_str or not isinstance(vector_str, str):
        raise ValueError("CVSS vector string must be a non-empty string.")

    cleaned = vector_str.strip().upper()
    match = VECTOR_REGEX.match(cleaned)
    if not match:
        raise ValueError(
            f"Invalid CVSS v3.1 vector string '{vector_str}'. "
            f"Expected format: CVSS:3.1/AV:[NALP]/AC:[LH]/PR:[NLH]/UI:[NR]/S:[UC]/C:[NLH]/I:[NLH]/A:[NLH]"
        )

    return match.groupdict()


class CVSSCalculator:
    """
    Implements the official FIRST CVSS v3.1 Base Score calculation algorithm.
    Section 7: Equations & Scoring.
    """

    @classmethod
    def calculate_base_score(cls, metrics: Dict[str, str]) -> float:
        """
        Calculates the CVSS v3.1 Base Score from validated metrics.
        metrics keys: AV, AC, PR, UI, S, C, I, A
        """
        # Ensure all metrics present
        for m in METRIC_NAMES:
            if m not in metrics:
                raise ValueError(f"Missing required CVSS metric '{m}'")

        av = metrics["AV"]
        ac = metrics["AC"]
        pr = metrics["PR"]
        ui = metrics["UI"]
        scope = metrics["S"]
        c = metrics["C"]
        i = metrics["I"]
        a = metrics["A"]

        # Validate values against dictionaries
        if av not in WEIGHTS_AV:
            raise ValueError(f"Invalid AV value '{av}'")
        if ac not in WEIGHTS_AC:
            raise ValueError(f"Invalid AC value '{ac}'")
        if ui not in WEIGHTS_UI:
            raise ValueError(f"Invalid UI value '{ui}'")
        if scope not in ("U", "C"):
            raise ValueError(f"Invalid S value '{scope}'")
        if c not in WEIGHTS_IMPACT or i not in WEIGHTS_IMPACT or a not in WEIGHTS_IMPACT:
            raise ValueError("Invalid impact metric value for C, I, or A")

        # Privileges Required weight depends on Scope
        if scope == "U":
            pr_val = WEIGHTS_PR_UNCHANGED.get(pr)
        else:
            pr_val = WEIGHTS_PR_CHANGED.get(pr)
        if pr_val is None:
            raise ValueError(f"Invalid PR value '{pr}' for Scope {scope}")

        # 1. Impact Sub-Score (ISS)
        c_val = WEIGHTS_IMPACT[c]
        i_val = WEIGHTS_IMPACT[i]
        a_val = WEIGHTS_IMPACT[a]
        iss = 1.0 - ((1.0 - c_val) * (1.0 - i_val) * (1.0 - a_val))

        # 2. Impact
        if scope == "U":
            impact = 6.42 * iss
        else:
            impact = 7.52 * (iss - 0.029) - 3.25 * math.pow((iss - 0.02), 15)

        # 3. Exploitability
        av_val = WEIGHTS_AV[av]
        ac_val = WEIGHTS_AC[ac]
        ui_val = WEIGHTS_UI[ui]
        exploitability = 8.22 * av_val * ac_val * pr_val * ui_val

        # 4. Base Score
        if impact <= 0.0:
            return 0.0

        if scope == "U":
            raw_score = min(impact + exploitability, 10.0)
            return cvss_roundup(raw_score)
        else:
            raw_score = min(1.08 * (impact + exploitability), 10.0)
            return cvss_roundup(raw_score)

    @classmethod
    def evaluate_vector(
        cls,
        vector_str: str,
        provenance: Literal["analyst_assessed", "rule_estimated", "unassessed"] = "analyst_assessed",
    ) -> CVSSAssessment:
        """
        Parses, validates, and computes the CVSS v3.1 assessment for a vector string.
        """
        try:
            metrics = parse_cvss_vector(vector_str)
            score = cls.calculate_base_score(metrics)
            canonical_vector = (
                f"{CVSS_PREFIX}/AV:{metrics['AV']}/AC:{metrics['AC']}/PR:{metrics['PR']}"
                f"/UI:{metrics['UI']}/S:{metrics['S']}/C:{metrics['C']}/I:{metrics['I']}/A:{metrics['A']}"
            )
            severity = score_to_severity(score)
            return CVSSAssessment(
                version="3.1",
                score=score,
                vector=canonical_vector,
                severity=severity,
                provenance=provenance,
                metrics=metrics,
                is_valid=True,
            )
        except Exception as exc:
            return CVSSAssessment(
                version="3.1",
                score=None,
                vector=vector_str,
                severity=None,
                provenance=provenance,
                metrics={},
                is_valid=False,
                error_message=str(exc),
            )

    @classmethod
    def estimate_from_cwe(
        cls,
        cwe_id: Optional[str],
        provenance: Literal["rule_estimated", "unassessed"] = "rule_estimated",
    ) -> CVSSAssessment:
        """
        Generates a standardized baseline rule-estimated CVSS vector based on established CWE profiles.
        Explicitly marked as 'rule_estimated'. Never claims analyst provenance.
        """
        if not cwe_id:
            return CVSSAssessment.unassessed("No CWE identifier provided for CVSS estimation")

        norm = cwe_id.strip().upper()
        if not norm.startswith("CWE-"):
            norm = f"CWE-{norm}"

        # Standard reference baseline profiles for common software vulnerability classes
        cwe_profiles = {
            # Remote Command Execution
            "CWE-78": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",   # 9.8 Critical
            "CWE-77": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",   # 9.8 Critical
            # SQL Injection
            "CWE-89": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",   # 9.1 Critical
            # Cross-Site Scripting (Reflected)
            "CWE-79": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",   # 6.1 Medium
            # Path Traversal
            "CWE-22": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",   # 7.5 High
            # SSRF
            "CWE-918": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:L/I:L/A:N",  # 7.2 High
            # Insecure Deserialization
            "CWE-502": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",  # 9.8 Critical
            # Hardcoded Credentials
            "CWE-798": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",  # 7.5 High
            # Broken Authentication
            "CWE-287": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",  # 9.1 Critical
            # Cryptographic Failure (Weak cipher / PRNG)
            "CWE-327": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N",  # 5.9 Medium
            "CWE-338": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N",  # 3.7 Low
            # Log Injection
            "CWE-117": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N",  # 5.3 Medium
        }

        vec = cwe_profiles.get(norm)
        if vec:
            return cls.evaluate_vector(vec, provenance=provenance)

        return CVSSAssessment.unassessed(f"No standardized CVSS estimation profile for '{norm}'")
