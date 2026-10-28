import pytest
from app.services.security.cvss import (
    CVSSCalculator,
    CVSSAssessment,
    cvss_roundup,
    parse_cvss_vector,
    score_to_severity,
)


def test_cvss_roundup_appendix_a():
    """Verify CVSS v3.1 Appendix A Roundup function against known mathematical edge cases."""
    # When already a single decimal, must remain unchanged
    assert cvss_roundup(4.0) == 4.0
    assert cvss_roundup(0.0) == 0.0
    assert cvss_roundup(9.8) == 9.8

    # When has subsequent decimal digits, rounds up to nearest tenth
    assert cvss_roundup(4.01) == 4.1
    assert cvss_roundup(4.00001) == 4.1
    assert cvss_roundup(4.09) == 4.1
    assert cvss_roundup(6.01) == 6.1
    assert cvss_roundup(9.71) == 9.8


def test_score_to_severity_scale():
    """Verify official CVSS v3.1 qualitative severity ratings."""
    assert score_to_severity(0.0) == "none"
    assert score_to_severity(0.1) == "low"
    assert score_to_severity(3.9) == "low"
    assert score_to_severity(4.0) == "medium"
    assert score_to_severity(6.9) == "medium"
    assert score_to_severity(7.0) == "high"
    assert score_to_severity(8.9) == "high"
    assert score_to_severity(9.0) == "critical"
    assert score_to_severity(10.0) == "critical"

    with pytest.raises(ValueError):
        score_to_severity(-0.1)
    with pytest.raises(ValueError):
        score_to_severity(10.1)


def test_official_first_cvss_reference_vectors():
    """Verify known reference vectors published by FIRST for CVSS v3.1."""
    # Example 1: Critical RCE (Unchanged Scope)
    # CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H -> 9.8 Critical
    res1 = CVSSCalculator.evaluate_vector("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
    assert res1.is_valid is True
    assert res1.score == 9.8
    assert res1.severity == "critical"
    assert res1.provenance == "analyst_assessed"

    # Example 2: Reflected XSS (Changed Scope)
    # CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N -> 6.1 Medium
    res2 = CVSSCalculator.evaluate_vector("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N")
    assert res2.is_valid is True
    assert res2.score == 6.1
    assert res2.severity == "medium"

    # Example 3: Local Privilege Escalation
    # CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H -> 7.8 High
    res3 = CVSSCalculator.evaluate_vector("CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H")
    assert res3.is_valid is True
    assert res3.score == 7.8
    assert res3.severity == "high"

    # Example 4: Information Disclosure with High Complexity
    # CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N -> 3.7 Low
    res4 = CVSSCalculator.evaluate_vector("CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N")
    assert res4.is_valid is True
    assert res4.score == 3.7
    assert res4.severity == "low"

    # Example 5: Zero Impact (None for all impact metrics)
    # CVSS:3.1/AV:P/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N -> 0.0 None
    res5 = CVSSCalculator.evaluate_vector("CVSS:3.1/AV:P/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N")
    assert res5.is_valid is True
    assert res5.score == 0.0
    assert res5.severity == "none"

    # Example 6: Scope Changed Critical Boundary
    # CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H -> 9.9 Critical
    res6 = CVSSCalculator.evaluate_vector("CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H")
    assert res6.is_valid is True
    assert res6.score == 9.9
    assert res6.severity == "critical"


def test_invalid_cvss_vectors():
    """Verify invalid vector strings are handled gracefully without exceptions."""
    # Bad prefix
    res1 = CVSSCalculator.evaluate_vector("CVSS:2.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
    assert res1.is_valid is False
    assert res1.score is None

    # Missing metric (missing A)
    res2 = CVSSCalculator.evaluate_vector("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H")
    assert res2.is_valid is False

    # Invalid metric value (AV:X)
    res3 = CVSSCalculator.evaluate_vector("CVSS:3.1/AV:X/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
    assert res3.is_valid is False

    # Non-string or empty input
    res4 = CVSSCalculator.evaluate_vector("")
    assert res4.is_valid is False


def test_unassessed_cvss_representation():
    """Verify unassessed metrics never fabricate a score and maintain unassessed provenance."""
    unassessed = CVSSAssessment.unassessed("No metrics available")
    assert unassessed.score is None
    assert unassessed.severity == "none"
    assert unassessed.vector is None
    assert unassessed.provenance == "unassessed"
    assert unassessed.is_valid is True


def test_rule_estimated_provenance_and_cwe():
    """Verify rule-estimated vectors are tagged with 'rule_estimated' provenance."""
    est = CVSSCalculator.estimate_from_cwe("CWE-89")
    assert est.is_valid is True
    assert est.provenance == "rule_estimated"
    assert est.score == 9.1
    assert est.severity == "critical"
    assert "AV:N" in est.vector

    # Unknown CWE returns unassessed without raising error
    est_unknown = CVSSCalculator.estimate_from_cwe("CWE-99999")
    assert est_unknown.score is None
    assert est_unknown.provenance == "unassessed"
