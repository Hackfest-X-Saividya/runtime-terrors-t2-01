import pytest
from app.services.security.correlation import (
    CorrelationEngine,
    compute_cluster_id,
    normalize_path,
)


def test_normalize_path_and_deterministic_cluster_id():
    """Verify path normalization and deterministic cluster hash generation."""
    p1 = normalize_path("backend\\app\\api\\auth.py")
    p2 = normalize_path("./backend/app/api/auth.py")
    assert p1 == "backend/app/api/auth.py"
    assert p2 == "backend/app/api/auth.py"

    cid1 = compute_cluster_id(p1, "scope_login", "CWE-89")
    cid2 = compute_cluster_id(p2, "scope_login", "CWE-89")
    assert cid1 == cid2
    assert len(cid1) == 12


def test_exact_duplicate_detection():
    """Verify strong duplicate detection between overlapping Bandit and Semgrep findings."""
    f_bandit = {
        "id": "find-1",
        "file_path": "services/exec.py",
        "start_line": 10,
        "end_line": 12,
        "cwe_id": "CWE-78",
        "rule_id": "B605",
        "source": "rule",
    }
    f_semgrep = {
        "id": "find-2",
        "file_path": "services/exec.py",
        "start_line": 11,
        "end_line": 11,
        "cwe_id": "CWE-78",
        "rule_id": "python.lang.security.audit.dangerous-system-call",
        "source": "rule",
    }

    is_dup, ev = CorrelationEngine.are_exact_duplicates(f_bandit, f_semgrep)
    assert is_dup is True
    assert len(ev) >= 2

    # Different files: must NOT be duplicates
    f_other_file = dict(f_semgrep, file_path="services/other.py")
    assert CorrelationEngine.are_exact_duplicates(f_bandit, f_other_file)[0] is False

    # Distant lines in same file: must NOT be duplicates
    f_distant = dict(f_semgrep, start_line=100, end_line=102)
    assert CorrelationEngine.are_exact_duplicates(f_bandit, f_distant)[0] is False

    # Incompatible CWEs on same line: must NOT be merged as duplicates
    f_diff_cwe = dict(f_semgrep, cwe_id="CWE-798")
    assert CorrelationEngine.are_exact_duplicates(f_bandit, f_diff_cwe)[0] is False


def test_correlation_pipeline_end_to_end():
    """Verify correlation engine categorizes duplicates, corroborated, standalone ML, and related findings."""
    findings = [
        # Pair of exact duplicates
        {
            "id": "b-605",
            "file_path": "app/worker.py",
            "start_line": 20,
            "end_line": 22,
            "cwe_id": "CWE-78",
            "rule_id": "B605",
            "source": "rule",
        },
        {
            "id": "sem-cmd",
            "file_path": "app/worker.py",
            "start_line": 21,
            "end_line": 21,
            "cwe_id": "CWE-78",
            "rule_id": "semgrep-cmd",
            "source": "rule",
        },
        # Corroborated finding (rule + ML)
        {
            "id": "corroborated-sqli",
            "file_path": "app/db.py",
            "start_line": 40,
            "end_line": 45,
            "cwe_id": "CWE-89",
            "rule_id": "B608",
            "source": "both",
            "ml_score": 0.94,
        },
        # Standalone ML zero-day candidate (ML only)
        {
            "id": "ml-candidate",
            "file_path": "app/custom.py",
            "start_line": 50,
            "end_line": 55,
            "cwe_id": "CWE-94",
            "rule_id": None,
            "source": "ml",
            "ml_score": 0.88,
        },
    ]

    clusters, results = CorrelationEngine.correlate_findings(findings)

    assert len(results) == 4

    # 1. Check duplicate group
    res_b605 = results["b-605"]
    res_sem = results["sem-cmd"]
    assert res_b605.cluster_id == res_sem.cluster_id
    assert res_b605.correlation_type == "exact_duplicate"
    assert res_sem.correlation_type == "exact_duplicate"
    assert res_b605.is_primary is True
    assert res_sem.is_primary is False
    assert "sem-cmd" in res_b605.related_finding_ids
    assert "b-605" in res_sem.related_finding_ids

    # 2. Check corroborated finding
    res_corrob = results["corroborated-sqli"]
    assert res_corrob.correlation_type == "corroborated"
    assert res_corrob.confidence == 0.90
    assert any(e.evidence_type == "ml_corroboration" for e in res_corrob.evidence)

    # 3. Check standalone ML candidate
    res_ml = results["ml-candidate"]
    assert res_ml.correlation_type == "standalone_candidate"
    assert "not a confirmed zero-day" in res_ml.limitations.lower()
    assert res_ml.confidence == 0.88


def test_correlation_determinism():
    """Verify repeated correlation executions produce identical clusters and IDs."""
    findings = [
        {"id": "f1", "file_path": "main.py", "start_line": 5, "end_line": 6, "cwe_id": "CWE-89", "source": "rule"},
        {"id": "f2", "file_path": "main.py", "start_line": 5, "end_line": 5, "cwe_id": "CWE-89", "source": "rule"},
    ]

    clusters_a, results_a = CorrelationEngine.correlate_findings(findings)
    clusters_b, results_b = CorrelationEngine.correlate_findings(findings)

    assert [c.cluster_id for c in clusters_a] == [c.cluster_id for c in clusters_b]
    assert results_a["f1"].cluster_id == results_b["f1"].cluster_id
    assert results_a["f1"].confidence == results_b["f1"].confidence
