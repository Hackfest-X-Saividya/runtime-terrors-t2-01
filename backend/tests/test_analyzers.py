import json
import os
import tempfile
import pytest

from app.services.analyzers.bandit_analyzer import run_bandit_analysis
from app.services.analyzers.owasp_mapper import map_cwe_to_owasp_2025
from app.services.analyzers.semgrep_analyzer import run_semgrep_analysis


def test_owasp_mapper():
    """Verify provisional OWASP Top 10 (2025) mappings and fallback to None."""
    assert map_cwe_to_owasp_2025("CWE-502") == "A08:2025-Software or Data Integrity Failures"
    assert map_cwe_to_owasp_2025("CWE-89") == "A05:2025-Injection"
    assert map_cwe_to_owasp_2025("CWE-22") == "A01:2025-Broken Access Control"
    assert map_cwe_to_owasp_2025("CWE-9999") is None
    assert map_cwe_to_owasp_2025(None) is None


def test_bandit_analysis_real_vulnerable_code():
    """Verify Bandit detects insecure code (e.g. pickle.loads) in a real test run."""
    with tempfile.TemporaryDirectory() as temp_dir:
        vulnerable_code = (
            "import pickle\n"
            "def handle_data(raw):\n"
            "    return pickle.loads(raw)\n"
        )
        file_path = os.path.join(temp_dir, "auth.py")
        with open(file_path, "w", encoding="utf-8") as f:
            f.write(vulnerable_code)

        findings = run_bandit_analysis(temp_dir)

        # Bandit should find B301 (pickle)
        assert len(findings) >= 1
        pickle_finding = next((f for f in findings if f.rule_id == "B301"), None)
        assert pickle_finding is not None
        assert pickle_finding.severity in ("high", "medium")
        assert pickle_finding.cwe_id == "CWE-502"
        assert pickle_finding.owasp == "A08:2025-Software or Data Integrity Failures"
        assert pickle_finding.source == "rule"
        assert pickle_finding.file_path == "auth.py"
        assert pickle_finding.start_line == 3


def test_bandit_analysis_malformed_output(monkeypatch):
    """Verify Bandit analyzer handles malformed JSON without crashing."""
    import subprocess
    def mock_run(*args, **kwargs):
        class MockProc:
            returncode = 1
            stdout = "{ invalid json..."
            stderr = ""
        return MockProc()

    monkeypatch.setattr(subprocess, "run", mock_run)

    with tempfile.TemporaryDirectory() as temp_dir:
        findings = run_bandit_analysis(temp_dir)
        assert findings == []


def test_bandit_analysis_missing_binary(monkeypatch):
    """Verify Bandit analyzer handles missing executable gracefully."""
    import shutil
    monkeypatch.setattr(shutil, "which", lambda cmd: None)
    monkeypatch.setattr(os.path, "exists", lambda p: False)

    with tempfile.TemporaryDirectory() as temp_dir:
        findings = run_bandit_analysis(temp_dir)
        assert findings == []


def test_semgrep_missing_binary_graceful(monkeypatch):
    """Verify Semgrep analyzer skips analysis gracefully when executable is absent."""
    import shutil
    monkeypatch.setattr(shutil, "which", lambda cmd: None)

    with tempfile.TemporaryDirectory() as temp_dir:
        findings = run_semgrep_analysis(temp_dir)
        assert findings == []
