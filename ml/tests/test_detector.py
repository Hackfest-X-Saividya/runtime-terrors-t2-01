"""
Unit Tests for ZeroSentinel Detector Package.

Verifies:
1. Artifact loading & graceful fallback to dummy mock when artifacts missing.
2. Prediction schema adherence against CONTRACT.md.
3. Scoring and CWE guessing for vulnerable functions.
4. Scoring for benign functions.
5. Line attribution correctness (top_lines bounds and length <= 3).
"""

from pathlib import Path
import pytest
from detector import Detector

ARTIFACTS_DIR = Path(__file__).resolve().parent.parent / "artifacts"

SAMPLE_VULN_SQL = {
    "code": (
        "def fetch_user_data(username: str):\n"
        "    query = f\"SELECT * FROM users WHERE username = '{username}'\"\n"
        "    cursor.execute(query)\n"
        "    return cursor.fetchone()\n"
    ),
    "file_path": "app/views/auth.py",
    "start_line": 10,
    "end_line": 13
}

SAMPLE_VULN_CMD = {
    "code": (
        "def run_diagnostics(ip_address: str):\n"
        "    cmd = f\"ping -c 3 {ip_address}\"\n"
        "    return subprocess.check_output(cmd, shell=True)\n"
    ),
    "file_path": "app/tools/net.py",
    "start_line": 25,
    "end_line": 27
}

SAMPLE_BENIGN = {
    "code": (
        "def compute_hash(salt: bytes, password: str) -> str:\n"
        "    return hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 100000).hex()\n"
    ),
    "file_path": "app/crypto/util.py",
    "start_line": 40,
    "end_line": 41
}

def test_detector_loads_artifacts():
    det = Detector.load(ARTIFACTS_DIR)
    assert det.is_loaded is True
    assert det.vectorizer is not None
    assert det.binary_model is not None
    assert det.cwe_model is not None

def test_detector_fallback_on_missing_dir(tmp_path):
    empty_dir = tmp_path / "empty_artifacts"
    empty_dir.mkdir()
    det = Detector.load(empty_dir)
    assert det.is_loaded is False

    # Still predicts using deterministic hash fallback
    preds = det.predict([SAMPLE_BENIGN])
    assert len(preds) == 1
    assert "ml_score" in preds[0]
    assert "cwe_guess" in preds[0]
    assert "cwe_probs" in preds[0]
    assert "top_lines" in preds[0]

def test_detector_predict_contract_schema():
    det = Detector.load(ARTIFACTS_DIR)
    functions = [SAMPLE_VULN_SQL, SAMPLE_VULN_CMD, SAMPLE_BENIGN]
    preds = det.predict(functions)

    assert len(preds) == len(functions)

    for p, fn in zip(preds, functions):
        assert isinstance(p["ml_score"], float)
        assert 0.0 <= p["ml_score"] <= 1.0
        assert isinstance(p["cwe_guess"], str)
        assert p["cwe_guess"].startswith("CWE-")

        # cwe_probs checks
        assert isinstance(p["cwe_probs"], dict)
        assert len(p["cwe_probs"]) == 7
        total_p = sum(p["cwe_probs"].values())
        assert pytest.approx(total_p, abs=0.02) == 1.0

        # top_lines checks
        top_lines = p["top_lines"]
        assert isinstance(top_lines, list)
        assert 1 <= len(top_lines) <= 3
        for line in top_lines:
            assert fn["start_line"] <= line <= fn["end_line"]

def test_detector_sql_prediction_accuracy():
    det = Detector.load(ARTIFACTS_DIR)
    preds = det.predict([SAMPLE_VULN_SQL])
    res = preds[0]

    assert res["ml_score"] > 0.50
    assert res["cwe_guess"] == "CWE-89"
    # The SQL query is on line 11 or 12
    assert any(line in res["top_lines"] for line in [11, 12])

def test_detector_cmd_injection_accuracy():
    det = Detector.load(ARTIFACTS_DIR)
    preds = det.predict([SAMPLE_VULN_CMD])
    res = preds[0]

    assert res["ml_score"] > 0.50
    assert res["cwe_guess"] == "CWE-78"
    assert any(line in res["top_lines"] for line in [26, 27])

def test_detector_benign_score():
    det = Detector.load(ARTIFACTS_DIR)
    preds = det.predict([SAMPLE_BENIGN])
    res = preds[0]

    assert res["ml_score"] < 0.50
