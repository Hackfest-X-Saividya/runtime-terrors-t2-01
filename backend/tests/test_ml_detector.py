import ast
import os
import tempfile
import uuid
from pathlib import Path
from unittest.mock import MagicMock
import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.finding import Finding
from app.models.scan import Scan
from app.services.function_extractor import extract_functions
from app.services.ml_detector import MLDetectorService, MLDetectorStub, ml_service
from app.services.scan_pipeline import execute_scan_pipeline


def test_function_extractor_sync_and_async():
    with tempfile.TemporaryDirectory() as tmp_dir:
        test_file = Path(tmp_dir) / "app.py"
        test_file.write_text(
            "def foo(x):\n"
            "    return x + 1\n\n"
            "async def bar(y):\n"
            "    return y * 2\n",
            encoding="utf-8",
        )

        funcs = extract_functions(tmp_dir)
        assert len(funcs) == 2
        names = {f["name"] for f in funcs}
        assert names == {"foo", "bar"}
        for f in funcs:
            assert f["file_path"] == "app.py"
            assert f["start_line"] >= 1
            assert f["end_line"] >= f["start_line"]
            assert "def " in f["code"]


def test_function_extractor_syntax_error_graceful():
    with tempfile.TemporaryDirectory() as tmp_dir:
        # One valid file and one broken syntax file
        broken_file = Path(tmp_dir) / "broken.py"
        broken_file.write_text("def broken(:\n    pass\n", encoding="utf-8")

        valid_file = Path(tmp_dir) / "valid.py"
        valid_file.write_text("def valid():\n    return True\n", encoding="utf-8")

        funcs = extract_functions(tmp_dir)
        assert len(funcs) == 1
        assert funcs[0]["name"] == "valid"


def test_function_extractor_directory_exclusion():
    with tempfile.TemporaryDirectory() as tmp_dir:
        # Create git and node_modules folders
        git_dir = Path(tmp_dir) / ".git"
        git_dir.mkdir()
        (git_dir / "ignored.py").write_text("def git_func(): pass\n", encoding="utf-8")

        node_dir = Path(tmp_dir) / "node_modules"
        node_dir.mkdir()
        (node_dir / "ignored2.py").write_text("def node_func(): pass\n", encoding="utf-8")

        src_dir = Path(tmp_dir) / "src"
        src_dir.mkdir()
        (src_dir / "good.py").write_text("def good_func(): pass\n", encoding="utf-8")

        funcs = extract_functions(tmp_dir)
        assert len(funcs) == 1
        assert funcs[0]["name"] == "good_func"
        assert funcs[0]["file_path"] == "src/good.py"


def test_ml_detector_stub_patterns():
    stub = MLDetectorStub()

    functions = [
        {
            "name": "insecure_pickle",
            "code": "def load(data):\n    import pickle\n    return pickle.loads(data)\n",
            "file_path": "services/auth.py",
            "start_line": 10,
            "end_line": 13,
        },
        {
            "name": "sql_exec",
            "code": "def search(user_input):\n    cursor.execute(f\"SELECT * FROM users WHERE name = '{user_input}'\")\n",
            "file_path": "services/db.py",
            "start_line": 20,
            "end_line": 22,
        },
        {
            "name": "cmd_run",
            "code": "def run_cmd(arg):\n    subprocess.run(arg, shell=True)\n",
            "file_path": "services/cli.py",
            "start_line": 30,
            "end_line": 32,
        },
        {
            "name": "clean_code",
            "code": "def add(a, b):\n    return a + b\n",
            "file_path": "services/math.py",
            "start_line": 1,
            "end_line": 2,
        },
    ]

    preds = stub.predict(functions)
    assert len(preds) == 4

    # 1. Pickle match
    assert preds[0]["cwe_guess"] == "CWE-502"
    assert preds[0]["ml_score"] >= 0.90
    assert preds[0]["top_lines"] == [12]

    # 2. SQL match
    assert preds[1]["cwe_guess"] == "CWE-89"
    assert preds[1]["ml_score"] >= 0.85
    assert preds[1]["top_lines"] == [21]

    # 3. Command injection match
    assert preds[2]["cwe_guess"] == "CWE-78"
    assert preds[2]["ml_score"] >= 0.85
    assert preds[2]["top_lines"] == [31]

    # 4. Clean function
    assert preds[3]["cwe_guess"] is None
    assert preds[3]["ml_score"] < 0.20


def test_ml_service_fallback_and_runtime_info():
    # Test service in environment where artifacts are absent
    service = MLDetectorService(artifacts_path="nonexistent/ml/artifacts")
    info = service.get_runtime_info()

    assert info["is_stub"] is True
    assert info["artifacts_present"] is False
    assert info["status"] == "stub_fallback"
    assert info["model_name"] == "ZeroSentinel Heuristic Stub"
    assert info["version"] == "stub-v0.1.0"
    assert info["device"] == "cpu"


def test_ml_service_load_failed_status(tmp_path):
    # Create empty artifacts directory to simulate artifacts present but broken/unsupported
    art_dir = tmp_path / "artifacts"
    art_dir.mkdir()
    (art_dir / "dummy.txt").write_text("dummy")

    service = MLDetectorService(artifacts_path=str(art_dir))
    info = service.get_runtime_info()

    assert info["is_stub"] is True
    assert info["artifacts_present"] is True
    assert info["status"] == "load_failed"


@pytest.mark.asyncio
async def test_pipeline_ml_corroboration_and_both_source(isolated_test_db: AsyncSession):
    """
    Test that when a function containing a rule finding is also flagged by ML,
    the finding is updated to source: 'both' with ml_score populated.
    """
    scan = Scan(
        project_name="CorroborationTest",
        submission_type="code",
        language="python",
        status="queued",
    )
    isolated_test_db.add(scan)
    await isolated_test_db.commit()
    await isolated_test_db.refresh(scan)

    code = (
        "import pickle\n"
        "def deserialize_user(token):\n"
        "    return pickle.loads(token)\n"
    )

    await execute_scan_pipeline(
        scan_id=scan.scan_id,
        submission_type="code",
        source_code=code,
        language="python",
        session_override=isolated_test_db,
    )

    await isolated_test_db.refresh(scan)
    assert scan.status == "completed"

    findings_stmt = select(Finding).where(Finding.scan_id == scan.scan_id)
    findings = (await isolated_test_db.execute(findings_stmt)).scalars().all()
    assert len(findings) >= 1

    corroborated = [f for f in findings if f.source == "both"]
    assert len(corroborated) >= 1
    f = corroborated[0]
    assert f.ml_score is not None
    assert 0.0 <= f.ml_score <= 1.0
    assert f.rule_id is not None  # Preserves static rule ID (e.g. B301)


@pytest.mark.asyncio
async def test_pipeline_ml_standalone_promotion(isolated_test_db: AsyncSession, monkeypatch):
    """
    Test that an ML prediction above threshold not caught by static rules
    is promoted to source: 'ml' with cwe_id populated and rule_id=None.
    """
    scan = Scan(
        project_name="StandaloneMLTest",
        submission_type="code",
        language="python",
        status="queued",
    )
    isolated_test_db.add(scan)
    await isolated_test_db.commit()
    await isolated_test_db.refresh(scan)

    # Benign-looking function to static analyzers, but mocked ML returns high score
    code = (
        "def custom_crypto_logic(key, payload):\n"
        "    return key ^ payload\n"
    )

    mock_predict = MagicMock(return_value=[
        {
            "ml_score": 0.88,
            "cwe_guess": "CWE-327",
            "cwe_probs": {"CWE-327": 0.88},
            "top_lines": [2],
        }
    ])
    monkeypatch.setattr(ml_service, "predict", mock_predict)

    await execute_scan_pipeline(
        scan_id=scan.scan_id,
        submission_type="code",
        source_code=code,
        language="python",
        session_override=isolated_test_db,
    )

    await isolated_test_db.refresh(scan)
    assert scan.status == "completed"

    findings_stmt = select(Finding).where(Finding.scan_id == scan.scan_id)
    findings = (await isolated_test_db.execute(findings_stmt)).scalars().all()
    assert len(findings) == 1

    f = findings[0]
    assert f.source == "ml"
    assert f.rule_id is None
    assert f.cwe_id == "CWE-327"
    assert f.ml_score == 0.88
    assert "A04:2025" in (f.owasp or "")


@pytest.mark.asyncio
async def test_pipeline_ml_low_score_discarded(isolated_test_db: AsyncSession, monkeypatch):
    """
    Test that ML predictions below threshold or with null cwe_guess are discarded.
    """
    scan = Scan(
        project_name="LowScoreDiscardTest",
        submission_type="code",
        language="python",
        status="queued",
    )
    isolated_test_db.add(scan)
    await isolated_test_db.commit()
    await isolated_test_db.refresh(scan)

    code = (
        "def safe_calc(a, b):\n"
        "    return a + b\n"
    )

    # Low score prediction (< 0.70 threshold)
    mock_predict = MagicMock(return_value=[
        {
            "ml_score": 0.35,
            "cwe_guess": "CWE-89",
            "cwe_probs": {"CWE-89": 0.35},
            "top_lines": [2],
        }
    ])
    monkeypatch.setattr(ml_service, "predict", mock_predict)

    await execute_scan_pipeline(
        scan_id=scan.scan_id,
        submission_type="code",
        source_code=code,
        language="python",
        session_override=isolated_test_db,
    )

    await isolated_test_db.refresh(scan)
    assert scan.status == "completed"
    assert scan.findings_count == 0


def test_ml_service_real_detector_mock_loading(tmp_path, monkeypatch):
    """
    Verifies that when Member 3's real detector is present, MLDetectorService
    loads it, sets is_stub=False, status='ready', and delegates predict() to it.
    """
    art_dir = tmp_path / "artifacts"
    art_dir.mkdir()
    (art_dir / "weights.bin").write_text("weights")

    class MockRealDetector:
        def __init__(self):
            pass

        @classmethod
        def load(cls, path):
            return cls()

        def predict(self, functions):
            return [
                {
                    "ml_score": 0.88,
                    "cwe_guess": "CWE-89",
                    "cwe_probs": {"CWE-89": 0.88, "CWE-79": 0.12},
                    "top_lines": [fn.get("start_line", 1)],
                }
                for fn in functions
            ]

    import sys
    import types
    mock_module = types.ModuleType("detector")
    mock_module.Detector = MockRealDetector
    monkeypatch.setitem(sys.modules, "detector", mock_module)

    service = MLDetectorService(artifacts_path=str(art_dir))
    info = service.get_runtime_info()

    assert info["is_stub"] is False
    assert info["status"] == "ready"
    assert info["artifacts_present"] is True
    assert info["model_name"] in ("ZeroSentinel Dual-Engine Vulnerability Detector", "ZeroSentinel CodeBERT Detector")
    assert info["version"] == "0.1.0"

    preds = service.predict([{"code": "def foo(): pass", "start_line": 5, "end_line": 6}])
    assert len(preds) == 1
    assert preds[0]["ml_score"] == 0.88
    assert preds[0]["cwe_guess"] == "CWE-89"
