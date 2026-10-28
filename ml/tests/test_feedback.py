"""
Unit Tests for ZeroSentinel Reinforcement Learning Feedback Module.

Verifies:
1. `det.feedback(code, status="false_positive")` applies negative reward and
   suppresses subsequent vulnerability score on that pattern.
2. `det.feedback(code, status="fixed")` applies positive reward and reinforces
   detection score.
3. State persistence to `ml/artifacts/rl_state.json` across reloads.
4. Safe handling when operating in mock mode without artifacts.
"""

import json
from pathlib import Path
import pytest
from detector import Detector

ARTIFACTS_DIR = Path(__file__).resolve().parent.parent / "artifacts"

SAMPLE_CODE = (
    "def custom_template_builder(name: str):\n"
    "    # Complex formatting that might trigger false alarm in internal tool\n"
    "    return f'Hello, {name}!'\n"
)

def test_feedback_suppresses_false_positive(tmp_path):
    det = Detector.load(ARTIFACTS_DIR)
    assert det.is_loaded is True

    # 1. Score before feedback
    functions = [{"code": SAMPLE_CODE, "start_line": 1, "end_line": 3, "file_path": "builder.py"}]
    score_initial = det.predict(functions)[0]["ml_score"]

    # 2. Analyst marks finding as false positive
    res = det.feedback(
        code=SAMPLE_CODE,
        status="false_positive",
        func_name="custom_template_builder"
    )
    assert res["status"] == "false_positive"
    assert res["reward"] < 0
    assert res["score_after"] < res["score_before"]

    # 3. Subsequent prediction reflects learned suppression
    score_after = det.predict(functions)[0]["ml_score"]
    assert score_after < score_initial, f"Score not suppressed: {score_after} >= {score_initial}"

def test_feedback_reinforces_confirmed_bug():
    det = Detector.load(ARTIFACTS_DIR)
    vuln_code = (
        "def run_custom_query():\n"
        "    u = request.args.get('u')\n"
        "    db.execute('SELECT * FROM t WHERE ' + u)\n"
    )
    functions = [{"code": vuln_code, "start_line": 1, "end_line": 3, "file_path": "query.py"}]
    score_initial = det.predict(functions)[0]["ml_score"]

    # Developer marks as fixed (true positive confirmed)
    res = det.feedback(code=vuln_code, status="fixed", func_name="run_custom_query")
    assert res["status"] == "fixed"
    assert res["reward"] > 0
    assert res["score_after"] >= res["score_before"]

    score_after = det.predict(functions)[0]["ml_score"]
    assert score_after >= score_initial

def test_rl_state_persistence():
    rl_state_file = ARTIFACTS_DIR / "rl_state.json"
    assert rl_state_file.exists()

    with open(rl_state_file, "r", encoding="utf-8") as f:
        state = json.load(f)

    assert "total_feedback_count" in state
    assert state["total_feedback_count"] > 0
    assert "weights" in state
    assert "recent_history" in state

    # Reload fresh detector instance and assert weights persist
    det_reloaded = Detector.load(ARTIFACTS_DIR)
    assert det_reloaded.feedback_learner.total_feedback_count == state["total_feedback_count"]

def test_feedback_mock_fallback(tmp_path):
    empty_dir = tmp_path / "empty_artifacts"
    empty_dir.mkdir()
    det_mock = Detector.load(empty_dir)
    assert det_mock.active_engine == "mock"

    res = det_mock.feedback(code="def foo(): pass", status="false_positive")
    assert res["reward"] == 0.0
    assert "ignored" in res["message"]
