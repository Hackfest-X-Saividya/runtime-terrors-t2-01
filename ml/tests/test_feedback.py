"""
Unit Tests for ZeroSentinel Reinforcement Learning Feedback Module.

Verifies:
1. `det.feedback(code, status="false_positive")` applies negative reward and
   suppresses subsequent vulnerability score on that pattern.
2. `det.feedback(code, status="fixed")` applies positive reward and reinforces
   detection score.
3. `det.feedback(code, status="accepted")` applies neutral reward (0.0) without
   falsely suppressing genuine findings.
4. `cwe_id` keyword argument is supported and recorded in history.
5. Atomic state persistence to `rl_state.json` across reloads and cross-process locking.
6. Safe handling and recovery under concurrent writes.
7. Safe recovery when state file is missing, empty, or corrupted.
8. Safe handling when operating in mock mode without artifacts.
"""

import concurrent.futures
import json
from pathlib import Path
import pytest
from detector import Detector
from detector.feedback import FeedbackLearner

ARTIFACTS_DIR = Path(__file__).resolve().parent.parent / "artifacts"

SAMPLE_CODE = (
    "def custom_template_builder(name: str):\n"
    "    # Complex formatting that might trigger false alarm in internal tool\n"
    "    return f'Hello, {name}!'\n"
)


def test_feedback_suppresses_false_positive():
    det = Detector.load(ARTIFACTS_DIR)
    assert det.is_loaded is True

    # 1. Score before feedback
    functions = [{"code": SAMPLE_CODE, "start_line": 1, "end_line": 3, "file_path": "builder.py"}]
    score_initial = det.predict(functions)[0]["ml_score"]

    # 2. Analyst marks finding as false positive
    res = det.feedback(
        code=SAMPLE_CODE,
        status="false_positive",
        func_name="custom_template_builder",
        cwe_id="CWE-79",
    )
    assert res["status"] == "false_positive"
    assert res["reward"] < 0
    assert res["score_after"] < res["score_before"]
    assert res.get("cwe_id") == "CWE-79"

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
    res = det.feedback(code=vuln_code, status="fixed", func_name="run_custom_query", cwe_id="CWE-89")
    assert res["status"] == "fixed"
    assert res["reward"] > 0
    assert res["score_after"] >= res["score_before"]
    assert res.get("cwe_id") == "CWE-89"

    score_after = det.predict(functions)[0]["ml_score"]
    assert score_after >= score_initial


def test_feedback_accepted_neutral_no_suppression():
    """Verify that 'accepted' risk is neutral (0.0 reward) and does NOT suppress detection score."""
    det = Detector.load(ARTIFACTS_DIR)
    accepted_code = (
        "def admin_debug_tool(cmd):\n"
        "    # Intentionally permitted internal tool with accepted risk\n"
        "    os.system(cmd)\n"
    )
    functions = [{"code": accepted_code, "start_line": 1, "end_line": 3, "file_path": "admin.py"}]
    score_initial = det.predict(functions)[0]["ml_score"]

    res = det.feedback(code=accepted_code, status="accepted", func_name="admin_debug_tool", cwe_id="CWE-78")
    assert res["status"] == "accepted"
    assert res["reward"] == 0.0
    assert res["score_after"] == res["score_before"]
    assert "neutral" in res.get("message", "").lower()

    score_after = det.predict(functions)[0]["ml_score"]
    assert score_after == score_initial, "Accepted risk should not suppress subsequent detection score"


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


def test_feedback_concurrent_writes(tmp_path):
    """Verify that multiple concurrent threads saving RL state do not corrupt the file."""
    state_file = tmp_path / "test_rl_state.json"
    learner = FeedbackLearner(vocab_size=100)

    def write_worker(idx):
        learner.total_feedback_count += 1
        learner.delta_weights[idx % 100] += 0.05
        return learner.save(state_file)

    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as executor:
        futures = [executor.submit(write_worker, i) for i in range(20)]
        results = [f.result() for f in concurrent.futures.as_completed(futures)]

    assert all(r is True for r in results)
    assert state_file.exists()

    # Verify state file parses cleanly
    with open(state_file, "r", encoding="utf-8") as f:
        data = json.load(f)
    assert data["vocab_size"] == 100
    assert len(data["weights"]) == 100

    # Verify reloading re-populates state cleanly
    loaded = FeedbackLearner.load(state_file, vocab_size=100)
    assert loaded.vocab_size == 100
    assert len(loaded.delta_weights) == 100


def test_feedback_corrupted_state_recovery(tmp_path):
    """Verify that a corrupted or truncated JSON state file is safely recovered with fresh policy."""
    corrupted_file = tmp_path / "corrupted_state.json"
    corrupted_file.write_text("{\"total_feedback_count\": 42, \"weights\": [INCOMPLETE_JSON_TRUNCATED", encoding="utf-8")

    # Load should log warning and return fresh learner without crashing
    learner = FeedbackLearner.load(corrupted_file, vocab_size=50)
    assert learner.total_feedback_count == 0
    assert len(learner.delta_weights) == 50


def test_feedback_empty_state_recovery(tmp_path):
    """Verify that an empty (0-byte) state file initializes a clean fresh learner."""
    empty_file = tmp_path / "empty_state.json"
    empty_file.write_text("", encoding="utf-8")

    learner = FeedbackLearner.load(empty_file, vocab_size=50)
    assert learner.total_feedback_count == 0
    assert len(learner.delta_weights) == 50


def test_feedback_missing_state_initializes(tmp_path):
    """Verify missing state file initializes a clean fresh learner."""
    missing_file = tmp_path / "nonexistent_state.json"
    learner = FeedbackLearner.load(missing_file, vocab_size=50)
    assert learner.total_feedback_count == 0
    assert len(learner.delta_weights) == 50


def test_feedback_mock_fallback(tmp_path):
    empty_dir = tmp_path / "empty_artifacts"
    empty_dir.mkdir()
    det_mock = Detector.load(empty_dir)
    assert det_mock.active_engine == "mock"

    res = det_mock.feedback(code="def foo(): pass", status="false_positive", cwe_id="CWE-89")
    assert res["reward"] == 0.0
    assert "ignored" in res["message"]
