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
9. Persistence and reload test after 3 false-positive feedback events.
10. Automatic reinitialisation and saving when vocabulary dimensions or hash drift.
"""

import concurrent.futures
import json
from pathlib import Path
import numpy as np
import pytest
from detector import Detector
from detector.feedback import FeedbackLearner, compute_vocab_hash

ARTIFACTS_DIR = Path(__file__).resolve().parent.parent / "artifacts"


@pytest.fixture(autouse=True)
def preserve_rl_state_artifact():
    """Ensures test runs do not permanently alter the production artifact rl_state.json."""
    rl_file = ARTIFACTS_DIR / "rl_state.json"
    lock_file = ARTIFACTS_DIR / "rl_state.lock"
    orig = rl_file.read_text(encoding="utf-8") if rl_file.exists() else None
    yield
    if orig is not None:
        rl_file.write_text(orig, encoding="utf-8")
    elif rl_file.exists():
        try:
            rl_file.unlink()
        except Exception:
            pass
    if lock_file.exists():
        try:
            lock_file.unlink()
        except Exception:
            pass


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
    det = Detector.load(ARTIFACTS_DIR)
    assert det.is_loaded is True

    # Apply a feedback event to create / update state
    det.feedback(
        code=SAMPLE_CODE,
        status="false_positive",
        func_name="persist_test_builder",
        cwe_id="CWE-79"
    )

    rl_state_file = ARTIFACTS_DIR / "rl_state.json"
    assert rl_state_file.exists()

    with open(rl_state_file, "r", encoding="utf-8") as f:
        state = json.load(f)

    assert "total_feedback_count" in state
    assert state["total_feedback_count"] > 0
    assert "weights" in state
    assert "recent_history" in state
    assert "vocab_hash" in state

    # Reload fresh detector instance and assert weights persist
    det_reloaded = Detector.load(ARTIFACTS_DIR)
    assert det_reloaded.feedback_learner.total_feedback_count == state["total_feedback_count"]
    assert det_reloaded.feedback_learner.vocab_size == len(det.vectorizer.get_feature_names_out())


def test_train_vectorizer_feedback_persist_and_reload(tmp_path):
    """
    Verifies that:
    1. A fresh vectorizer is trained.
    2. 3 false-positive feedback events are recorded.
    3. The policy state is saved to disk.
    4. Upon reload, weights persist and the scores of those findings remain lowered.
    """
    from sklearn.feature_extraction.text import TfidfVectorizer
    from detector.tokenizer import tokenize_code

    corpus = [
        "def custom_template_builder(name: str):\n    return f'Hello, {name}!'\n",
        "def run_sql_query(user_id: int):\n    return f'SELECT * FROM users WHERE id = {user_id}'\n",
        "def execute_task(cmd: str):\n    return f'Running {cmd}'\n",
        "def calculate_total(prices: list):\n    return sum(prices)\n"
    ]
    vec = TfidfVectorizer(tokenizer=tokenize_code, token_pattern=None, ngram_range=(1, 2))
    vec.fit(corpus)
    feature_names = vec.get_feature_names_out()
    vocab_size = len(feature_names)
    vocab_hash = compute_vocab_hash(feature_names)

    state_file = tmp_path / "rl_state.json"
    learner = FeedbackLearner(vocab_size=vocab_size, vocab_hash=vocab_hash)

    snippets = corpus[:3]
    base_score = 0.85
    initial_scores = []
    for snip in snippets:
        X_snip = vec.transform([snip])[0]
        initial_scores.append(learner.adjust_score(base_score, X_snip))

    # Apply 3 false-positive feedback events
    for idx, snip in enumerate(snippets):
        X_snip = vec.transform([snip])[0]
        learner.record_feedback(
            X_sparse=X_snip,
            status="false_positive",
            base_score=base_score,
            func_name=f"test_func_{idx}",
            cwe_id="CWE-79"
        )

    # Verify state saved
    assert learner.save(state_file) is True
    assert state_file.exists()

    # Reload fresh instance
    reloaded = FeedbackLearner.load(state_file, vocab_size=vocab_size, vocab_hash=vocab_hash)
    assert reloaded.total_feedback_count == 3
    assert reloaded.false_positive_count == 3
    assert reloaded.vocab_size == vocab_size
    assert reloaded.vocab_hash == vocab_hash
    assert np.count_nonzero(reloaded.delta_weights) > 0

    # Weights persist and the scores of those findings stay lowered
    for idx, snip in enumerate(snippets):
        X_snip = vec.transform([snip])[0]
        reloaded_score = reloaded.adjust_score(base_score, X_snip)
        assert reloaded_score < initial_scores[idx], (
            f"Finding {idx} score not lowered: reloaded={reloaded_score} >= initial={initial_scores[idx]}"
        )


def test_feedback_vocabulary_mismatch_reinitialises(tmp_path):
    """
    Verifies that when vocabulary size or hash differs from vectorizer,
    FeedbackLearner logs a warning, reinitialises clean weights once, and saves state.
    """
    state_file = tmp_path / "rl_state.json"
    learner = FeedbackLearner(vocab_size=100, vocab_hash="old_hash_123")
    learner.total_feedback_count = 5
    learner.false_positive_count = 5
    learner.delta_weights[10] = -0.75
    assert learner.save(state_file) is True

    # Load with mismatched dimension and hash
    reloaded = FeedbackLearner.load(state_file, vocab_size=150, vocab_hash="new_hash_456")
    assert reloaded.vocab_size == 150
    assert reloaded.vocab_hash == "new_hash_456"
    assert reloaded.total_feedback_count == 0
    assert len(reloaded.delta_weights) == 150
    assert np.all(reloaded.delta_weights == 0.0)

    # Verify the clean reinitialised state was persisted to file
    with open(state_file, "r", encoding="utf-8") as f:
        persisted = json.load(f)
    assert persisted["vocab_size"] == 150
    assert persisted["vocab_hash"] == "new_hash_456"
    assert persisted["total_feedback_count"] == 0


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
