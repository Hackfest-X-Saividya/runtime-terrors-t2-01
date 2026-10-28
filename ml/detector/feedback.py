"""
Reinforcement Learning & Human-in-the-Loop Feedback Module for ZeroSentinel.

Implements an Online Contextual Bandit with Policy Gradient adaptation:
- Tracks feedback from triage actions ('fixed', 'confirmed', 'false_positive', 'accepted').
- Applies immediate reward/penalty gradient updates to online policy weights.
- Suppresses false positives dynamically on similar code patterns while reinforcing
  true positive detections.
- Persists RL state (weights, reward history, suppression counts) to `ml/artifacts/rl_state.json`
  using atomic file replacement and cross-process file locking.
- Dynamically derives vocabulary dimensions from vectorizer artifacts with automatic
  hash verification to prevent dimension drift.
"""

import contextlib
import hashlib
import json
import logging
import math
import os
import uuid
from pathlib import Path
from typing import Dict, Any, List, Optional
import numpy as np

logger = logging.getLogger(__name__)

# Standardized Reward Signals & Learning Semantics:
# - 'fixed' / 'confirmed': Legitimate vulnerability confirmed by human triage (+1.0). Reinforces detection policy.
# - 'false_positive': False alarm / benign code flagged in error (-1.5). Penalizes policy to suppress noise.
# - 'accepted': Legitimate vulnerability where business/team accepted the risk (0.0). Neutral reward;
#   must NOT be treated as a false positive or penalized.
# - 'open': Finding acknowledged as open issue (+0.5). Positive confirmation.
REWARD_MAP = {
    "fixed": 1.0,           # True positive confirmed / resolved by developer (+1.0)
    "confirmed": 1.0,       # Confirmed vulnerability (+1.0)
    "open": 0.5,            # Triage engineer acknowledged finding (+0.5)
    "accepted": 0.0,        # Business risk accepted; real finding, neutral reward (0.0, no suppression)
    "false_positive": -1.5  # False alarm; strong penalty to suppress noise (-1.5)
}


def compute_vocab_hash(vectorizer_or_features) -> str:
    """
    Computes a deterministic hash of vocabulary feature names to detect dimension
    or token vocabulary drift between training artifacts and RL feedback state.
    """
    if hasattr(vectorizer_or_features, "get_feature_names_out"):
        names = vectorizer_or_features.get_feature_names_out()
    elif hasattr(vectorizer_or_features, "vocabulary_"):
        names = sorted(vectorizer_or_features.vocabulary_.keys())
    elif isinstance(vectorizer_or_features, (list, tuple, np.ndarray)):
        names = vectorizer_or_features
    else:
        names = []
    content = "\n".join(str(n) for n in names).encode("utf-8")
    return hashlib.sha256(content).hexdigest()[:16]


@contextlib.contextmanager
def file_lock(lock_path: Path):
    """
    Context manager acquiring an exclusive file lock across processes and threads.
    Supports Windows (msvcrt) and Unix (fcntl).
    """
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    f = open(lock_path, "a+b")
    try:
        if os.name == "nt":
            import msvcrt
            f.seek(0)
            msvcrt.locking(f.fileno(), msvcrt.LK_LOCK, 1)
        else:
            import fcntl
            fcntl.flock(f.fileno(), fcntl.LOCK_EX)
        yield
    finally:
        try:
            if os.name == "nt":
                import msvcrt
                f.seek(0)
                msvcrt.locking(f.fileno(), msvcrt.LK_UNLCK, 1)
            else:
                import fcntl
                fcntl.flock(f.fileno(), fcntl.LOCK_UN)
        except Exception:
            pass
        f.close()


class FeedbackLearner:
    def __init__(
        self,
        vocab_size: int,
        learning_rate: float = 0.25,
        l2_reg: float = 0.0005,
        vocab_hash: Optional[str] = None
    ):
        self.vocab_size = int(vocab_size)
        self.learning_rate = learning_rate
        self.l2_reg = l2_reg
        self.vocab_hash = vocab_hash
        self.delta_weights = np.zeros(self.vocab_size, dtype=np.float32)

        self.total_feedback_count = 0
        self.false_positive_count = 0
        self.confirmed_count = 0
        self.history: List[Dict[str, Any]] = []

    def adjust_logit(self, X_sparse) -> float:
        """
        Computes the delta logit contribution from RL feedback weights for a single sample.
        """
        if self.delta_weights is None or X_sparse is None:
            return 0.0
        if len(self.delta_weights) != X_sparse.shape[1]:
            logger.warning(
                "FeedbackLearner weights dimension mismatch against sample shape (%d vs %d). Adjusting internal size.",
                len(self.delta_weights),
                X_sparse.shape[1],
            )
            self.vocab_size = X_sparse.shape[1]
            self.delta_weights = np.zeros(self.vocab_size, dtype=np.float32)
            return 0.0
        delta = float(X_sparse.dot(self.delta_weights)[0])
        return delta

    def adjust_score(self, base_score: float, X_sparse) -> float:
        """
        Applies learned policy delta to the base model probability via logit space:
        p_new = sigmoid(logit(base_score) + delta_w * X)
        """
        if base_score <= 0.001:
            base_score = 0.001
        elif base_score >= 0.999:
            base_score = 0.999

        base_logit = math.log(base_score / (1.0 - base_score))
        delta_logit = self.adjust_logit(X_sparse)
        new_logit = base_logit + delta_logit

        new_score = 1.0 / (1.0 + math.exp(-max(-15.0, min(15.0, new_logit))))
        return round(float(new_score), 3)

    def record_feedback(
        self,
        X_sparse,
        status: str,
        base_score: float,
        func_name: str = "unknown",
        cwe_id: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Updates the bandit policy using policy gradient step on received reward:
        - If confirmed / fixed (reward > 0): target = 1.0, error > 0, weights increase.
        - If false positive (reward < 0): target = 0.0, error < 0, weights decrease.
        - If accepted (reward == 0.0): neutral event, records audit entry without shifting weights.
        """
        normalized_status = status.strip().lower()
        reward = REWARD_MAP.get(normalized_status, 0.0)
        if self.delta_weights is None or len(self.delta_weights) != X_sparse.shape[1]:
            self.vocab_size = X_sparse.shape[1]
            self.delta_weights = np.zeros(self.vocab_size, dtype=np.float32)

        target = 1.0 if reward > 0 else 0.0
        current_score = self.adjust_score(base_score, X_sparse)

        if reward == 0.0:
            # Neutral feedback (e.g. 'accepted' risk or unknown status):
            # Record triage audit event but do not shift model weights
            self.total_feedback_count += 1
            entry = {
                "step": self.total_feedback_count,
                "func_name": func_name,
                "cwe_id": cwe_id,
                "status": normalized_status,
                "reward": 0.0,
                "score_before": current_score,
                "score_after": current_score,
                "score_delta": 0.0,
                "message": "Neutral feedback: policy weights unchanged.",
            }
            self.history.append(entry)
            if len(self.history) > 100:
                self.history.pop(0)
            return entry

        target = 1.0 if reward > 0 else 0.0
        error = target - current_score
        step_multiplier = abs(reward) * self.learning_rate

        indices = X_sparse.indices
        values = X_sparse.data

        for idx, val in zip(indices, values):
            if idx < self.vocab_size:
                update_step = step_multiplier * error * val
                self.delta_weights[idx] += update_step - (self.l2_reg * self.delta_weights[idx])

        new_score = self.adjust_score(base_score, X_sparse)

        self.total_feedback_count += 1
        if reward < 0:
            self.false_positive_count += 1
        elif reward > 0:
            self.confirmed_count += 1

        entry = {
            "step": self.total_feedback_count,
            "func_name": func_name,
            "cwe_id": cwe_id,
            "status": normalized_status,
            "reward": reward,
            "score_before": current_score,
            "score_after": new_score,
            "score_delta": round(new_score - current_score, 4)
        }
        self.history.append(entry)
        if len(self.history) > 100:
            self.history.pop(0)

        logger.info(
            f"RL Feedback processed for '{func_name}' (cwe={cwe_id}): status={normalized_status}, "
            f"reward={reward}, score: {current_score} -> {new_score}"
        )
        return entry

    def save(self, filepath: Path) -> bool:
        """
        Serializes RL state and weights to JSON using atomic temporary file
        replacement and cross-process file locking.
        Never leaves a corrupted or truncated target file if an interruption occurs.
        """
        state = {
            "vocab_size": self.vocab_size,
            "feature_count": self.vocab_size,
            "vocab_hash": self.vocab_hash,
            "learning_rate": self.learning_rate,
            "l2_reg": self.l2_reg,
            "total_feedback_count": self.total_feedback_count,
            "false_positive_count": self.false_positive_count,
            "confirmed_count": self.confirmed_count,
            "weights_non_zero_count": int(np.count_nonzero(self.delta_weights)),
            "weights": self.delta_weights.tolist(),
            "recent_history": self.history[-25:]
        }

        filepath = Path(filepath)
        lock_path = filepath.with_suffix(".lock")
        temp_path = filepath.parent / f".rl_state_{uuid.uuid4().hex}.tmp"

        try:
            filepath.parent.mkdir(parents=True, exist_ok=True)
            with file_lock(lock_path):
                # 1. Write state to temporary file on same filesystem
                with open(temp_path, "w", encoding="utf-8") as f:
                    json.dump(state, f, indent=2)
                    f.flush()
                    os.fsync(f.fileno())

                # 2. Atomic replacement of target file
                os.replace(temp_path, filepath)
            return True
        except Exception as exc:
            logger.warning("Could not atomically save RL feedback state to %s: %s", filepath, exc)
            if temp_path.exists():
                try:
                    temp_path.unlink()
                except Exception:
                    pass
            return False

    @classmethod
    def load(
        cls,
        filepath: Path,
        vocab_size: int,
        vocab_hash: Optional[str] = None
    ) -> "FeedbackLearner":
        """
        Loads RL state from JSON with cross-process locking, dimension verification, and corruption recovery.
        If feature counts or vocabulary hash differ from the vectorizer, logs a clear warning,
        reinitialises a clean state once, persists it, and returns the fresh learner.
        """
        filepath = Path(filepath)
        learner = cls(vocab_size=vocab_size, vocab_hash=vocab_hash)

        if not filepath.exists():
            logger.info("RL feedback state file not found at %s. Initializing fresh policy.", filepath)
            return learner

        lock_path = filepath.with_suffix(".lock")
        try:
            with file_lock(lock_path):
                with open(filepath, "r", encoding="utf-8") as f:
                    content = f.read()

                if not content.strip():
                    logger.warning("RL feedback state file at %s is empty. Initializing fresh policy.", filepath)
                    return learner
                state = json.loads(content)

            persisted_vocab_size = state.get("vocab_size") or state.get("feature_count")
            persisted_hash = state.get("vocab_hash")
            weights_list = state.get("weights", [])

            # Check if feature count or vocabulary hash differ
            dimension_mismatch = (persisted_vocab_size != vocab_size) or (len(weights_list) != vocab_size)
            hash_mismatch = bool(vocab_hash and persisted_hash and persisted_hash != vocab_hash)

            if dimension_mismatch or hash_mismatch:
                logger.warning(
                    "RL state vocabulary mismatch detected in %s: state has (vocab_size=%s, weights_len=%s, vocab_hash=%s) "
                    "vs expected (vocab_size=%d, vocab_hash=%s). Reinitialising clean policy once and saving state.",
                    filepath,
                    persisted_vocab_size,
                    len(weights_list),
                    persisted_hash,
                    vocab_size,
                    vocab_hash,
                )
                learner.save(filepath)
                return learner

            # Compatible state: populate weights and history
            learner.vocab_size = vocab_size
            learner.vocab_hash = persisted_hash or vocab_hash
            learner.learning_rate = state.get("learning_rate", 0.25)
            learner.l2_reg = state.get("l2_reg", 0.0005)
            learner.total_feedback_count = state.get("total_feedback_count", 0)
            learner.false_positive_count = state.get("false_positive_count", 0)
            learner.confirmed_count = state.get("confirmed_count", 0)
            learner.history = state.get("recent_history", [])
            learner.delta_weights = np.array(weights_list, dtype=np.float32)

            logger.info(
                "Loaded existing RL feedback state (%d features, hash=%s) with %d feedback cycles.",
                learner.vocab_size,
                learner.vocab_hash,
                learner.total_feedback_count
            )
        except Exception as exc:
            logger.warning(
                "Could not load RL feedback state from %s (%s). Falling back to fresh weights and persisting.",
                filepath,
                exc
            )
            learner = cls(vocab_size=vocab_size, vocab_hash=vocab_hash)
            try:
                learner.save(filepath)
            except Exception:
                pass

        return learner
