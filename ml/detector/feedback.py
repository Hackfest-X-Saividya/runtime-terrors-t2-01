"""
Reinforcement Learning & Human-in-the-Loop Feedback Module for ZeroSentinel.

Implements an Online Contextual Bandit with Policy Gradient adaptation:
- Tracks feedback from triage actions ('fixed', 'false_positive', 'accepted').
- Applies immediate reward/penalty gradient updates to online policy weights.
- Suppresses false positives dynamically on similar code patterns while reinforcing
  true positive detections.
- Persists RL state (weights, reward history, suppression counts) to `ml/artifacts/rl_state.json`.
"""

import json
import logging
import math
from pathlib import Path
from typing import Dict, Any, List, Optional
import numpy as np

logger = logging.getLogger(__name__)

# Standardized Reward Signals
REWARD_MAP = {
    "fixed": 1.0,           # True positive confirmed by developer
    "confirmed": 1.0,       # Confirmed vulnerability
    "open": 0.5,            # Triage engineer accepted finding as legitimate
    "accepted": -0.3,       # Accepted risk / low priority
    "false_positive": -1.5  # False alarm; strong penalty to suppress noise
}

class FeedbackLearner:
    def __init__(self, vocab_size: int = 2416, learning_rate: float = 0.25, l2_reg: float = 0.0005):
        self.vocab_size = vocab_size
        self.learning_rate = learning_rate
        self.l2_reg = l2_reg
        self.delta_weights = np.zeros(vocab_size, dtype=np.float32)
        
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
        func_name: str = "unknown"
    ) -> Dict[str, Any]:
        """
        Updates the bandit policy using policy gradient step on received reward:
        - If confirmed / fixed (reward > 0): target = 1.0, error > 0, weights increase.
        - If false positive (reward < 0): target = 0.0, error < 0, weights decrease.
        """
        normalized_status = status.strip().lower()
        reward = REWARD_MAP.get(normalized_status, 0.0)
        
        target = 1.0 if reward > 0 else 0.0
        current_score = self.adjust_score(base_score, X_sparse)
        
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
            f"RL Feedback processed for '{func_name}': status={normalized_status}, "
            f"reward={reward}, score: {current_score} -> {new_score}"
        )
        return entry

    def save(self, filepath: Path):
        """Serializes RL state and weights to JSON."""
        state = {
            "vocab_size": self.vocab_size,
            "learning_rate": self.learning_rate,
            "l2_reg": self.l2_reg,
            "total_feedback_count": self.total_feedback_count,
            "false_positive_count": self.false_positive_count,
            "confirmed_count": self.confirmed_count,
            "weights_non_zero_count": int(np.count_nonzero(self.delta_weights)),
            "weights": self.delta_weights.tolist(),
            "recent_history": self.history[-10:]
        }
        filepath.parent.mkdir(parents=True, exist_ok=True)
        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(state, f, indent=2)

    @classmethod
    def load(cls, filepath: Path, vocab_size: int = 2416) -> "FeedbackLearner":
        learner = cls(vocab_size=vocab_size)
        if filepath.exists():
            try:
                with open(filepath, "r", encoding="utf-8") as f:
                    state = json.load(f)
                learner.vocab_size = state.get("vocab_size", vocab_size)
                learner.learning_rate = state.get("learning_rate", 0.25)
                learner.l2_reg = state.get("l2_reg", 0.0005)
                learner.total_feedback_count = state.get("total_feedback_count", 0)
                learner.false_positive_count = state.get("false_positive_count", 0)
                learner.confirmed_count = state.get("confirmed_count", 0)
                learner.history = state.get("recent_history", [])
                
                weights_list = state.get("weights", [])
                if weights_list and len(weights_list) == learner.vocab_size:
                    learner.delta_weights = np.array(weights_list, dtype=np.float32)
                logger.info(f"Loaded existing RL feedback state with {learner.total_feedback_count} feedback cycles.")
            except Exception as e:
                logger.warning(f"Could not load RL feedback state ({e}). Initializing fresh weights.")
        return learner
