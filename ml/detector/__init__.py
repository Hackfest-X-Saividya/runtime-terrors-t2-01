"""
ZeroSentinel Detector Package.

Loads trained vulnerability detection models or falls back to a deterministic
hash dummy scorer. Implements the standard contract:
- Detector.load(path: str = "ml/artifacts") -> Detector
- Detector.predict(functions: List[Dict[str, Any]]) -> List[Dict[str, Any]]
- Detector.feedback(code: str, status: str, func_name: str) -> Dict[str, Any]

Supports 3-tier progressive enhancement with Online Reinforcement Learning:
  Tier 1: Deep Learning (CodeBERT) if fine-tuned weights exist and torch is available.
  Tier 2: TF-IDF Baseline (Linear classifier with token-level line attribution).
  Tier 3: Deterministic hash dummy scorer (fallback when no artifacts are present).
  Adaptive Layer: Real-time Contextual Bandit policy feedback from user triage actions.
"""

import hashlib
import json
import logging
from pathlib import Path
from typing import List, Dict, Any, Optional

import joblib
import numpy as np

from detector.tokenizer import tokenize_code
from detector.feedback import FeedbackLearner

logger = logging.getLogger(__name__)

class Detector:
    def __init__(self, artifacts_path: Path):
        self.artifacts_path = Path(artifacts_path)

        self.label_map = self._read_json(
            self.artifacts_path / "label_map.json",
            {
                "sql": "CWE-89",
                "xss": "CWE-79",
                "command_injection": "CWE-78",
                "xsrf": "CWE-352",
                "remote_code_execution": "CWE-94",
                "path_disclosure": "CWE-22",
                "open_redirect": "CWE-601"
            }
        )
        self.thresholds = self._read_json(
            self.artifacts_path / "thresholds.json",
            {"default_threshold": 0.50}
        )

        self.all_cwes = sorted(list(set(self.label_map.values())))
        self.active_engine = "mock"  # "codebert" | "baseline" | "mock"
        self.is_loaded = False

        # Baseline components
        self.vectorizer = None
        self.binary_model = None
        self.cwe_model = None
        self.positive_feature_weights: Dict[str, float] = {}

        # Reinforcement Learning feedback component
        self.feedback_learner: Optional[FeedbackLearner] = None

        # CodeBERT components
        self.codebert_pipeline = None

        self._load_artifacts()

    def _load_artifacts(self):
        # 1. Check for CodeBERT artifacts first (Tier 1)
        codebert_dir = self.artifacts_path / "codebert" if (self.artifacts_path / "codebert").exists() else self.artifacts_path
        codebert_weights = codebert_dir / "codebert_model.pt"
        if not codebert_weights.exists():
            codebert_weights = codebert_dir / "pytorch_model.bin"

        if codebert_weights.exists():
            try:
                import torch
                from train_codebert import CodeBertPipeline
                pipeline = CodeBertPipeline(
                    model_name=str(codebert_dir),
                    num_cwes=len(self.all_cwes),
                    device="cuda" if torch.cuda.is_available() else "cpu"
                )
                if pipeline.initialize_model():
                    self.codebert_pipeline = pipeline
                    self.active_engine = "codebert"
                    self.is_loaded = True
                    logger.info(f"Detector successfully loaded CodeBERT deep learning engine from {codebert_dir}")
                    return
            except Exception as e:
                logger.warning(f"Could not initialize CodeBERT ({e}). Falling back to baseline.")

        # 2. Check for TF-IDF Baseline artifacts (Tier 2)
        vec_path = self.artifacts_path / "tfidf_vectorizer.joblib"
        bin_path = self.artifacts_path / "binary_model.joblib"
        cwe_path = self.artifacts_path / "cwe_model.joblib"

        if vec_path.exists() and bin_path.exists() and cwe_path.exists():
            try:
                self.vectorizer = joblib.load(vec_path)
                self.binary_model = joblib.load(bin_path)
                self.cwe_model = joblib.load(cwe_path)

                vocab_size = len(self.vectorizer.vocabulary_)
                feature_names = self.vectorizer.get_feature_names_out()
                coefs = self.binary_model.coef_[0]
                self.positive_feature_weights = {
                    feat: float(w) for feat, w in zip(feature_names, coefs) if w > 0
                }

                # Initialize / load RL feedback state
                rl_state_file = self.artifacts_path / "rl_state.json"
                self.feedback_learner = FeedbackLearner.load(rl_state_file, vocab_size=vocab_size)

                self.active_engine = "baseline"
                self.is_loaded = True
                logger.info(f"Detector successfully loaded TF-IDF baseline artifacts from {self.artifacts_path}")
                return
            except Exception as e:
                logger.warning(f"Failed to load baseline artifacts ({e}). Falling back to dummy mock.")

        # 3. Fallback to deterministic hash mock (Tier 3)
        self.active_engine = "mock"
        self.is_loaded = False
        logger.info("Artifact files not found. Using deterministic hash dummy scorer.")

    @staticmethod
    def _read_json(path: Path, fallback: dict) -> dict:
        if path.exists():
            with open(path, "r", encoding="utf-8") as f:
                return json.load(f)
        return fallback

    @classmethod
    def load(cls, path: str = "ml/artifacts") -> "Detector":
        p = Path(path)
        if not p.is_absolute() and not p.exists():
            # Automatically resolve relative to the detector package location
            pkg_artifacts = Path(__file__).resolve().parent.parent / "artifacts"
            if pkg_artifacts.exists():
                return cls(pkg_artifacts)
            # Or relative to repo root
            repo_artifacts = Path(__file__).resolve().parent.parent.parent / "ml" / "artifacts"
            if repo_artifacts.exists():
                return cls(repo_artifacts)
        return cls(p)

    def _attribute_baseline_lines(self, code: str, start_line: int, end_line: int) -> List[int]:
        """
        Pinpoints up to 3 highest-risk absolute line numbers by scoring individual
        lines against the highest-weighted TF-IDF vulnerability tokens.
        """
        lines = code.splitlines()
        if not lines:
            return [start_line]

        line_scores = []
        for idx, line_text in enumerate(lines):
            abs_line = start_line + idx
            if abs_line > end_line:
                break
            tokens = tokenize_code(line_text)
            score = sum(self.positive_feature_weights.get(tok, 0.0) for tok in tokens)
            line_scores.append((abs_line, score))

        positive_lines = [item for item in line_scores if item[1] > 0]
        if positive_lines:
            positive_lines.sort(key=lambda x: x[1], reverse=True)
            top_k = [item[0] for item in positive_lines[:3]]
            return sorted(top_k)

        return [start_line]

    def feedback(
        self,
        code: str,
        status: str,
        cwe_id: Optional[str] = None,
        func_name: str = "unknown"
    ) -> Dict[str, Any]:
        """
        Reinforcement Learning Feedback Hook:
        Accepts triage decisions ('fixed', 'confirmed', 'false_positive', 'accepted')
        and updates the policy gradient weights in real-time.
        """
        if not self.is_loaded or self.vectorizer is None or self.feedback_learner is None:
            return {
                "status": status,
                "reward": 0.0,
                "message": "Feedback ignored: running on mock engine without trainable artifacts."
            }

        X = self.vectorizer.transform([code])
        base_score = float(self.binary_model.predict_proba(X)[0, 1])

        feedback_record = self.feedback_learner.record_feedback(
            X_sparse=X[0],
            status=status,
            base_score=base_score,
            func_name=func_name,
            cwe_id=cwe_id
        )

        # Persist updated RL state atomically
        rl_state_file = self.artifacts_path / "rl_state.json"
        persisted = self.feedback_learner.save(rl_state_file)
        feedback_record["persisted"] = persisted

        return feedback_record

    def predict(self, functions: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        results = []
        cwe_list = self.all_cwes

        # Path 1: Deterministic hash mock
        if self.active_engine == "mock":
            for fn in functions:
                code = fn.get("code", "")
                start = fn.get("start_line", 1)
                end = fn.get("end_line", start)

                digest = hashlib.md5(code.encode("utf-8")).hexdigest()
                num = int(digest, 16)
                score = round((num % 1000) / 1000.0, 3)
                cwe_choice = cwe_list[num % len(cwe_list)]

                span = max(1, end - start + 1)
                flagged_line = start + (num % span)

                results.append({
                    "ml_score": score,
                    "cwe_guess": cwe_choice,
                    "cwe_probs": {
                        cwe: round(1.0 / len(cwe_list), 3)
                        for cwe in cwe_list
                    },
                    "top_lines": [flagged_line]
                })
            return results

        # Path 2: CodeBERT Deep Learning Engine
        if self.active_engine == "codebert" and self.codebert_pipeline:
            for fn in functions:
                code = fn.get("code", "")
                start = fn.get("start_line", 1)
                end = fn.get("end_line", start)

                score, cwe_probs_raw = self.codebert_pipeline.predict_function_with_sliding_window(code)
                score = round(float(score), 3)

                cwe_probs = {
                    cwe: round(float(p), 3) for cwe, p in zip(cwe_list, cwe_probs_raw)
                }
                cwe_guess = max(cwe_probs, key=cwe_probs.get)

                thresh = float(self.thresholds.get("default_threshold", 0.50))
                if score >= thresh:
                    top_lines = self.codebert_pipeline.compute_line_occlusion(code, start, end)
                else:
                    top_lines = [start]

                results.append({
                    "ml_score": score,
                    "cwe_guess": cwe_guess,
                    "cwe_probs": cwe_probs,
                    "top_lines": top_lines
                })
            return results

        # Path 3: TF-IDF Baseline Engine + RL Feedback Policy Adaptation
        codes = [fn.get("code", "") for fn in functions]
        X = self.vectorizer.transform(codes)

        binary_probs = self.binary_model.predict_proba(X)[:, 1]
        cwe_probs_matrix = self.cwe_model.predict_proba(X)
        cwe_classes = list(self.cwe_model.classes_)

        for idx, fn in enumerate(functions):
            code = fn.get("code", "")
            start = fn.get("start_line", 1)
            end = fn.get("end_line", start)

            base_score = float(binary_probs[idx])

            # Apply online RL contextual bandit adjustment if available
            if self.feedback_learner:
                score = self.feedback_learner.adjust_score(base_score, X[idx])
            else:
                score = round(base_score, 3)

            cwe_raw_dict = {
                cls_name: float(cwe_probs_matrix[idx, i])
                for i, cls_name in enumerate(cwe_classes)
            }

            full_cwe_probs = {}
            for cwe in cwe_list:
                full_cwe_probs[cwe] = cwe_raw_dict.get(cwe, 0.001)

            prob_sum = sum(full_cwe_probs.values())
            if prob_sum > 0:
                normalized_probs = {
                    k: round(v / prob_sum, 3)
                    for k, v in full_cwe_probs.items()
                }
            else:
                uniform_p = round(1.0 / len(cwe_list), 3)
                normalized_probs = {k: uniform_p for k in cwe_list}

            cwe_guess = max(normalized_probs, key=normalized_probs.get)
            top_lines = self._attribute_baseline_lines(code, start, end)

            results.append({
                "ml_score": score,
                "cwe_guess": cwe_guess,
                "cwe_probs": normalized_probs,
                "top_lines": top_lines
            })

        return results
