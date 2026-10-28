"""
ZeroSentinel Detector Package.

Loads trained vulnerability detection models or falls back to a deterministic
hash dummy scorer. Implements the standard contract:
- Detector.load(path: str = "ml/artifacts") -> Detector
- Detector.predict(functions: List[Dict[str, Any]]) -> List[Dict[str, Any]]
"""

import hashlib
import json
import logging
from pathlib import Path
from typing import List, Dict, Any, Optional

import joblib
import numpy as np

from detector.tokenizer import tokenize_code

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

        # Target CWE list
        self.all_cwes = sorted(list(set(self.label_map.values())))

        # Attempt to load trained baseline artifacts
        self.vectorizer = None
        self.binary_model = None
        self.cwe_model = None
        self.positive_feature_weights: Dict[str, float] = {}
        self.is_loaded = False

        self._load_artifacts()

    def _load_artifacts(self):
        vec_path = self.artifacts_path / "tfidf_vectorizer.joblib"
        bin_path = self.artifacts_path / "binary_model.joblib"
        cwe_path = self.artifacts_path / "cwe_model.joblib"

        if vec_path.exists() and bin_path.exists() and cwe_path.exists():
            try:
                self.vectorizer = joblib.load(vec_path)
                self.binary_model = joblib.load(bin_path)
                self.cwe_model = joblib.load(cwe_path)

                # Precompute positive feature weights for line attribution
                feature_names = self.vectorizer.get_feature_names_out()
                coefs = self.binary_model.coef_[0]
                self.positive_feature_weights = {
                    feat: float(w) for feat, w in zip(feature_names, coefs) if w > 0
                }
                self.is_loaded = True
                logger.info(f"Detector successfully loaded trained artifacts from {self.artifacts_path}")
            except Exception as e:
                logger.warning(f"Failed to load artifacts from {self.artifacts_path} ({e}). Falling back to dummy mock.")
                self.is_loaded = False
        else:
            logger.info("Artifact files not found. Using deterministic hash dummy scorer.")
            self.is_loaded = False

    @staticmethod
    def _read_json(path: Path, fallback: dict) -> dict:
        if path.exists():
            with open(path, "r", encoding="utf-8") as f:
                return json.load(f)
        return fallback

    @classmethod
    def load(cls, path: str = "ml/artifacts") -> "Detector":
        return cls(Path(path))

    def _attribute_top_lines(self, code: str, start_line: int, end_line: int) -> List[int]:
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
            # Sum positive weights of tokens occurring on this line
            score = sum(self.positive_feature_weights.get(tok, 0.0) for tok in tokens)
            line_scores.append((abs_line, score))

        # Filter lines with positive risk evidence
        positive_lines = [item for item in line_scores if item[1] > 0]
        if positive_lines:
            # Sort descending by score
            positive_lines.sort(key=lambda x: x[1], reverse=True)
            top_k = [item[0] for item in positive_lines[:3]]
            return sorted(top_k)
        
        # If no positive tokens found, default to start_line
        return [start_line]

    def predict(self, functions: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        results = []
        cwe_list = self.all_cwes

        # Fast path if using deterministic hash dummy mock
        if not self.is_loaded:
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

        # Real ML prediction using trained artifacts
        codes = [fn.get("code", "") for fn in functions]
        X = self.vectorizer.transform(codes)

        # 1. Binary probabilities
        binary_probs = self.binary_model.predict_proba(X)[:, 1]

        # 2. CWE multiclass probabilities
        cwe_probs_matrix = self.cwe_model.predict_proba(X)
        cwe_classes = list(self.cwe_model.classes_)

        for idx, fn in enumerate(functions):
            code = fn.get("code", "")
            start = fn.get("start_line", 1)
            end = fn.get("end_line", start)

            score = round(float(binary_probs[idx]), 3)

            # Map raw model probabilities to full CWE dictionary
            cwe_raw_dict = {
                cls_name: float(cwe_probs_matrix[idx, i])
                for i, cls_name in enumerate(cwe_classes)
            }
            
            # Ensure every CWE from label_map is represented
            full_cwe_probs = {}
            for cwe in cwe_list:
                full_cwe_probs[cwe] = cwe_raw_dict.get(cwe, 0.001)

            # Normalize so probabilities sum to 1.0
            prob_sum = sum(full_cwe_probs.values())
            if prob_sum > 0:
                normalized_probs = {
                    k: round(v / prob_sum, 3)
                    for k, v in full_cwe_probs.items()
                }
            else:
                uniform_p = round(1.0 / len(cwe_list), 3)
                normalized_probs = {k: uniform_p for k in cwe_list}

            # Best guess is the CWE with the highest probability
            cwe_guess = max(normalized_probs, key=normalized_probs.get)

            # Compute top_lines
            top_lines = self._attribute_top_lines(code, start, end)

            results.append({
                "ml_score": score,
                "cwe_guess": cwe_guess,
                "cwe_probs": normalized_probs,
                "top_lines": top_lines
            })

        return results
