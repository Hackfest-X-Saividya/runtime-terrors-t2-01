import importlib
import logging
import os
import re
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

from app.core.config import settings

logger = logging.getLogger("zerosentinel.ml_detector")


class MLDetectorStub:
    """
    Deterministic heuristic stub when Member 3's ML detector package
    or trained artifacts are not available in the execution environment.
    Transparently flagged with is_stub=True; never claims mock scores are trained weights.
    """

    HEURISTIC_RULES = [
        (
            re.compile(r"pickle\.(loads|load)|_pickle\.(loads|load)", re.IGNORECASE),
            "CWE-502",
            0.94,
            {"CWE-502": 0.94, "CWE-89": 0.03, "CWE-79": 0.01},
        ),
        (
            re.compile(r"(cursor|db|connection)\.execute\s*\(.*(%s|format|f\"|f')", re.IGNORECASE),
            "CWE-89",
            0.88,
            {"CWE-89": 0.88, "CWE-78": 0.06, "CWE-79": 0.04},
        ),
        (
            re.compile(r"subprocess\.(run|Popen|call|check_output)\s*\(.*shell\s*=\s*True", re.IGNORECASE),
            "CWE-78",
            0.90,
            {"CWE-78": 0.90, "CWE-89": 0.05, "CWE-94": 0.03},
        ),
        (
            re.compile(r"os\.(system|popen)", re.IGNORECASE),
            "CWE-78",
            0.85,
            {"CWE-78": 0.85, "CWE-89": 0.08, "CWE-502": 0.05},
        ),
        (
            re.compile(r"(eval|exec)\s*\(", re.IGNORECASE),
            "CWE-94",
            0.92,
            {"CWE-94": 0.92, "CWE-78": 0.05, "CWE-502": 0.03},
        ),
        (
            re.compile(r"render_template_string\s*\(", re.IGNORECASE),
            "CWE-79",
            0.80,
            {"CWE-79": 0.80, "CWE-89": 0.10, "CWE-352": 0.05},
        ),
    ]

    def predict(self, functions: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        results: List[Dict[str, Any]] = []

        for fn in functions:
            code = fn.get("code", "")
            start_line = fn.get("start_line", 1)
            end_line = fn.get("end_line", start_line)

            matched_cwe: Optional[str] = None
            matched_score: float = 0.12
            matched_probs: Dict[str, float] = {}
            top_lines: List[int] = [start_line]

            lines = code.splitlines()
            for idx, line_text in enumerate(lines):
                line_no = start_line + idx
                for pattern, cwe, score, probs in self.HEURISTIC_RULES:
                    if pattern.search(line_text):
                        matched_cwe = cwe
                        matched_score = score
                        matched_probs = probs
                        top_lines = [line_no]
                        break
                if matched_cwe:
                    break

            results.append({
                "ml_score": matched_score,
                "cwe_guess": matched_cwe,
                "cwe_probs": matched_probs,
                "top_lines": top_lines,
            })

        return results


class MLDetectorService:
    """
    Adapter adhering to CONTRACT.md and PROJECT_CONTEXT.md.
    Loads Member 3's detector (from detector import Detector) if present,
    otherwise falls back to MLDetectorStub with explicit status tracking.
    """

    def __init__(self, artifacts_path: Optional[str] = None):
        self.artifacts_path = artifacts_path or settings.ML_ARTIFACTS_PATH
        self.device = "cpu"
        self._detector: Any = None
        self.is_stub: bool = True
        self.artifacts_present: bool = False
        self.status: str = "stub_fallback"
        self.model_name: str = "ZeroSentinel Heuristic Stub"
        self.version: str = "stub-v0.1.0"

        self._initialize()

    def _initialize(self) -> None:
        path = Path(self.artifacts_path)
        # Check if artifacts exist
        if path.exists() and path.is_dir() and any(path.iterdir()):
            self.artifacts_present = True
        else:
            self.artifacts_present = False

        # Attempt to import Detector
        detector_cls = None
        try:
            from detector import Detector
            detector_cls = Detector
        except ImportError:
            # Check if ml or ml/detector is locally available in workspace
            repo_root = Path.cwd()
            candidate_paths = [repo_root / "ml", repo_root]
            for c_path in candidate_paths:
                if c_path.exists() and str(c_path) not in sys.path:
                    sys.path.insert(0, str(c_path))
            try:
                from detector import Detector
                detector_cls = Detector
            except ImportError:
                detector_cls = None

        if detector_cls is not None and self.artifacts_present:
            try:
                logger.info("Loading ML detector from %s...", self.artifacts_path)
                self._detector = detector_cls.load(self.artifacts_path)
                self.is_stub = False
                self.status = "ready"
                self.model_name = "ZeroSentinel CodeBERT Detector"
                self.version = "0.1.0"
                logger.info("ML detector loaded successfully.")
                return
            except Exception as exc:
                logger.warning(
                    "[ML_STUB] Failed to load detector from %s (%s). Falling back to stub.",
                    self.artifacts_path,
                    exc,
                )
                self._detector = MLDetectorStub()
                self.is_stub = True
                self.status = "load_failed"
                self.model_name = "ZeroSentinel Heuristic Stub"
                self.version = "stub-v0.1.0"
                return

        # Artifacts missing or detector not importable
        if self.artifacts_present:
            self.status = "load_failed"
        else:
            self.status = "stub_fallback"

        self._detector = MLDetectorStub()
        self.is_stub = True
        self.model_name = "ZeroSentinel Heuristic Stub"
        self.version = "stub-v0.1.0"
        logger.warning(
            "[ML_STUB] ML detector artifacts or package unavailable (status=%s). Fallback stub active.",
            self.status,
        )

    def predict(self, functions: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        if not functions:
            return []
        return self._detector.predict(functions)

    def get_runtime_info(self) -> Dict[str, Any]:
        return {
            "model_name": self.model_name,
            "version": self.version,
            "is_stub": self.is_stub,
            "artifacts_present": self.artifacts_present,
            "artifacts_path": self.artifacts_path,
            "device": self.device,
            "status": self.status,
        }


# Singleton service instance
ml_service = MLDetectorService()
