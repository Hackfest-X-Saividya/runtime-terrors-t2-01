import asyncio
import importlib
import logging
import os
import re
import sys
import threading
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

    def feedback(
        self,
        code: str,
        status: str,
        func_name: str = "unknown",
        cwe_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Deterministic stub implementation of feedback learning.
        Returns explicit non-learning response; never pretends mock heuristics adapt.
        """
        return {
            "status": status,
            "reward": 0.0,
            "applied": False,
            "message": "Feedback ignored: running on heuristic stub without trainable artifacts.",
        }


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
        self._lock = threading.Lock()
        self.is_stub: bool = True
        self.artifacts_present: bool = False
        self.status: str = "stub_fallback"
        self.model_name: str = "ZeroSentinel Heuristic Stub"
        self.version: str = "stub-v0.1.0"
        self.feedback_supported: bool = False

        self._initialize()

    def _initialize(self) -> None:
        path = Path(self.artifacts_path)
        if not path.is_absolute() and not path.exists():
            repo_root = Path(__file__).resolve().parents[3]
            if (repo_root / self.artifacts_path).exists():
                path = repo_root / self.artifacts_path

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
            file_root = Path(__file__).resolve().parents[3]
            candidate_paths = [repo_root / "ml", repo_root, file_root / "ml", file_root]
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
                logger.info("Loading ML detector from %s...", path)
                loaded_det = detector_cls.load(path)
                if hasattr(loaded_det, "is_loaded") and not loaded_det.is_loaded:
                    logger.warning("[ML_STUB] Detector reported is_loaded=False. Falling back to stub.")
                    self._detector = MLDetectorStub()
                    self.is_stub = True
                    self.status = "load_failed"
                    self.model_name = "ZeroSentinel Heuristic Stub"
                    self.version = "stub-v0.1.0"
                    self.feedback_supported = False
                    return

                self._detector = loaded_det
                self.is_stub = False
                self.status = "ready"
                self.model_name = "ZeroSentinel Dual-Engine Vulnerability Detector" if getattr(self._detector, "active_engine", "") != "codebert" else "ZeroSentinel CodeBERT Detector"
                self.version = "0.1.0"
                self.feedback_supported = hasattr(self._detector, "feedback") and callable(getattr(self._detector, "feedback"))
                logger.info("ML detector loaded successfully (feedback_supported=%s).", self.feedback_supported)
                return
            except Exception as exc:
                logger.warning(
                    "[ML_STUB] Failed to load detector from %s (%s). Falling back to stub.",
                    path,
                    exc,
                )
                self._detector = MLDetectorStub()
                self.is_stub = True
                self.status = "load_failed"
                self.model_name = "ZeroSentinel Heuristic Stub"
                self.version = "stub-v0.1.0"
                self.feedback_supported = False
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
        self.feedback_supported = False
        logger.warning(
            "[ML_STUB] ML detector artifacts or package unavailable (status=%s). Fallback stub active.",
            self.status,
        )

    def predict(self, functions: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        if not functions:
            return []
        raw_results = self._detector.predict(functions)
        normalized: List[Dict[str, Any]] = []
        for idx, item in enumerate(raw_results):
            fn = functions[idx] if idx < len(functions) else {}
            start = fn.get("start_line", 1)
            end = fn.get("end_line", start)

            score = float(item.get("ml_score", 0.0))
            cwe_guess = item.get("cwe_guess")
            cwe_probs = item.get("cwe_probs") or {}
            top_lines = item.get("top_lines") or [start]

            score = max(0.0, min(1.0, score))
            valid_lines = [l for l in top_lines if start <= l <= end] or [start]

            normalized.append({
                "ml_score": round(score, 3),
                "cwe_guess": cwe_guess,
                "cwe_probs": cwe_probs,
                "top_lines": valid_lines,
            })
        return normalized

    def feedback(
        self,
        code: str,
        status: str,
        func_name: str = "unknown",
        cwe_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Safely dispatches feedback learning to the active detector under lock protection.
        - Enforces safe semantic mapping per Phase 7B.
        - Protects concurrent disk and state writes.
        - Never throws unhandled exceptions that could crash caller workflows.
        - Rejects code execution or evaluation.
        """
        if not code or not code.strip():
            return {
                "status": status,
                "reward": 0.0,
                "applied": False,
                "message": "Feedback ignored: empty code snippet provided.",
            }

        norm_status = status.strip().lower()

        # Semantic Mapping Policy per Phase 7B:
        # - 'false_positive': negative reward to suppress false alarm
        # - 'fixed': positive reward confirming true vulnerability
        # - 'accepted': indicates business risk acceptance, NOT a false positive.
        #   Member 3's engine assigns it negative reward (-0.3), which improperly penalizes legitimate findings.
        #   Therefore, we explicitly reject model updates for 'accepted'.
        if norm_status == "accepted":
            logger.info("Feedback for status 'accepted' received: skipped model parameter update to prevent false suppression.")
            return {
                "status": norm_status,
                "reward": 0.0,
                "applied": False,
                "message": "Feedback skipped: 'accepted' indicates business risk acceptance, not a false positive.",
            }

        if norm_status not in ("false_positive", "fixed"):
            logger.info("Feedback status '%s' not recognized for online model learning; skipped.", norm_status)
            return {
                "status": norm_status,
                "reward": 0.0,
                "applied": False,
                "message": f"Feedback skipped: status '{norm_status}' is not mapped to an active training signal.",
            }

        # Check if active detector supports feedback
        if not hasattr(self._detector, "feedback") or not callable(getattr(self._detector, "feedback")):
            return {
                "status": norm_status,
                "reward": 0.0,
                "applied": False,
                "message": "Feedback ignored: active detector does not support online feedback.",
            }

        # Thread-safe execution under lock to prevent concurrent state corruption
        with self._lock:
            try:
                # Truncate overly large snippets to prevent memory/vectorizer exhaustion (64 KB ceiling)
                safe_code = code[:65536]
                feedback_kwargs = {
                    "code": safe_code,
                    "status": norm_status,
                    "func_name": func_name,
                }
                if cwe_id is not None:
                    feedback_kwargs["cwe_id"] = cwe_id
                try:
                    result = self._detector.feedback(**feedback_kwargs)
                except TypeError:
                    result = self._detector.feedback(code=safe_code, status=norm_status, func_name=func_name)
                if isinstance(result, dict):
                    result["applied"] = True
                return result
            except Exception as exc:
                logger.warning("[ML_FEEDBACK] Detector feedback failed: %s", exc)
                return {
                    "status": norm_status,
                    "reward": 0.0,
                    "applied": False,
                    "message": f"Detector feedback processing failed: {exc}",
                }

    async def record_feedback_async(
        self,
        code: str,
        status: str,
        func_name: str = "unknown",
        cwe_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Non-blocking async wrapper that delegates synchronous feedback processing
        to an asynchronous worker thread pool to avoid blocking the event loop.
        """
        return await asyncio.to_thread(self.feedback, code, status, func_name, cwe_id)

    def get_runtime_info(self) -> Dict[str, Any]:
        return {
            "model_name": self.model_name,
            "version": self.version,
            "is_stub": self.is_stub,
            "artifacts_present": self.artifacts_present,
            "artifacts_path": self.artifacts_path,
            "device": self.device,
            "status": self.status,
            "feedback_supported": self.feedback_supported,
        }



# Singleton service instance
ml_service = MLDetectorService()
