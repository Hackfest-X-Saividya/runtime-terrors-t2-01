import hashlib
import json
from pathlib import Path
from typing import List, Dict, Any

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
            {"default_threshold": 0.5}
        )

    @staticmethod
    def _read_json(path: Path, fallback: dict) -> dict:
        if path.exists():
            with open(path, "r", encoding="utf-8") as f:
                return json.load(f)
        return fallback

    @classmethod
    def load(cls, path: str = "ml/artifacts") -> "Detector":
        return cls(Path(path))

    def predict(self, functions: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        results = []
        cwe_list = list(self.label_map.values())
        
        for fn in functions:
            code = fn.get("code", "")
            start = fn.get("start_line", 1)
            end = fn.get("end_line", start)
            
            # Deterministic hash mock for early testing
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