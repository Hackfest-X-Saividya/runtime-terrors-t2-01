"""
Unit Tests for ZeroSentinel Held-Out Evaluation, Model Card, and Demo Scoring.

Verifies:
1. `ml/reports/eval.json` schema and 7 held-out zero-day results.
2. `ml/reports/eval.md` documentation table.
3. `ml/artifacts/model_card.json` backend schema contract.
4. `data/samples/vuln_demo.py` function extraction and accurate classification:
   - Confirmed vulnerabilities: score >= threshold.
   - Novel vulnerabilities (zero-day candidates): score >= threshold.
   - Benign controls: score < threshold.
5. Detector 3-tier loading and graceful engine fallback.
"""

import ast
import json
from pathlib import Path
import pytest
from detector import Detector

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
ML_DIR = REPO_ROOT / "ml"
REPORTS_DIR = ML_DIR / "reports"
ARTIFACTS_DIR = ML_DIR / "artifacts"
DEMO_SAMPLE_PATH = REPO_ROOT / "data" / "samples" / "vuln_demo.py"

def test_eval_json_structure():
    eval_path = REPORTS_DIR / "eval.json"
    assert eval_path.exists(), f"Missing {eval_path}"

    with open(eval_path, "r", encoding="utf-8") as f:
        data = json.load(f)

    assert "metadata" in data
    assert "dataset_counts" in data
    assert "full_model_test_metrics" in data
    assert "held_out_zero_day_results" in data

    meta = data["metadata"]
    assert meta["random_seed"] == 42
    assert "threshold" in meta

    full_metrics = data["full_model_test_metrics"]
    assert full_metrics["roc_auc"] >= 0.85
    assert full_metrics["precision"] >= 0.80

    held_out = data["held_out_zero_day_results"]
    expected_types = [
        "sql", "xss", "command_injection", "xsrf",
        "remote_code_execution", "path_disclosure", "open_redirect"
    ]
    for vtype in expected_types:
        assert vtype in held_out, f"Missing held-out results for {vtype}"
        res = held_out[vtype]
        assert "detection_rate" in res
        assert "fpr_benign" in res
        assert "roc_auc" in res
        assert 0.0 <= res["detection_rate"] <= 1.0
        assert 0.0 <= res["fpr_benign"] <= 1.0

def test_eval_markdown_report_exists():
    md_path = REPORTS_DIR / "eval.md"
    assert md_path.exists()
    content = md_path.read_text(encoding="utf-8")
    assert "Leave-One-Type-Out Zero-Day Generalization Test" in content
    assert "Full Model Standard Test Benchmark" in content
    assert "CWE-89" in content
    assert "CWE-78" in content

def test_model_card_schema():
    card_path = ARTIFACTS_DIR / "model_card.json"
    assert card_path.exists(), f"Missing {card_path}"

    with open(card_path, "r", encoding="utf-8") as f:
        card = json.load(f)

    assert "model_name" in card
    assert "model_version" in card
    assert "default_threshold" in card
    assert "dataset" in card
    assert "metrics" in card
    assert "limitations" in card
    assert isinstance(card["limitations"], list)
    assert len(card["limitations"]) > 0
    assert len(card["supported_cwes"]) == 7

def test_demo_sample_scoring():
    assert DEMO_SAMPLE_PATH.exists(), f"Missing {DEMO_SAMPLE_PATH}"
    code = DEMO_SAMPLE_PATH.read_text(encoding="utf-8")
    tree = ast.parse(code)
    lines = code.splitlines()

    functions = []
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            func_code = "\n".join(lines[node.lineno - 1 : node.end_lineno])
            functions.append({
                "func_name": node.name,
                "code": func_code,
                "start_line": node.lineno,
                "end_line": node.end_lineno,
                "file_path": "data/samples/vuln_demo.py"
            })

    functions.sort(key=lambda x: x["start_line"])
    det = Detector.load(ARTIFACTS_DIR)
    preds = det.predict(functions)
    assert len(preds) == len(functions)

    thresh = float(det.thresholds.get("default_threshold", 0.50))
    pred_map = {fn["func_name"]: pred for fn, pred in zip(functions, preds)}

    # Confirmed Vulnerabilities (Rule + ML hits)
    confirmed_funcs = ["search_users_classic", "execute_system_ping", "render_user_profile"]
    for c_name in confirmed_funcs:
        assert c_name in pred_map
        p = pred_map[c_name]
        assert p["ml_score"] >= thresh, f"{c_name} scored {p['ml_score']} < {thresh}"
        assert p["cwe_guess"].startswith("CWE-")
        assert len(p["top_lines"]) >= 1

    # Novel Vulnerabilities (ML Only Zero-Day Candidates)
    novel_funcs = ["dynamic_query_assembler", "dispatch_dynamic_worker", "stream_tenant_log"]
    for n_name in novel_funcs:
        assert n_name in pred_map
        p = pred_map[n_name]
        assert p["ml_score"] >= thresh, f"Novel function {n_name} scored {p['ml_score']} < {thresh}"
        assert p["cwe_guess"].startswith("CWE-")

    # Benign Control Functions (Safe)
    benign_funcs = ["safe_get_user_by_id", "safe_run_ping", "compute_token_hash"]
    for b_name in benign_funcs:
        assert b_name in pred_map
        p = pred_map[b_name]
        assert p["ml_score"] < thresh, f"Benign function {b_name} falsely flagged with {p['ml_score']} >= {thresh}"

def test_detector_engine_hierarchy(tmp_path):
    # Tier 2: TF-IDF Baseline
    det_base = Detector.load(ARTIFACTS_DIR)
    assert det_base.active_engine == "baseline"

    # Tier 3: Dummy Mock fallback on non-existent folder
    empty_artifacts = tmp_path / "empty"
    empty_artifacts.mkdir()
    det_mock = Detector.load(empty_artifacts)
    assert det_mock.active_engine == "mock"
    assert det_mock.is_loaded is False
