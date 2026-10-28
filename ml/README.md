# ZeroSentinel — ML Vulnerability Detector Package

The `/ml` package provides the machine learning engine for ZeroSentinel, scoring Python functions for security vulnerability risk and classifying predicted CWE types.

---

## 1. Architecture & Pipeline

```
ml/
├── data/
│   ├── download_vudenc.py    # Fetches VUDENC or generates realistic multi-repo bootstrap sample
│   ├── prepare.py            # AST parsing, function-level labeling, dedup, 70/15/15 repo split
│   ├── raw/                  # Raw multi-repository code JSON
│   ├── processed/            # train.parquet, val.parquet, test.parquet
│   └── samples/              # vuln_demo.py (demo sample target)
├── detector/
│   ├── __init__.py           # Detector class adhering to CONTRACT.md (3-tier progressive enhancement)
│   └── tokenizer.py          # Code tokenizer (subwords, operators, calls)
├── artifacts/
│   ├── label_map.json        # 7 vulnerability categories to CWE mappings
│   ├── thresholds.json       # Optimal decision threshold maximizing validation F1
│   ├── model_card.json       # Metadata & metrics for backend GET /api/model/info
│   ├── tfidf_vectorizer.joblib
│   ├── binary_model.joblib   # Vulnerable vs. benign classifier
│   ├── cwe_model.joblib      # Multiclass CWE classifier
│   └── codebert/             # Fine-tuned CodeBERT weights & configuration
├── reports/
│   ├── eval.json             # Machine-readable held-out zero-day & test benchmarks
│   └── eval.md               # Markdown report table for judges & SOC review
├── tests/
│   ├── test_detector.py      # Contract compliance, artifact loading, and accuracy tests
│   └── test_evaluation.py    # Held-out evaluation, model card, and demo scoring tests
├── train_baseline.py         # TF-IDF + class-weighted LogisticRegression pipeline
├── train_codebert.py         # microsoft/codebert-base dual-head fine-tuning & line occlusion
├── eval_holdout.py           # Leave-One-Type-Out Zero-Day Generalization benchmark
└── pyproject.toml            # Editable package specification
```

---

## 2. Supported Vulnerability Types (7 Categories)

| Vulnerability Type | CWE ID | Description |
|---|---|---|
| `sql` | **CWE-89** | SQL Injection (unparameterized query strings, f-strings, `%` format) |
| `xss` | **CWE-79** | Cross-Site Scripting (raw template rendering, unescaped output) |
| `command_injection` | **CWE-78** | OS Command Injection (`subprocess`, `os.system`, `os.popen` with `shell=True`) |
| `xsrf` | **CWE-352** | Cross-Site Request Forgery (missing anti-forgery tokens on state mutations) |
| `remote_code_execution`| **CWE-94** | Code Injection / Insecure Deserialization (`eval`, `exec`, `pickle.loads`, `yaml.load`) |
| `path_disclosure` | **CWE-22** | Path Traversal / Arbitrary File Read (`os.path.join` with user input, unvalidated paths) |
| `open_redirect` | **CWE-601** | URL Redirection to Untrusted Site (unvalidated `redirect(target)`) |

---

## 3. Leave-One-Type-Out Zero-Day Evaluation

To simulate real-world zero-day discovery, the model is trained strictly on **6 known vulnerability types** and tested against functions exhibiting a **7th unseen vulnerability type**:

| Held-Out (Unseen) Type | Target CWE | Training Types | Detection Rate (Recall) | Benign FPR | ROC-AUC |
|---|---|---|---|---|---|
| `sql` | **CWE-89** | 6 classes | **100.0% (1/1)** | 0.0% | **1.0000** |
| `xss` | **CWE-79** | 6 classes | **100.0% (1/1)** | 0.0% | **1.0000** |
| `command_injection` | **CWE-78** | 6 classes | **100.0% (1/1)** | 0.0% | **1.0000** |
| `xsrf` | **CWE-352** | 6 classes | **0.0% (0/2)** | 0.0% | **0.7000** |
| `remote_code_execution` | **CWE-94** | 6 classes | **100.0% (1/1)** | 0.0% | **1.0000** |
| `path_disclosure` | **CWE-22** | 6 classes | **100.0% (1/1)** | 0.0% | **1.0000** |
| `open_redirect` | **CWE-601** | 6 classes | **100.0% (1/1)** | 0.0% | **1.0000** |

Full benchmarks are recorded in [`reports/eval.json`](file:///C:/Users/jyoti/runtime-terrors-t2-01/ml/reports/eval.json) and [`reports/eval.md`](file:///C:/Users/jyoti/runtime-terrors-t2-01/ml/reports/eval.md).

---

## 4. Demo Sample (`data/samples/vuln_demo.py`)

Tailored for the 3-minute hackathon demo:
- **Confirmed Findings (Rules + ML):** `search_users_classic`, `execute_system_ping`, `render_user_profile` $\rightarrow$ scored $\ge 0.53$ (high risk).
- **Novel Findings (Zero-Day Candidates, ML Only):** `dynamic_query_assembler`, `dispatch_dynamic_worker`, `stream_tenant_log` $\rightarrow$ scored $\ge 0.53$ (high risk).
- **Benign Controls:** `safe_get_user_by_id`, `safe_run_ping`, `compute_token_hash` $\rightarrow$ scored $< 0.53$ (clean).

---

## 5. Usage & Integration Contract

```python
from detector import Detector

# Load model artifacts (Tier 1: CodeBERT -> Tier 2: TF-IDF -> Tier 3: Mock)
det = Detector.load("ml/artifacts")

# Predict vulnerability scores for a batch of functions
functions = [
    {
        "code": "def query_user(user_id):\n    return db.execute('SELECT * FROM users WHERE id = ' + user_id)",
        "file_path": "app/views.py",
        "start_line": 42,
        "end_line": 44
    }
]

preds = det.predict(functions)
# Output format:
# [
#   {
#     "ml_score": 0.912,
#     "cwe_guess": "CWE-89",
#     "cwe_probs": {"CWE-89": 0.85, "CWE-79": 0.04, ...},
#     "top_lines": [43]
#   }
# ]
```

---

## 6. Running Tests

```bash
pytest ml/tests -v
```
All 11 tests passing: contract validation, artifact loading, held-out reports, model card, and demo sample classification.
