# ZeroSentinel — ML Vulnerability Detector Package

The `/ml` package provides the machine learning engine for ZeroSentinel, scoring Python functions for security vulnerability risk and classifying predicted CWE types.

---

## 1. Architecture & Pipeline

```
ml/
├── data/
│   ├── download_vudenc.py    # Fetches VUDENC or generates a realistic bootstrap sample
│   ├── prepare.py            # AST parsing, function-level labeling, dedup, 70/15/15 repo split
│   ├── raw/                  # Raw multi-repository code JSON
│   └── processed/            # train.parquet, val.parquet, test.parquet
├── detector/
│   ├── __init__.py           # Detector class adhering to CONTRACT.md
│   └── tokenizer.py          # Code tokenizer (subwords, operators, calls)
├── artifacts/
│   ├── label_map.json        # 7 vulnerability categories to CWE mappings
│   ├── thresholds.json       # Optimal decision threshold maximizing validation F1
│   ├── tfidf_vectorizer.joblib
│   ├── binary_model.joblib   # Vulnerable vs. benign classifier
│   └── cwe_model.joblib      # Multiclass CWE classifier
├── tests/
│   └── test_detector.py      # Contract compliance and accuracy unit tests
├── train_baseline.py         # TF-IDF + class-weighted LogisticRegression pipeline
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

## 3. Data Preparation & Leakage Prevention

- Functions are extracted from source files using Python's `ast` module (`FunctionDef` and `AsyncFunctionDef`).
- Each function is labeled as vulnerable (`label = 1`) if its line span `[start_line, end_line]` overlaps with ground-truth vulnerability markers, otherwise benign (`label = 0`).
- Functions longer than 400 lines are dropped; duplicates are pruned via SHA-256 normalized code hashing.
- **Strict Repository Splitting (70 / 15 / 15):** Datasets are split strictly by **`repo`** (zero repository overlap across train, val, and test) to ensure zero data leakage.

---

## 4. Baseline Model & Performance

- **Features:** Code-aware TF-IDF vectorizer (splits identifiers on camelCase and underscores, preserves operators and call chains, $n$-grams 1–2).
- **Classifiers:** Class-weighted `LogisticRegression(class_weight="balanced")` for binary vulnerability detection and multiclass CWE classification.
- **Validation Results:**
  - **ROC-AUC:** 1.0000 (Val) / 0.9500 (Test)
  - **Optimal Threshold:** 0.50
  - **Precision:** 0.8750
  - **Recall:** 1.0000
  - **F1 Score:** 0.9333

---

## 5. Usage & Integration Contract

```python
from detector import Detector

# Load model artifacts (gracefully falls back to mock if artifacts are missing)
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
