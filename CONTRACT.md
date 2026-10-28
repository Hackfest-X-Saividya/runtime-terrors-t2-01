# CONTRACT.md

## Finding Schema
Every finding in ZeroSentinel adheres to this JSON structure:

```json
{ 
  "id": "f_01J…", 
  "scan_id": "s_01J…", 
  "file_path": "app/views.py", 
  "start_line": 42, 
  "end_line": 51, 
  "title": "SQL built from user input", 
  "cwe_id": "CWE-89", 
  "owasp": "A05:2025 Injection", 
  "source": "both", 
  "ml_score": 0.91, 
  "severity": "high", 
  "risk_score": 8.2, 
  "mitigation": "Use parameterised queries instead of string concatenation.", 
  "status": "open" 
}
```

- `source`: `rule` | `ml` | `both`
- `severity`: `critical` | `high` | `medium` | `low`
- `status`: `open` | `fixed` | `false_positive` | `accepted`

---

## ML Detector Interface Contract
The backend imports and invokes the ML detector package as follows:

```python
from detector import Detector

det = Detector.load("ml/artifacts")   # Loaded once at startup
preds = det.predict(functions)       # functions: List[Dict[str, Any]]
```

### Input Format
`functions` is a list of dictionary objects:
```json
[
  {
    "code": "def query_user(user_id):\n    return db.execute('SELECT * FROM users WHERE id = ' + user_id)",
    "file_path": "app/views.py",
    "start_line": 42,
    "end_line": 44
  }
]
```

### Output Format
`preds` is a list of prediction dictionaries corresponding 1:1 with `functions`:
```json
[
  {
    "ml_score": 0.912,
    "cwe_guess": "CWE-89",
    "cwe_probs": {
      "CWE-89": 0.852,
      "CWE-79": 0.041,
      "CWE-78": 0.033,
      "CWE-352": 0.015,
      "CWE-94": 0.027,
      "CWE-22": 0.021,
      "CWE-601": 0.011
    },
    "top_lines": [43]
  }
]
```
`top_lines` returns up to 3 absolute line numbers in `[start_line, end_line]` indicating the highest-risk lines.
