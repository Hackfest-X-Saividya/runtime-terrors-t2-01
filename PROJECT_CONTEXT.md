# ZeroSentinel — Shared Project Context & Architecture

ZeroSentinel is an automated source-code vulnerability detection prototype developed for a 24-hour cybersecurity hackathon.

---

## 1. Team Architecture & Responsibilities

- **Member 1 (Backend & Database — Antigravity):**
  - Manages `/backend` on Git branch `Backend`.
  - Implements FastAPI server, PostgreSQL 16 database integration, Alembic migrations, static analysis runners (Bandit + Semgrep), ML adapter, WebSocket progress broadcaster, and REST endpoints.
- **Member 2 (Frontend — Stitch + Claude Code):**
  - Manages `/frontend` on Git branch `frontend`.
  - Builds React + Tailwind dashboard consuming the REST API and WebSocket events defined in `CONTRACT.md`.
- **Member 3 (Machine Learning Detector):**
  - Manages `/ml` on Git branch `ai/ml`.
  - Builds model training artifacts in `ml/artifacts` and the `detector.py` inference package.

---

## 2. Machine Learning Detector Contract

### 2.1 Invocation Pattern
Member 3's confirmed inference interface:
```python
from detector import Detector

det = Detector.load("ml/artifacts")
results = det.predict(functions)
```

### 2.2 Input Payload (`functions`)
A list of extracted Python function AST nodes:
```python
[
    {
        "code": "def authenticate(token):\n    return pickle.loads(token)",
        "file_path": "services/auth.py",
        "start_line": 23,
        "end_line": 25
    }
]
```

### 2.3 Output Payload (`results`)
A list of prediction dictionaries matching the input order:
```python
[
    {
        "ml_score": 0.94,             # float: uncalibrated model score (0.0 - 1.0)
        "cwe_guess": "CWE-502",        # string | null: predicted CWE identifier
        "cwe_probs": {                 # dict[str, float]: distribution over modeled classes
            "CWE-502": 0.94,
            "CWE-89": 0.03,
            "CWE-79": 0.01
        },
        "top_lines": [24]              # list[int]: lines within function with highest attention
    }
]
```

### 2.4 Evidence-Based Finding Promotion Policy
1. **Uncalibrated Score:** `ml_score` represents raw model activation or ranking score. It is never presented as an empirical statistical probability.
2. **Corroborated Rule Finding (`source: "both"`):** When an ML prediction overlaps lines flagged by a static rule (Bandit or Semgrep), the finding is preserved with `source: "both"`, storing the static `rule_id` along with `ml_score`.
3. **Standalone ML Candidate (`source: "ml"`):** An ML prediction without a matching static rule is promoted to a public finding **only if**:
   - `ml_score >= ML_STANDALONE_THRESHOLD` (Environment variable default: `0.70`, documented as an unvalidated demo default).
   - `cwe_guess` is not null.
   - Predictions below threshold or without a CWE guess remain internal telemetry signals and are discarded from public findings.
4. **No "Zero-Day" Claims:** Standalone ML candidates are classified as heuristic anomalies or potential unverified vulnerabilities, never as confirmed zero-day exploits.
5. **Transparent Fallback:** If `detector.Detector` cannot be imported or `ml/artifacts` is missing, the backend loads `app.services.ml_detector.MLDetectorStub`, explicitly reporting `is_stub: true` via `/api/model/info`.

---

## 3. Safe Ingestion & Zero-Execution Security Guardrails

The application analyzes potentially malicious untrusted source code. **Submitted code is never executed, evaluated, imported, or run.**

### 3.1 Git URL Ingestion Security & SSRF Defense

1. **Domain Allowlist & Hostname Validation:**
   - For prototype safety, repositories are restricted to an explicit allowlist of approved Git hosting domains:
     `ALLOWED_GIT_DOMAINS = {"github.com", "gitlab.com", "bitbucket.org"}`
   - The URL is parsed strictly using `urllib.parse.urlsplit`:
     - Scheme must be strictly `https`.
     - Hostname is lowercased and matched against `ALLOWED_GIT_DOMAINS`.
     - Embedded credentials (`username`, `password`) are rejected with `400 Bad Request`.
     - Non-standard ports (anything other than default 443) are rejected.
     - Shell control characters (`;&|$\`\n`) are rejected.
2. **Pre-Clone IP Resolution & TOCTOU Limitation Disclosure:**
   - Every IPv4 and IPv6 address returned by `socket.getaddrinfo(parsed.hostname, 443)` is evaluated using `ipaddress.ip_address()`:
     - Each IP must satisfy `ip.is_global is True`.
     - Private (RFC 1918), loopback (`127.0.0.0/8`, `::1`), link-local (`169.254.0.0/16`), multicast, and cloud metadata addresses (`169.254.169.254`, `metadata.google.internal`) are rejected with `400 Bad Request`.
   - **Documented Security Limitation (TOCTOU / DNS Rebinding):** Pre-resolving DNS in Python significantly mitigates accidental internal network scanning, but does not provide complete SSRF immunity because the subsequent `git clone` process re-resolves the domain independently (Time-of-Check to Time-of-Use window). In production, this requires kernel-level or egress-proxy network filtering.
3. **Native Branch Validation & Option-Injection Prevention:**
   - Candidate branch names starting with `-` or `--` are immediately rejected.
   - Rather than relying on heuristics, branch validity is verified natively using Git's own ref parser:
     ```python
     # Validates branch syntax according to Git's reference formatting rules
     subprocess.run(
         ["git", "check-ref-format", "--branch", branch],
         shell=False,
         check=True,
         capture_output=True,
         text=True
     )
     ```
   - The clone command passes `--` prior to the repository URL to prevent option injection:
     ```python
     subprocess.run(
         ["git", "clone", "--depth", "1", "--single-branch", "--branch", branch, "--", git_url, target_dir],
         shell=False,
         timeout=30,
         check=True
     )
     ```
4. **Resource Bounds & Cleanup:**
   - Hard execution timeout: 30 seconds (terminates child process tree on timeout).
   - Maximum cloned footprint: 50 MB checked immediately post-clone.
   - Enclosed within `tempfile.TemporaryDirectory()` for deterministic cleanup on both success and failure.

### 3.2 ZIP Archive Ingestion Security (Cross-Platform & Windows-Safe)

- **Upload Size Ceiling:** Maximum archive upload size: 25 MB.
- **Decompression Bomb Protection:** Cumulative extracted uncompressed byte count monitored during extraction; process aborted if total exceeds 100 MB.
- **Entry Count Limit:** Aborted if total archive entry count exceeds 500 files.
- **Pre-Extraction Path Normalization & Rejection (Windows & POSIX):**
  Before writing any file to disk, every `ZipInfo.filename` is evaluated:
  1. **Absolute Paths:** Rejected if starting with `/` or `\` (e.g., `/etc/passwd`).
  2. **Drive Letters:** Rejected if matching Windows drive-letter patterns (e.g., `^[a-zA-Z]:`).
  3. **Path Traversal Sequences:** Rejected if containing `..` segments across both forward and backslashes (`../`, `..\`, `..\\`).
  4. **Symlink / Hardlink / Device Node Rejection:** Inspects `external_attr >> 16` to ensure entries are regular files or directories; symlinks (`stat.S_ISLNK`) and device files are rejected.
  5. **Containment Verification:**
     ```python
     base_dir = os.path.realpath(temp_dir)
     entry_path = os.path.realpath(os.path.join(base_dir, member.filename))
     if os.path.commonpath([base_dir, entry_path]) != base_dir:
         raise SecurityException(f"Path traversal detected: {member.filename}")
     ```
- **Exclusion Filters:** The following directories and their contents are ignored during vulnerability scanning:
  `.git`, `node_modules`, `venv`, `.venv`, `__pycache__`, `.idea`, `.vscode`, `dist`, `build`.
- Individual source files exceeding 1 MB are skipped to prevent memory exhaustion.
- Enclosed within `tempfile.TemporaryDirectory()` for guaranteed cleanup.

---

## 4. Database Architecture & Mitigations Catalog

Target: **PostgreSQL 16** via SQLAlchemy 2.x async engine (`postgresql+asyncpg://...`). SQLite (`sqlite+aiosqlite:///:memory:`) is strictly isolated to the `pytest` test suite (`tests/conftest.py`).

### 4.1 Startup vs. Health Probe Semantics
- **Startup:** The application reads `DATABASE_URL`. If missing or invalid, it fails fast. If PostgreSQL is temporarily unreachable during boot, it logs a critical warning and initializes in degraded mode without infinite crash-looping.
- **`/health`:** Runs an active `SELECT 1` query probe with a 2-second timeout. If successful, returns `200 OK` (`status: "healthy"`). If the query fails, returns `503 Service Unavailable` (`status: "degraded"`).

### 4.2 Tables Schema & Indexes

```
+------------------------------------+
|               scans                |
+------------------------------------+
| scan_id: UUID [PK]                 |
| project_name: String(255)          |
| submission_type: String(50)        |
| language: String(50)               |
| status: String(50)                 |
| risk_score: Float                  |
| findings_count: Integer            |
| created_at: DateTime(tz=True)      |
| completed_at: DateTime(tz=True)    |
+-----------------+------------------+
                  | 1
                  |
                  | *
+-----------------+------------------+       *    0..1 +------------------------------------+
|              findings              |-----------------|            mitigations             |
+------------------------------------+                 +------------------------------------+
| id: UUID [PK]                      |                 | id: UUID [PK]                      |
| scan_id: UUID [FK -> scans]        |                 | canonical_key: String(150) [UQ]    |
| mitigation_id: UUID [FK -> mitig.] |                 | cwe_id: String(50) [IDX]           |
| file_path: String(500)             |                 | rule_id: String(100) [IDX]         |
| start_line: Integer                |                 | title: String(255)                 |
| end_line: Integer                  |                 | remediation_guidance: Text         |
| title: String(255)                 |                 | code_diff: Text                    |
| cwe_id: String(50) [Nullable]      |                 | references_json: JSONB [Nullable]  |
| owasp: String(100) [Nullable]      |                 | created_at: DateTime(tz=True)      |
| source: String(20)                 |                 +------------------------------------+
| rule_id: String(100) [Nullable]    |
| snippet: Text                      |
| ml_score: Float [Nullable]         |
| severity: String(20)               |
| risk_score: Float                  |
| mitigation: Text                   |
| status: String(20)                 |
+------------------------------------+
```

#### Table 1: `scans`
- `scan_id`: UUID, Primary Key.
- `project_name`: String(255), Not Null.
- `submission_type`: String(50), Not Null (`code`, `zip`, `git`).
- `language`: String(50), Not Null.
- `status`: String(50), Not Null (`queued`, `scanning`, `analyzing_ml`, `completed`, `failed`).
- `risk_score`: Float, default `0.0`.
- `findings_count`: Integer, default `0`.
- `created_at`: DateTime with timezone, Not Null.
- `completed_at`: DateTime with timezone, Nullable.

#### Table 2: `mitigations` (Canonical Deduplicated Catalog)
- `id`: UUID, Primary Key.
- `canonical_key`: String(150), Unique, Not Null.
  - Deterministic generation rules:
    - Rule-specific mitigation: `"rule:" || rule_id`
    - CWE-generic mitigation: `"cwe:" || cwe_id || ":generic"`
    - CWE-specific variant: `"cwe:" || cwe_id || ":" || slugify(title)`
    - Custom/unmapped mitigation: `"custom:" || uuid4()`
- `cwe_id`: String(50), Nullable, Indexed.
- `rule_id`: String(100), Nullable, Indexed.
- `title`: String(255), Not Null.
- `remediation_guidance`: Text, Not Null.
- `code_diff`: Text, Nullable.
- `references_json`: JSONB, Nullable.
- `created_at`: DateTime with timezone, Not Null.
- **Upsert Semantics:** Deduplicated using concurrency-safe `INSERT ... ON CONFLICT (canonical_key) DO UPDATE SET title = EXCLUDED.title, remediation_guidance = EXCLUDED.remediation_guidance, code_diff = EXCLUDED.code_diff, references_json = EXCLUDED.references_json RETURNING id`.

#### Table 3: `findings`
- `id`: UUID, Primary Key.
- `scan_id`: UUID, ForeignKey(`scans.scan_id`, ondelete='CASCADE'), Not Null.
- `mitigation_id`: UUID, ForeignKey(`mitigations.id`, ondelete='SET NULL'), Nullable.
- `file_path`: String(500), Not Null.
- `start_line`: Integer, Not Null.
- `end_line`: Integer, Not Null.
- `title`: String(255), Not Null.
- `cwe_id`: String(50), Nullable.
- `owasp`: String(100), Nullable.
- `source`: String(20), Not Null (`rule`, `ml`, `both`).
- `rule_id`: String(100), Nullable.
- `snippet`: Text, Not Null.
- `ml_score`: Float, Nullable.
- `severity`: String(20), Not Null (`critical`, `high`, `medium`, `low`).
- `risk_score`: Float, Not Null.
- `mitigation`: Text, Not Null *(denormalized summary for direct display)*.
- `status`: String(20), Not Null (`open`, `fixed`, `false_positive`, `accepted`).
- **Indexes:**
  - Composite Index: `ix_findings_scan_id_severity` on `(scan_id, severity)`
  - Single Index: `ix_findings_status` on `(status)`
