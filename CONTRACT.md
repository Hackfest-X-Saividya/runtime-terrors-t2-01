# CONTRACT.md

## Finding
id, scan_id, file_path, start_line, end_line, snippet, title,
cwe_id ("CWE-89"), owasp ("A05:2025 Injection"),
source: rule | ml | both, rule_id (nullable), ml_score (0-1, nullable),
severity: critical | high | medium | low, risk_score (0-10),
mitigation (markdown text), status: open | fixed | false_positive | accepted

## Scan
id, name, source_type: zip | git | paste,
status: queued | running | done | failed | partial,
stage: unpack | rules | ml | ranking, files_scanned, functions_scanned,
risk_score, counts_by_severity {critical, high, medium, low},
started_at, finished_at (ISO 8601)

## Summary (GET /api/stats/summary)
total_scans, total_findings, novel_count,
by_severity {critical, high, medium, low}, by_owasp {category: count},
by_source {rule, ml, both}, top_findings [5 x Finding], last_scan (Scan)

## Endpoints
POST  /api/scans                  multipart zip | {git_url} | {code, filename} -> {scan_id}
GET   /api/scans                  -> Scan[]
GET   /api/scans/{id}             -> Scan
GET   /api/scans/{id}/findings    ?severity&owasp&source&status&sort&limit&offset -> {items, total}
GET   /api/findings/{id}          -> Finding
PATCH /api/findings/{id}          {status} -> Finding
GET   /api/scans/{id}/report      ?format=html|pdf -> file
GET   /api/stats/summary          -> Summary
GET   /api/model/info             -> {model_card, eval}
GET   /health                     -> {ok: true}

## WebSocket  /ws/scans/{id}
{"type": "progress", "data": {"stage", "done", "total"}}
{"type": "finding",  "data": Finding}
{"type": "done",     "data": Scan}

## Feedback learning (PROPOSED - needs backend sign-off)
Drafted by the frontend on 2026-10-28; see OPEN_QUESTIONS.md. Fields above are unchanged.

Finding (+): ml_score_before (0-1, nullable), suppressed (bool),
  feedback (nullable) {reason, note, train, created_at, model_version}

Scan (+): rescan_of (nullable scan id), model_version

PATCH /api/findings/{id}          {status, reason?, note?, train?} -> Finding
POST  /api/scans                  ... | {rescan_of} -> {scan_id}
GET   /api/scans/{id}/findings    + ?q (text search) &include_suppressed (bool, default false)
GET   /api/scans/{id}/diff        -> {previous_scan_id, new: Finding[], suppressed: Finding[],
                                      still_open: Finding[], resolved: Finding[]}
GET   /api/model/info             -> {model_card, eval, learning:
                                      {version, threshold, feedback_count, suppressed_count,
                                       versions [{version, created_at, trigger, f1, fpr}],
                                       recent_feedback [Finding]}}
POST  /api/model/revert           {version} -> {version}

model_card: {name, version, architecture, training_data, languages [string], threshold}
eval: {precision, recall, f1, roc_auc, held_out [{vuln_type, cwe_id, detection_rate, fpr, samples}]}
# ZeroSentinel API & Integration Contract

This document is the single source of truth for communication between Member 1 (FastAPI Backend), Member 2 (React Frontend), and Member 3 (ML Detector).

---

## 1. General Conventions

- **Base URL:** `/` (Strictly no `/api/v1` prefix).
- **Date/Time Format:** ISO 8601 UTC (`YYYY-MM-DDTHH:MM:SSZ`).
- **Identifiers:** All IDs (`scan_id`, `id`, `mitigation_id`) are standard RFC 4122 UUID v4 strings (e.g., `4fa9b0e2-127b-4221-a477-99d863f6a200`).
- **Pagination Defaults:** Endpoints returning lists support query parameters `skip` (default: `0`) and `limit` (default: `50`, maximum: `100`).
- **Standard Error Response Envelope:** All 4xx and 5xx responses return a consistent error body:
  ```json
  {
    "error": {
      "code": "STRING_ERROR_CODE",
      "message": "Human-readable explanation of the error.",
      "details": null
    }
  }
  ```

---

## 2. Shared Enums

1. **`source`** (Finding origin):
   - `"rule"`: Static analysis engine match (Bandit / Semgrep / AST).
   - `"ml"`: Standalone machine-learning detector candidate.
   - `"both"`: Static rule match corroborated by ML detector.
2. **`severity`** (Vulnerability severity):
   - `"critical"`
   - `"high"`
   - `"medium"`
   - `"low"`
3. **`status`** (Finding lifecycle status):
   - `"open"`: Active vulnerability requiring review/action.
   - `"fixed"`: Remediated in code.
   - `"false_positive"`: Triaged and marked invalid by user.
   - `"accepted"`: Risk acknowledged and accepted by user.
4. **`scan_status`** (Scan lifecycle state):
   - `"queued"`: Received and awaiting processing.
   - `"scanning"`: Static rule analysis active.
   - `"analyzing_ml"`: ML inference active.
   - `"completed"`: Scan completed successfully.
   - `"failed"`: Scan failed due to unrecoverable ingestion/syntax error.

---

## 3. Provisional OWASP Top 10 (2025) Taxonomy & Fallback Policy

> [!WARNING]
> All associations below are **Provisional Working Mappings** for prototype development and subject to ongoing team verification against the final published OWASP Top 10 (2025) standard.
> Any detection, heuristic, or CWE lacking independently verified correlation MUST evaluate to `owasp: null`.

### Provisional Working Mappings:
- **CWE-22, CWE-918** -> `"A01:2025-Broken Access Control"`
- **CWE-798, CWE-1188** -> `"A02:2025-Security Misconfiguration"`
- **CWE-1357** -> `"A03:2025-Software Supply Chain Failures"`
- **CWE-327, CWE-338** -> `"A04:2025-Cryptographic Failures"`
- **CWE-89, CWE-78, CWE-79, CWE-77** -> `"A05:2025-Injection"`
- **CWE-287, CWE-384** -> `"A07:2025-Authentication Failures"`
- **CWE-502** -> `"A08:2025-Software or Data Integrity Failures"`
- **CWE-117** -> `"A09:2025-Security Logging and Alerting Failures"`
- **CWE-755, CWE-703** -> `"A10:2025-Mishandling of Exceptional Conditions"`
- **Unverified / General CWEs** -> `null` *(Frontend displays "Uncategorized")*

---

## 4. Endpoints Specification

### 4.1 `GET /health`
Verifies live backend process and PostgreSQL 16 database connectivity via active query probe (`SELECT 1`).

- **Success (`200 OK`):**
  ```json
  {
    "status": "healthy",
    "database": "connected",
    "version": "0.1.0",
    "timestamp": "2026-10-28T12:00:00Z"
  }
  ```
- **Degraded (`503 Service Unavailable`):**
  ```json
  {
    "status": "degraded",
    "database": "disconnected",
    "version": "0.1.0",
    "timestamp": "2026-10-28T12:00:00Z",
    "error": {
      "code": "DATABASE_UNAVAILABLE",
      "message": "PostgreSQL 16 connection probe failed.",
      "details": null
    }
  }
  ```

---

### 4.2 `POST /api/scans`
Submits source code for analysis via pasted code, ZIP archive upload, or Git repository URL. Responds asynchronously with `202 Accepted`.

#### Request Content-Types:
1. **Pasted Code (`Content-Type: application/json`):**
   ```json
   {
     "submission_type": "code",
     "project_name": "AuthService",
     "source_code": "import pickle\ndef authenticate(token):\n    return pickle.loads(token)\n",
     "language": "python"
   }
   ```
2. **ZIP File (`Content-Type: multipart/form-data`):**
   - `submission_type`: `"zip"` (string, required)
   - `project_name`: `"PaymentGateway"` (string, required)
   - `file`: `<binary .zip content>` (file, required; max 25 MB)
   - `language`: `"python"` (string, optional)
3. **Git Repository (`Content-Type: application/json`):**
   ```json
   {
     "submission_type": "git",
     "project_name": "CoreRepo",
     "git_url": "https://github.com/example-org/sample-backend.git",
     "branch": "main"
   }
   ```

#### Response (`202 Accepted`):
```json
{
  "scan_id": "4fa9b0e2-127b-4221-a477-99d863f6a200",
  "project_name": "AuthService",
  "submission_type": "code",
  "language": "python",
  "status": "queued",
  "risk_score": 0.0,
  "findings_count": 0,
  "created_at": "2026-10-28T12:00:00Z",
  "completed_at": null
}
```

---

### 4.3 `GET /api/scans`
Returns a paginated list of historical scans.

- **Query Parameters:** `skip=0`, `limit=50`
- **Response (`200 OK`):**
  ```json
  [
    {
      "scan_id": "4fa9b0e2-127b-4221-a477-99d863f6a200",
      "project_name": "AuthService",
      "submission_type": "code",
      "language": "python",
      "status": "completed",
      "risk_score": 8.5,
      "findings_count": 1,
      "created_at": "2026-10-28T12:00:00Z",
      "completed_at": "2026-10-28T12:00:02Z"
    }
  ]
  ```

---

### 4.4 `GET /api/scans/{id}`
Returns metadata, status, risk score, and severity breakdown for a scan.

- **Response (`200 OK`):**
  ```json
  {
    "scan_id": "4fa9b0e2-127b-4221-a477-99d863f6a200",
    "project_name": "AuthService",
    "submission_type": "code",
    "language": "python",
    "status": "completed",
    "risk_score": 8.5,
    "findings_count": 1,
    "severity_breakdown": {
      "critical": 0,
      "high": 1,
      "medium": 0,
      "low": 0
    },
    "created_at": "2026-10-28T12:00:00Z",
    "completed_at": "2026-10-28T12:00:02Z"
  }
  ```
- **Error (`404 Not Found`):** When `id` does not match an existing scan record.

---

### 4.5 `GET /api/scans/{id}/findings`
Returns all findings discovered during a specific scan.

- **Query Parameters:**
  - `severity`: Filter by severity (`critical`, `high`, `medium`, `low`)
  - `status`: Filter by status (`open`, `fixed`, `false_positive`, `accepted`)
  - `source`: Filter by detection source (`rule`, `ml`, `both`)
  - `skip`: Default `0`
  - `limit`: Default `50`
- **Response (`200 OK`):**
  ```json
  [
    {
      "id": "8a3f124c-9f88-4c6e-b2d4-1a9823f6e10a",
      "scan_id": "4fa9b0e2-127b-4221-a477-99d863f6a200",
      "file_path": "services/auth.py",
      "start_line": 24,
      "end_line": 26,
      "title": "Deserialization of Untrusted Data via pickle",
      "cwe_id": "CWE-502",
      "owasp": "A08:2025-Software or Data Integrity Failures",
      "source": "both",
      "rule_id": "B301",
      "snippet": "user_payload = pickle.loads(raw_token)",
      "ml_score": 0.94,
      "severity": "high",
      "risk_score": 8.5,
      "mitigation": "Avoid using pickle with untrusted data. Use cryptographically signed tokens or safe serialization formats like JSON.",
      "status": "open"
    }
  ]
  ```

---

### 4.6 `GET /api/findings/{id}`
Returns details for a single finding, including optional extended catalog mitigation references.

- **Response (`200 OK`):**
  ```json
  {
    "id": "8a3f124c-9f88-4c6e-b2d4-1a9823f6e10a",
    "scan_id": "4fa9b0e2-127b-4221-a477-99d863f6a200",
    "file_path": "services/auth.py",
    "start_line": 24,
    "end_line": 26,
    "title": "Deserialization of Untrusted Data via pickle",
    "cwe_id": "CWE-502",
    "owasp": "A08:2025-Software or Data Integrity Failures",
    "source": "both",
    "rule_id": "B301",
    "snippet": "user_payload = pickle.loads(raw_token)",
    "ml_score": 0.94,
    "severity": "high",
    "risk_score": 8.5,
    "mitigation": "Avoid using pickle with untrusted data. Use cryptographically signed tokens or safe serialization formats like JSON.",
    "status": "open",
    "mitigation_detail": {
      "id": "1a2b3c4d-5e6f-7a8b-9c0d-1e2f3a4b5c6d",
      "title": "Secure Deserialization Practices",
      "remediation_guidance": "Replace pickle.loads with json.loads for structured data, or HMAC sign payloads if binary serialization is unavoidable.",
      "code_diff": "- user_payload = pickle.loads(raw_token)\n+ user_payload = json.loads(raw_token.decode('utf-8'))",
      "references_json": [
        "https://owasp.org/Top10/A08_2025-Software_or_Data_Integrity_Failures"
      ]
    }
  }
  ```

---

### 4.7 `PATCH /api/findings/{id}`
Updates finding status (triage workflow).

- **Request Body (`Content-Type: application/json`):**
  ```json
  {
    "status": "false_positive"
  }
  ```
- **Response (`200 OK`):** Full updated `Finding` object.
- **Errors:**
  - `400 Bad Request`: Body missing or unparseable.
  - `404 Not Found`: Finding `id` does not exist.
  - `422 Unprocessable Entity`: `status` not one of `"open"`, `"fixed"`, `"false_positive"`, `"accepted"`.

---

### 4.8 `GET /api/scans/{id}/report`
Exports a comprehensive report for the scan.

- **Query Parameters:** `format=html` (default) or `format=pdf`
- **Response:**
  - `format=html`: `200 OK` with `Content-Type: text/html; charset=utf-8`
  - `format=pdf`: `200 OK` with `Content-Type: application/pdf`

---

### 4.9 `GET /api/stats/summary`
Returns global vulnerability metrics across all stored scans.

- **Response (`200 OK`):**
  ```json
  {
    "total_scans": 12,
    "total_findings": 38,
    "severity_distribution": {
      "critical": 4,
      "high": 14,
      "medium": 12,
      "low": 8
    },
    "top_cwes": [
      {"cwe_id": "CWE-89", "count": 10},
      {"cwe_id": "CWE-502", "count": 8},
      {"cwe_id": "CWE-78", "count": 6}
    ],
    "average_risk_score": 6.8
  }
  ```

---

### 4.10 `GET /api/model/info`
Exposes the actual runtime status of the ML inference subsystem, dynamically derived from live environment checks.

- **Response (`200 OK` — Trained Model Loaded):**
  ```json
  {
    "model_name": "ZeroSentinel CodeBERT Detector",
    "version": "0.1.0",
    "is_stub": false,
    "artifacts_present": true,
    "artifacts_path": "ml/artifacts",
    "device": "cpu",
    "status": "ready"
  }
  ```
- **Response (`200 OK` — Stub Fallback Active):**
  ```json
  {
    "model_name": "ZeroSentinel Heuristic Stub",
    "version": "stub-v0.1.0",
    "is_stub": true,
    "artifacts_present": false,
    "artifacts_path": "ml/artifacts",
    "device": "cpu",
    "status": "stub_fallback"
  }
  ```
- **Response (`200 OK` — Artifacts Exist but Load Failed):**
  ```json
  {
    "model_name": "ZeroSentinel Heuristic Stub",
    "version": "stub-v0.1.0",
    "is_stub": true,
    "artifacts_present": true,
    "artifacts_path": "ml/artifacts",
    "device": "cpu",
    "status": "load_failed"
  }
  ```

---

### 4.11 `WS /ws/scans/{id}`
WebSocket connection streaming real-time scan events.

- **Envelope:** Every event conforms strictly to `{"type": "...", "data": {...}}`.
- **`scan_id` Guarantee:** Every event's `data` payload includes `scan_id`.

#### Event 1: `progress`
```json
{
  "type": "progress",
  "data": {
    "scan_id": "4fa9b0e2-127b-4221-a477-99d863f6a200",
    "stage": "rules",
    "done": 1,
    "total": 5,
    "message": "Executing Bandit and Semgrep static rule checks..."
  }
}
```
*(Valid `stage` values: `"ingest"`, `"rules"`, `"ml"`, `"aggregation"`)*

#### Event 2: `finding`
```json
{
  "type": "finding",
  "data": {
    "id": "8a3f124c-9f88-4c6e-b2d4-1a9823f6e10a",
    "scan_id": "4fa9b0e2-127b-4221-a477-99d863f6a200",
    "file_path": "services/auth.py",
    "start_line": 24,
    "end_line": 26,
    "title": "Deserialization of Untrusted Data via pickle",
    "cwe_id": "CWE-502",
    "owasp": "A08:2025-Software or Data Integrity Failures",
    "source": "both",
    "rule_id": "B301",
    "snippet": "user_payload = pickle.loads(raw_token)",
    "ml_score": 0.94,
    "severity": "high",
    "risk_score": 8.5,
    "mitigation": "Avoid using pickle with untrusted data. Use JSON or Protocol Buffers.",
    "status": "open"
  }
}
```

#### Event 3: `done`
```json
{
  "type": "done",
  "data": {
    "scan_id": "4fa9b0e2-127b-4221-a477-99d863f6a200",
    "status": "completed",
    "risk_score": 8.5,
    "findings_count": 1,
    "severity_breakdown": {
      "critical": 0,
      "high": 1,
      "medium": 0,
      "low": 0
    },
    "duration_seconds": 1.45,
    "completed_at": "2026-10-28T12:00:02Z"
  }
}
```

#### Event 4: `error` (Failure Notification)
```json
{
  "type": "error",
  "data": {
    "scan_id": "4fa9b0e2-127b-4221-a477-99d863f6a200",
    "code": "SCAN_FAILED_PARSING",
    "message": "Source code contains unrecoverable syntax errors and could not be parsed.",
    "stage": "rules"
  }
}
```
*(Stable error codes: `INGESTION_TIMEOUT`, `ARCHIVE_LIMIT_EXCEEDED`, `GIT_CLONE_FAILED`, `SSRF_DETECTED`, `SCAN_FAILED_PARSING`, `INTERNAL_SCAN_ERROR`)*

**Client Recovery Semantics:**
If a WebSocket disconnects or emits an `error` event, the client must query `GET /api/scans/{id}` to retrieve the persisted final scan state (`status: "failed"`), timestamp, and error details recorded in PostgreSQL.
