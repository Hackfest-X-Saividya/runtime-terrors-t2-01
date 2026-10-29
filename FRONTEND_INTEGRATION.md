# ZeroSentinel — Frontend Integration & Handoff Guide

**Target Audience:** Member 2 (React Frontend Developer)
**Target Stack:** React + Vite + Tailwind CSS
**Target Branch:** `frontend`
**Backend Branch:** `Backend` (serving at `http://localhost:8000`)

---

## 1. Environment Configuration

In the frontend root directory (`frontend/.env`):

```env
VITE_API_BASE_URL=http://localhost:8000
VITE_WS_BASE_URL=ws://localhost:8000
```

### CORS Configuration on Backend
The backend permits credentials and cross-origin requests from:
* `http://localhost:5173` (Standard Vite React dev server)
* `http://127.0.0.1:5173`
* `http://localhost:3000`
* `http://127.0.0.1:3000`

---

## 2. API Endpoints Specification

### 2.1 Health Probe
`GET /health`

**Success (`200 OK`):**
```json
{
  "status": "healthy",
  "database": "connected",
  "version": "0.1.0",
  "timestamp": "2026-10-28T12:00:00Z"
}
```

---

### 2.2 Model Runtime Status
`GET /api/model/info`

**Trained Model Ready (`200 OK`):**
```json
{
  "model_name": "ZeroSentinel CodeBERT Detector",
  "version": "0.1.0",
  "is_stub": false,
  "artifacts_present": true,
  "artifacts_path": "ml/artifacts",
  "device": "cpu",
  "status": "ready",
  "feedback_supported": true
}
```

---

### 2.3 Submit Code / Scan Creation
`POST /api/scans`

Returns HTTP `202 Accepted`:
```json
{
  "scan_id": "4fa9b0e2-127b-4221-a477-99d863f6a200",
  "status": "queued",
  "project_name": "AuthService",
  "created_at": "2026-10-28T12:00:00Z"
}
```

#### Mode A: Pasted Source Code (JSON)
```json
{
  "submission_type": "code",
  "project_name": "MyProject",
  "language": "python",
  "source_code": "def query():\n    cursor.execute(f'SELECT * FROM users WHERE name={name}')"
}
```

#### Mode B: ZIP Archive Upload (`multipart/form-data`)
* Form Field `submission_type`: `"zip"`
* Form Field `project_name`: `"MyProject"`
* Form Field `language`: `"python"` (optional, default `"python"`)
* Form File `file`: `<binary zip payload>` (Max 25 MB)

#### Mode C: Git Repository (JSON)
```json
{
  "submission_type": "git",
  "project_name": "MyRepo",
  "repo_url": "https://github.com/org/repo.git",
  "branch": "main",
  "language": "python"
}
```

---

### 2.4 WebSocket Real-Time Scan Streaming
`WS /ws/scans/{id}`

Every message conforms to the envelope `{ "type": string, "data": object }`.

#### Event 1: `progress`
```json
{
  "type": "progress",
  "data": {
    "scan_id": "4fa9b0e2-127b-4221-a477-99d863f6a200",
    "status": "scanning",
    "step": "Executing Bandit static security analyzers...",
    "progress_pct": 35
  }
}
```

#### Event 2: `finding` (Streamed as detected)
```json
{
  "type": "finding",
  "data": {
    "scan_id": "4fa9b0e2-127b-4221-a477-99d863f6a200",
    "finding": {
      "id": "19ace23c-c98d-42e5-ad73-9eb1c65a839b",
      "scan_id": "4fa9b0e2-127b-4221-a477-99d863f6a200",
      "mitigation_id": "d0e1f2a3-b4c5-6789-0123-456789abcdef",
      "file_path": "auth.py",
      "start_line": 15,
      "end_line": 15,
      "title": "Possible SQL injection vector through string-based query construction.",
      "cwe_id": "CWE-89",
      "owasp": "A05:2025-Injection",
      "source": "both",
      "rule_id": "B608",
      "snippet": "cursor.execute(f'SELECT * FROM users WHERE id={id}')",
      "ml_score": 0.88,
      "severity": "high",
      "risk_score": 8.0,
      "mitigation": "Use parameterized queries or ORM abstractions instead of direct string interpolation.",
      "status": "open"
    }
  }
}
```

#### Event 3: `done` (Terminal)
```json
{
  "type": "done",
  "data": {
    "scan_id": "4fa9b0e2-127b-4221-a477-99d863f6a200",
    "status": "completed",
    "risk_score": 8.0,
    "findings_count": 1,
    "severity_breakdown": {
      "critical": 0,
      "high": 1,
      "medium": 0,
      "low": 0
    }
  }
}
```

#### Event 4: `error` (Terminal Failure)
```json
{
  "type": "error",
  "data": {
    "scan_id": "4fa9b0e2-127b-4221-a477-99d863f6a200",
    "status": "failed",
    "error": "Decompression bomb detected (exceeded 100 MB ceiling)."
  }
}
```

---

### 2.5 Scan Details
`GET /api/scans/{id}`

Returns scan metadata with summary severity breakdown.

---

### 2.6 Findings List & Filtering
`GET /api/scans/{id}/findings?severity=high&status=open&source=both&skip=0&limit=50`

Query parameters supported:
* `severity`: `"critical" | "high" | "medium" | "low"`
* `status`: `"open" | "fixed" | "false_positive" | "accepted"`
* `source`: `"rule" | "ml" | "both"`
* `skip`: integer (default `0`)
* `limit`: integer (default `50`, max `100`)

---

### 2.7 Finding Detail with Catalog Remediation
`GET /api/findings/{id}`

Returns finding plus optional extended `mitigation_detail` containing code diffs and documentation references:
```json
{
  "id": "19ace23c-c98d-42e5-ad73-9eb1c65a839b",
  "scan_id": "4fa9b0e2-127b-4221-a477-99d863f6a200",
  "mitigation_id": "d0e1f2a3-b4c5-6789-0123-456789abcdef",
  "file_path": "auth.py",
  "start_line": 15,
  "end_line": 15,
  "title": "Possible SQL injection vector",
  "cwe_id": "CWE-89",
  "owasp": "A05:2025-Injection",
  "source": "both",
  "rule_id": "B608",
  "snippet": "...",
  "ml_score": 0.88,
  "severity": "high",
  "risk_score": 8.0,
  "mitigation": "Use parameterized queries.",
  "status": "open",
  "mitigation_detail": {
    "id": "d0e1f2a3-b4c5-6789-0123-456789abcdef",
    "canonical_key": "rule:B608",
    "cwe_id": "CWE-89",
    "rule_id": "B608",
    "title": "Remediation for SQL Injection",
    "remediation_guidance": "Pass parameters through the database driver execute API...",
    "code_diff": "- cursor.execute(f'SELECT * FROM users WHERE name={name}')\n+ cursor.execute('SELECT * FROM users WHERE name = %s', (name,))",
    "references_json": [
      {"name": "OWASP SQL Injection Prevention", "url": "https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html"}
    ],
    "created_at": "2026-10-28T12:00:00Z"
  }
}
```

---

### 2.8 Human-in-the-Loop Triage (Dispatches Online Feedback)
`PATCH /api/findings/{id}`

Request payload:
```json
{
  "status": "false_positive"
}
```
Supported values: `"open" | "fixed" | "false_positive" | "accepted"`.

**Feedback Learning Semantics:**
* `fixed`: Marks confirmed resolution; triggers `+1.0` positive reinforcement in online ML policy.
* `false_positive`: Marks false alarm; triggers `-1.5` suppression penalty to quiet noise.
* `accepted`: Risk acknowledged by security team; neutral audit entry (`0.0`, zero suppression).
* `open`: Initial state.

---

### 2.9 Download Reports
`GET /api/scans/{id}/report?format=html`
`GET /api/scans/{id}/report?format=pdf`

Trigger directly via browser download or `window.open()`.

---

## 3. Finding Source Semantics

* **`"rule"` (Static Rule Only):** Caught exclusively by Bandit/Semgrep AST patterns.
* **`"ml"` (Zero-Day Candidate):** Flagged exclusively by the ML detector above confidence threshold (`>= 0.70`). Represents novel or obfuscated logic that slipped past traditional AST rules.
* **`"both"` (Confirmed Vulnerability):** Corroborated by both a static rule and the ML detector.

---

## 4. Error Response Envelope

All 4xx and 5xx errors return:
```json
{
  "error": {
    "code": "SCAN_NOT_FOUND",
    "message": "Scan with ID '...' was not found.",
    "details": null
  }
}
```

---

## 5. Copy-Paste Claude Code Prompt for Member 2

Run this prompt directly in Claude Code on the `frontend` branch:

```markdown
Build and connect the React + Vite + Tailwind CSS frontend for ZeroSentinel on branch `frontend`.
Connect to the FastAPI backend running at `http://localhost:8000`.

Read `FRONTEND_INTEGRATION.md` and `CONTRACT.md` at repository root as your authoritative specification.

### Key Requirements:
1. Initialize/configure Vite React app with Tailwind CSS under `/frontend`.
2. Configure `.env` with `VITE_API_BASE_URL=http://localhost:8000` and `VITE_WS_BASE_URL=ws://localhost:8000`.
3. Create API service client wrapping fetch/axios for all endpoints in `FRONTEND_INTEGRATION.md`:
   - `POST /api/scans` (Pasted code, ZIP upload, Git URL)
   - `GET /api/scans` & `GET /api/scans/{id}`
   - `GET /api/scans/{id}/findings` (with severity, status, source filters)
   - `GET /api/findings/{id}` (with mitigation code diff)
   - `PATCH /api/findings/{id}` (Triage: open, fixed, false_positive, accepted)
   - `GET /api/stats/summary`
   - `GET /api/model/info`
   - `GET /api/scans/{id}/report?format=html|pdf`
4. Connect to `WS /ws/scans/{id}` to show live real-time progress and stream findings.
5. Provide clean UI with:
   - Header with Model Status indicator (Ready / Fallback)
   - Scan Submission form (Code editor, File dropzone for ZIP, Git URL input)
   - Scan Overview with Risk Score gauge (0–10) and severity counts
   - Findings Table with filter pills (All, Zero-Day ML Candidates, Confirmed Both, Static Rule)
   - Finding Detail Drawer/Modal showing code snippet, line numbers, and mitigation diff
   - Triage buttons (Mark Fixed, Mark False Positive, Accept Risk)
   - Export Report buttons (HTML, PDF)
6. Never expose internal filesystem paths or raw stack traces. Render loading, empty, and network error states cleanly.
```
