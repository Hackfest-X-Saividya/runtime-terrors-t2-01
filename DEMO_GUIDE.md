# ZeroSentinel — Reproducible Demonstration Guide

This guide provides instructions for launching, verifying, and demonstrating the **ZeroSentinel** AI-powered zero-day vulnerability detection engine.

---

## 1. Prerequisites & Environment Setup

### System Requirements
* **Operating System:** Windows 10/11, macOS, or Linux.
* **Python Runtime:** Python 3.11.x (verified on Python 3.11.9).
* **Virtual Environment:** Configured locally at `backend/.venv`.

### Activation
```powershell
# Windows PowerShell
.\backend\.venv\Scripts\Activate.ps1

# Linux / macOS
source backend/.venv/bin/activate
```

### Environment Configuration
Copy `.env.example` to `.env` if not already present:
```powershell
Copy-Item .env.example .env
```
Key defaults:
* `APP_PORT=8000`
* `APP_HOST=0.0.0.0`
* `DATABASE_URL=postgresql+asyncpg://postgres:postgres@localhost:5432/zerosentinel`
* `ML_ARTIFACTS_PATH=ml/artifacts`
* `ML_STANDALONE_THRESHOLD=0.70`

---

## 2. PostgreSQL 16 Target & Current Offline Status

ZeroSentinel is architected for **PostgreSQL 16**.

### Current Verification Status:
* During local offline testing, PostgreSQL 16 is not running locally.
* All 121 automated backend and ML tests run in isolated SQLite in-memory environments with foreign keys and regular expression support.
* In production, the backend connects to PostgreSQL 16 using `asyncpg`.

### Starting PostgreSQL 16 (When Docker Is Available):
```bash
docker run -d \
  --name zerosentinel-postgres \
  -e POSTGRES_USER=postgres \
  -e POSTGRES_PASSWORD=postgres \
  -e POSTGRES_DB=zerosentinel \
  -p 5432:5432 \
  postgres:16-alpine
```

### Applying Database Migrations:
```bash
cd backend
alembic upgrade head
cd ..
```

---

## 3. Starting the Backend Server

Start the FastAPI application with Uvicorn:
```powershell
$env:PYTHONPATH = "backend;ml"
.\backend\.venv\Scripts\python.exe -m uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
```

Server endpoints:
* **API Base URL:** `http://localhost:8000`
* **Interactive OpenAPI Docs:** `http://localhost:8000/docs`
* **Health Probe:** `http://localhost:8000/health`
* **ML Model Info:** `http://localhost:8000/api/model/info`

---

## 4. Pre-Flight Verification

Verify server health and model readiness:

```bash
# Health Check (Probes server and database connection)
curl -s http://localhost:8000/health

# Model Runtime Info (Verifies real ML detector is loaded)
curl -s http://localhost:8000/api/model/info
```

Expected `/api/model/info` response:
```json
{
  "model_name": "ZeroSentinel Dual-Engine Vulnerability Detector",
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

## 5. Live Demonstration Sequence

### Automated Walkthrough (Single Command)
You can run the end-to-end demo walkthrough script at any time:
```powershell
$env:PYTHONPATH = "backend;ml"
.\backend\.venv\Scripts\python.exe backend/scripts/demo_walkthrough.py
```

### Manual Interactive Demonstration

#### Step 1: Submit Code for Analysis
Submit the demo target fixture [`data/samples/vuln_demo.py`](file:///data/samples/vuln_demo.py):
```bash
curl -X POST http://localhost:8000/api/scans \
  -H "Content-Type: application/json" \
  -d '{
    "submission_type": "code",
    "project_name": "DemoService",
    "language": "python",
    "source_code": "def run_cmd(host):\n    import subprocess\n    return subprocess.check_output(f\"ping {host}\", shell=True)\n"
  }'
```
Response: HTTP `202 Accepted` returning a UUID `scan_id`.

#### Step 2: Stream Live Scan Progress via WebSocket
Connect your WebSocket client (or browser) to:
`ws://localhost:8000/ws/scans/<scan_id>`

Observed events:
1. `{"type": "progress", "data": {"scan_id": "...", "status": "scanning", "step": "Running AST function extraction..."}}`
2. `{"type": "progress", "data": {"scan_id": "...", "status": "analyzing_ml", "step": "Running ML inference..."}}`
3. `{"type": "finding", "data": {"scan_id": "...", "finding": { ... }}}`
4. `{"type": "done", "data": {"scan_id": "...", "status": "completed", "risk_score": 8.0, "findings_count": 1}}`

#### Step 3: Inspect Findings & Risk Scores
```bash
# Retrieve findings list
curl -s http://localhost:8000/api/scans/<scan_id>/findings

# Retrieve specific finding detail with canonical remediation catalog entry
curl -s http://localhost:8000/api/findings/<finding_id>
```

#### Step 4: Human-in-the-Loop Triage & Online Feedback Learning
Triage an open finding:
```bash
# Mark as false positive (triggers suppression penalty in online Contextual Bandit)
curl -X PATCH http://localhost:8000/api/findings/<finding_id> \
  -H "Content-Type: application/json" \
  -d '{"status": "false_positive"}'

# Or mark as fixed (triggers positive reinforcement)
curl -X PATCH http://localhost:8000/api/findings/<finding_id> \
  -H "Content-Type: application/json" \
  -d '{"status": "fixed"}'

# Or mark as accepted (neutral audit record; zero suppression penalty)
curl -X PATCH http://localhost:8000/api/findings/<finding_id> \
  -H "Content-Type: application/json" \
  -d '{"status": "accepted"}'
```

#### Step 5: Download Vulnerability Audit Reports
```bash
# Download HTML Report (XSS-safe, zero external CDN scripts)
curl -s "http://localhost:8000/api/scans/<scan_id>/report?format=html" -o report.html

# Download ReportLab PDF Report
curl -s "http://localhost:8000/api/scans/<scan_id>/report?format=pdf" -o report.pdf
```

---

## 6. Safe Shutdown & State Cleanliness

To stop the development server:
* Press `Ctrl+C` in the terminal.
* Feedback weights and audit history are persisted atomically to `ml/artifacts/rl_state.json` (protected by cross-process file locks).
* `rl_state.json`, `.lock`, and `.tmp` files are ignored by `.gitignore` to prevent tracking of local demo state in Git.

---

## 7. Starting the React Frontend (Branch `frontend`)

The ZeroSentinel React web client lives on branch `frontend`. To run both side-by-side without file collisions:

```powershell
# In a second terminal window:
git checkout frontend
cd frontend
npm install
npm run dev
# The React dashboard will be available at http://127.0.0.1:5173
```

### Verified Runtime Model Architecture
* **Primary Runtime Engine:** TF-IDF Code Vectorizer + Class-Weighted Logistic Regression (`ml/artifacts/binary_model.joblib`, `ml/artifacts/cwe_model.joblib`).
* **Continuous Online Adaptation:** Contextual Bandit Reinforcement Learning policy (`detector/feedback.py`) adjusting scores in real time based on triage decisions (`ml/artifacts/rl_state.json`).
* **Evaluation Ground Truth:** Benchmark metrics strictly derived from VUDENC Python dataset (75 train, 18 val, 18 test) across 7 CWE types. Test set performance: ROC-AUC 0.925, Precision 1.0, Recall 0.75, F1 0.857.
* **Deep Learning Pipeline (CodeBERT):** Dual-head CodeBERT fine-tuning pipeline is implemented in `ml/train_codebert.py` with GPU configuration manifest in `ml/artifacts/codebert/codebert_manifest.json`.
