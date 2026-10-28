# ZeroSentinel — Production Deployment Guide

This guide details the deployment architecture, environment configurations, database migration procedures, and hosting instructions for ZeroSentinel.

---

## 1. Architecture & Deployment Overview

ZeroSentinel consists of three primary components:
1. **Frontend (React 19 / Vite / TypeScript / Tailwind CSS):** Single Page Application deployed to **Vercel** with client-side SPA routing (`vercel.json`) and WebSocket streaming listeners.
2. **Backend (FastAPI / Python 3.11 / SQLAlchemy / Alembic):** Asynchronous REST and WebSocket API deployed on a **persistent container or VM host** (e.g., Render, Railway, Fly.io, AWS App Runner, or GCP Cloud Run).
3. **Database (Supabase PostgreSQL):** Managed PostgreSQL instance accessed via transaction pooling (port 6543) or session pooling (port 5432) with SSL enforcement.

```
                          ┌───────────────────────────┐
                          │   Vercel Edge Network     │
                          │   (React 19 / Vite SPA)   │
                          └─────────────┬─────────────┘
                                        │ HTTPS / WSS
                                        ▼
                          ┌───────────────────────────┐
                          │    FastAPI Application    │
                          │   (Persistent Container)  │
                          │   - REST API              │
                          │   - WebSocket Server      │
                          │   - Analysis Orchestrator │
                          │   - ML Inference Engine   │
                          └──────┬─────────────┬──────┘
                                 │             │
                    pgvector/SQL │             │ ML Artifacts / AST
                                 ▼             ▼
      ┌────────────────────────────┐         ┌─────────────────────────┐
      │   Supabase PostgreSQL      │         │ Bandit & Semgrep Engines│
      │   - Alembic Version Head   │         │ TF-IDF + Logistic Reg   │
      │   - Security Frameworks    │         │ Online Bandit RL State  │
      └────────────────────────────┘         └─────────────────────────┘
```

> [!IMPORTANT]
> **Why Serverless Function Hosting is Not Recommended for the Backend:**
> Standard serverless runtimes (AWS Lambda, Vercel Serverless Functions) impose execution timeouts (typically 10–30s on free tiers), drop persistent WebSocket duplex streams, and lack local scratch filesystems necessary for multi-file archive extraction and CLI subprocess orchestration (Bandit/Semgrep). Use containerized environments with persistent connection lifecycles.

---

## 2. Environment Variables Matrix

### A. Backend (`backend/.env` or Host Environment)

| Variable | Required | Default | Description | Example |
| :--- | :---: | :---: | :--- | :--- |
| `DATABASE_URL` | **Yes** | `sqlite+aiosqlite:///./test.db` | Async PostgreSQL connection string for Supabase | `postgresql+asyncpg://postgres.PROJECT_REF:PASSWORD@aws-0-REGION.pooler.supabase.com:6543/postgres` |
| `SUPABASE_DB_PASSWORD` | **Yes** | — | Supabase database user password (percent-encoded if special characters) | `s3cur3%23p4ss!` |
| `DB_SSL` | Optional | `require` | SSL mode for PostgreSQL connection (`require` for Supabase) | `require` |
| `CORS_ORIGINS` | **Yes** | `http://localhost:5173,http://127.0.0.1:5173` | Comma-separated list or JSON array of permitted frontend origins | `https://zerosentinel.vercel.app,http://localhost:5173` |
| `SECRET_KEY` | Optional | `insecure-dev-secret-key-change-in-production` | Secret key for session encryption and signing | `prod-random-64-char-hex-secret` |
| `ENVIRONMENT` | Optional | `development` | Deployment tier: `development`, `staging`, `production` | `production` |
| `LOG_LEVEL` | Optional | `INFO` | Python logging severity: `DEBUG`, `INFO`, `WARNING`, `ERROR` | `INFO` |
| `BANDIT_BIN` | Optional | auto-detected | Path to bandit CLI binary in environment | `/opt/venv/bin/bandit` |

> [!WARNING]
> **Password Percent-Encoding in Database URLs:**
> If your Supabase password contains reserved URL characters (such as `%`, `#`, `@`, or `/`), they must be percent-encoded (e.g. `#` becomes `%23`). Alembic's ConfigParser requires double-percent `%%` escaping, which is automatically handled in `backend/alembic/env.py`.

### B. Frontend (`frontend/.env` or Vercel Environment)

| Variable | Required | Default | Description | Example |
| :--- | :---: | :---: | :--- | :--- |
| `VITE_API_URL` | **Yes** | `http://localhost:8000` | Public URL of the FastAPI backend service | `https://api.zerosentinel.com` |
| `VITE_API_BASE_URL` | Optional | — | Alias for `VITE_API_URL` | `https://api.zerosentinel.com` |
| `VITE_USE_MOCKS` | Optional | `false` | Enable in-browser MSW mock database for demo/preview mode | `false` |

---

## 3. Database Migration Procedure (Supabase)

The live Supabase database is currently initialized at migration `001_initial_schema`.
Migration `002_security_frameworks` adds the additive columns for CVSS v3.1, OWASP Top 10:2025, NIST CSF 2.0, and explainable correlation.

### Pre-requisites
1. Verify Supabase project access.
2. Ensure you have the `DATABASE_URL` with percent-encoded credentials ready.

### Execution Steps
From the repository root with the backend virtual environment activated:

```bash
# 1. Switch to backend directory
cd backend

# 2. Check current migration state (should report 001_initial_schema)
alembic current

# 3. Apply migration 002_security_frameworks
alembic upgrade head

# 4. Verify head status
alembic current
```

### Verification SQL
Execute this read-only query in the Supabase SQL Editor:

```sql
-- 1. Verify Alembic revision
SELECT version_num FROM alembic_version;
-- Expected output: 002_security_frameworks

-- 2. Verify additive columns on findings table
SELECT column_name, data_type, is_nullable
FROM information_schema.columns
WHERE table_name = 'findings'
  AND column_name IN (
    'cvss_score',
    'cvss_vector',
    'cvss_severity',
    'cvss_provenance',
    'security_frameworks',
    'correlation_data'
  )
ORDER BY column_name;
```

---

## 4. Frontend Deployment on Vercel

The frontend is contained on the `frontend` branch.

### Step-by-Step Vercel Setup
1. **Import Repository:**
   - Link `https://github.com/Hackfest-X-Saividya/runtime-terrors-t2-01` in Vercel.
   - Select production branch: `frontend`.
2. **Build and Output Settings:**
   - **Framework Preset:** Vite
   - **Root Directory:** `frontend` (or `.` if deploying from root; `vercel.json` exists in both locations)
   - **Build Command:** `npm run build`
   - **Output Directory:** `dist`
3. **Environment Variables:**
   - Add `VITE_API_URL` = `https://<YOUR-BACKEND-DOMAIN>` (e.g. `https://api.zerosentinel.com`)
4. **Deploy:** Click **Deploy**. Vercel will run `tsc -b && vite build` and serve the optimized static bundles.

---

## 5. Backend Deployment (Render / Railway / GCP Cloud Run)

### Recommended: Render Web Service
1. **Repository & Branch:** Select `https://github.com/Hackfest-X-Saividya/runtime-terrors-t2-01`, branch `Backend`.
2. **Environment:** Python 3 (or Docker).
3. **Root Directory:** `.` (or `backend`).
4. **Build Command:**
   ```bash
   pip install --upgrade pip && pip install -r backend/requirements.txt
   ```
5. **Start Command:**
   ```bash
   uvicorn backend.app.main:app --host 0.0.0.0 --port $PORT --workers 2
   ```
6. **Environment Variables:** Add `DATABASE_URL`, `CORS_ORIGINS`, `DB_SSL=require`, `ENVIRONMENT=production`.

---

## 6. Security & Responsible Disclosure Statement

> [!CAUTION]
> **Ethical Usage & Zero-Day Candidates:**
> ZeroSentinel incorporates machine learning anomaly models to flag potential novel vulnerability patterns (zero-day candidates). ML predictions represent statistical hypotheses based on AST token patterns and holdout benchmark distributions; they are **not confirmed exploits**. Automated candidate alerts must always undergo manual review, source code triage, and controlled validation prior to disclosure. Never execute unauthorized penetration tests against systems without explicit permission.
