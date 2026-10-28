# ZeroSentinel — AI-Powered Vulnerability Scanner & Correlation Platform

[![Backend Tests](https://img.shields.io/badge/Backend%20Tests-125%20Passed-brightgreen)](backend/tests)
[![ML Tests](https://img.shields.io/badge/ML%20Tests-20%20Passed-brightgreen)](ml/tests)
[![Frontend Tests](https://img.shields.io/badge/Frontend%20Tests-23%20Passed-brightgreen)](frontend/src)
[![Python](https://img.shields.io/badge/Python-3.11-blue)](https://python.org)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.115+-009688)](https://fastapi.tiangolo.com)
[![React](https://img.shields.io/badge/React-19.1-61dafb)](https://react.dev)
[![Vite](https://img.shields.io/badge/Vite-6.4-646CFF)](https://vitejs.dev)
[![Tailwind CSS](https://img.shields.io/badge/Tailwind-3.4-38B2AC)](https://tailwindcss.com)
[![Supabase](https://img.shields.io/badge/Database-Supabase%20PostgreSQL-3ECF8E)](https://supabase.com)

**ZeroSentinel** is an enterprise-grade AI-powered cybersecurity vulnerability scanner and correlation platform designed for rapid static analysis, explainable threat deduplication, and zero-day candidate discovery.

Combining deterministic static rule engines (Semgrep & Bandit) with machine learning AST classifiers and contextual reinforcement learning, ZeroSentinel discovers confirmed vulnerabilities and novel threat candidates while mapping them to industry-standard security frameworks.

---

## Key Capabilities

### 1. Dual-Engine Static Analysis & Correlation
- **Static Pattern Matching:** Rule-based detection using Bandit and Semgrep with rule attribution (e.g. `B608`, `B102`, `python.lang.security`).
- **Statistical ML Inference:** Function-level vulnerability scoring using a sublinear TF-IDF vectorizer + regularized Logistic Regression classifier trained on the VUDENC software vulnerability dataset.
- **Explainable Correlation Engine:** Groups co-located findings using deterministic 12-character hexadecimal cluster IDs (`cl_<hash>`), identifies `exact_duplicate` entries to prevent risk score inflation, corroborates dual-engine hits (`source="both"`), and isolates novel zero-day hypotheses (`standalone_candidate`).

### 2. FIRST CVSS v3.1 Specification
- Strictly compliant CVSS v3.1 Base Score implementation using the official FIRST Appendix A roundup algorithm.
- Complete vector validation (`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`).
- Clear provenance tracking: `analyst_assessed`, `rule_estimated`, and `unassessed`.
- CVSS technical scores remain strictly separate from ZeroSentinel's proprietary contextual risk score (0–10).

### 3. OWASP Top 10:2025 Framework
- Standardized mapping against the official 2025 taxonomy (`A01:2025` through `A10:2025`).
- Multi-category mapping with explicit primary designation, confidence levels (`high`, `medium`, `low`), and non-evaluative technical rationales.

### 4. NIST Cybersecurity Framework (CSF) 2.0
- Aligned to all 6 NIST CSF 2.0 core functions: **Govern (`GV`)**, **Identify (`ID`)**, **Protect (`PR`)**, **Detect (`DE`)**, **Respond (`RS`)**, and **Recover (`RC`)**.
- Concrete technical subcategory mappings (e.g., `PR.PS-01`, `PR.AA-01`, `PR.DS-02`) with cross-references to NIST SP 800-53 Rev. 5 controls (`SI-2`, `AC-3`, `SC-8`).

### 5. Active Feedback Reinforcement Learning Loop
- Contextual bandit online learning adjusts classifier weights when security analysts triage findings (`false_positive`, `fixed`, `accepted`).
- Suppresses repetitive false positives across rescans while reinforcing true positive detections.
- Safe atomic persistence to disk (`rl_state.json`) with cross-process file locking.

### 6. Real-Time Streaming & Reporting
- Live scan progression and finding streaming via duplex WebSockets (`/ws/scans/{id}`).
- Executive summary statistics and aggregated posture dashboards.
- Audit-ready report generation in both standalone HTML and downloadable PDF formats.

---

## Repository Branch Organization

To maintain team velocity and isolated responsibilities:

| Branch | Responsibilities | Core Stack |
| :--- | :--- | :--- |
| **`Backend`** | FastAPI backend, Supabase database, Alembic migrations, security framework mappers, scan pipeline, tests | Python 3.11, FastAPI, SQLAlchemy, Alembic, SQLite, PostgreSQL |
| **`frontend`** | React 19 UI, Vite build, Tailwind CSS, API client, in-browser mock backend, vitest tests | TypeScript, React 19, Vite, Tailwind CSS, TanStack Query, Recharts |
| **`ai/ml`** | ML model training, baseline vectorizer, CodeBERT evaluation, VUDENC preprocessing | Python, PyTorch, Transformers, Scikit-Learn |
| **`main`** | Stable integration releases | — |

---

## Quick Start (Local Development)

### 1. Prerequisites
- Python 3.11+
- Node.js 20+ and npm 10+
- Git

### 2. Backend Setup
```bash
# Clone the repository
git clone https://github.com/Hackfest-X-Saividya/runtime-terrors-t2-01.git
cd runtime-terrors-t2-01
git checkout Backend

# Set up Python virtual environment
cd backend
python -m venv .venv
source .venv/bin/activate  # Windows: .venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Run database migrations (or use local SQLite for dev)
alembic upgrade head

# Start FastAPI development server
uvicorn app.main:app --reload --port 8000
```
API Documentation will be available at `http://localhost:8000/docs`.

### 3. Frontend Setup
```bash
# In a separate terminal or worktree on branch frontend:
git checkout frontend
cd frontend

# Install dependencies
npm install

# Start Vite development server
npm run dev
```
Open `http://localhost:5173` to interact with the ZeroSentinel dashboard.

---

## Verification & Test Suites

ZeroSentinel maintains comprehensive automated test suites across all layers:

### Backend & ML Tests (145 Passing)
```bash
# From repository root with backend virtual environment active:
pytest backend/tests ml/tests -v
```
- **125 Backend Tests:** CVSS calculator, OWASP 2025 mapper, NIST CSF 2.0 mapper, correlation engine, Alembic migrations, REST endpoints, WebSocket streaming, and scan pipeline.
- **20 ML Tests:** AST tokenizer, baseline TF-IDF inference, held-out evaluation, and reinforcement learning feedback state persistence.

### Frontend Tests (23 Passing & Production Build)
```bash
# From the frontend directory:
npm test            # 23 unit tests (vitest)
npm run lint        # ESLint 9 (0 errors, 0 warnings)
npm run build       # TypeScript compilation & Vite production bundle
```

---

## Production Deployment

ZeroSentinel is optimized for rapid cloud deployment:
- **Frontend:** Deploy to **Vercel** with client-side SPA routing (`vercel.json`).
- **Backend:** Deploy to a persistent container service (**Render**, **Railway**, or **GCP Cloud Run**).
- **Database:** Hosted on **Supabase PostgreSQL** with SSL pooling (`aws-0-*.pooler.supabase.com:6543`).

See [`DEPLOYMENT.md`](file:///DEPLOYMENT.md) for complete environment variable matrices and step-by-step production guides.

---

## Research & Ethical Disclosure Notice

> [!CAUTION]
> **Ethical Zero-Day Hypothesis Disclaimer:**
> Candidate novel vulnerabilities flagged solely by machine learning inference (`source="ml"`, `standalone_candidate`) represent probabilistic feature correlations and AST token anomalies. They are **not verified exploits**. In accordance with responsible disclosure principles, candidate zero-days require manual analyst triage and verified proof-of-concept testing in controlled environments prior to remediation or public reporting.
