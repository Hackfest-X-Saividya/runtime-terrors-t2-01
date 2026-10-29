# ZeroSentinel frontend

React dashboard for ZeroSentinel: submit code, watch the rule engine and ML model
scan it live, triage findings, teach the model with feedback, and export risk reports.

Built with Vite, React 19, TypeScript, Tailwind CSS 3, React Router 7, TanStack Query 5,
Recharts, MSW 2, react-dropzone and Shiki.

- Data shapes: [`../CONTRACT.md`](../CONTRACT.md), including the **Feedback learning (PROPOSED)**
  section the frontend drafted. Open points are listed in [`../OPEN_QUESTIONS.md`](../OPEN_QUESTIONS.md).
- Visual tokens: [`../design/stitch/DESIGN.md`](../design/stitch/DESIGN.md); screens:
  `../design/stitch/screens/*.png`.
- Demo script: [`DEMO.md`](DEMO.md).

## Setup

Needs Node 20+ (built with Node 24 / npm 11).

```bash
npm install
npm run dev          # http://localhost:5173, sample data on by default
```

| Script            | What it does                                            |
| ----------------- | ------------------------------------------------------- |
| `npm run dev`     | Dev server with hot reload                              |
| `npm run build`   | Type-check (`tsc -b`) and production build into `dist/` |
| `npm run lint`    | ESLint, zero warnings allowed                           |
| `npm test`        | Vitest: API client, mock backend, feedback learning     |
| `npm run format`  | Prettier                                                |
| `npm run preview` | Serve the production build                              |

## Environment variables

| Variable         | Default                 | Meaning                                                                                 |
| ---------------- | ----------------------- | --------------------------------------------------------------------------------------- |
| `VITE_API_URL`   | `http://localhost:8000` | FastAPI base URL. REST calls and the `ws://…/ws/scans/{id}` socket are derived from it. |
| `VITE_USE_MOCKS` | `true` (in `.env`)      | `true`: everything runs on in-browser sample data. `false`: calls `VITE_API_URL`.       |

Both are baked in at build time. Put local overrides in `.env.local` (see `.env.example`).

## Mocks vs the real API

**Mock mode** is on when `VITE_USE_MOCKS=true`, or when the URL has `?mock=1` (remembered for
the tab; `?mock=0` turns it off again). The top bar shows **Mock mode**, and data is labelled
**Sample data** where it matters.

- Every endpoint in CONTRACT.md is served by MSW handlers (`src/mocks/handlers.ts`) backed by an
  in-memory database (`src/mocks/db.ts`): 3 scans, 60 Python findings covering all severities,
  all sources (11 ML-only), all 10 OWASP 2025 categories and real CWE IDs.
- The scan WebSocket is replaced by an in-page fake that plays a 20-second scan:
  unpack → rules → ML → ranking, streaming 15 findings, then `done`.
- **Feedback learning:** marking an `ml` or `both` finding as a false positive with
  "Use this to improve the model" bumps the model version and lowers `ml_score` (keeping
  `ml_score_before`) for that finding and same-CWE findings in the same file. A re-scan then
  suppresses findings below the 0.5 threshold and lists them in the scan diff. Rule-only
  findings never change the model. Revert on the Model page undoes newer versions.
- Changes survive reloads within the tab (sessionStorage). **Reset sample data** in the sidebar,
  or `?reset=1`, starts over.
- MSW prefers its service worker. Browsers without service workers (some embedded browsers)
  fall back to routing `fetch` through the same handlers in-page, automatically.

**Real API mode** (`VITE_USE_MOCKS=false`): the top bar shows **API online/offline** from
`GET /health`. If the socket drops, the New Scan page retries 3 times with backoff, then polls
`GET /api/scans/{id}` and the findings list every 2 s. The backend must allow CORS from the
frontend origin.

## Screen tour

| Route                 | Screen                                                                                                      |
| --------------------- | ----------------------------------------------------------------------------------------------------------- |
| `/`                   | **Dashboard**: KPIs (incl. false positives suppressed), severity donut, OWASP bars, recent scans, top risks |
| `/scan/new`           | **New Scan**: zip (50 MB), Git URL, paste, _Run demo scan_; live stages + findings feed; finished summary   |
| `/scans/:id/findings` | **Findings**: URL-synced filters, sortable/paginated table, Novel + score-change badges, bulk feedback      |
| `/findings/:id`       | **Finding detail**: Shiki code with the sink highlighted, risk gauge, CWE/OWASP links, fix, triage          |
| `/scans/:id/changes`  | **Scan changes**: new, suppressed by feedback, still open (and resolved) vs. the previous scan              |
| `/reports/:id?`       | **Reports**: scan picker, summary, sandboxed HTML preview, PDF/HTML download                                |
| `/model`              | **Model**: model card, metrics, held-out types table + chart, learning loop, version timeline with Revert   |

Keyboard: `[` / `]` move between findings on the detail page; every control has a visible focus ring.

## Design rules

`tailwind.config.ts` builds the theme from `src/lib/tokens.ts`, which copies DESIGN.md. Tailwind's
default colours, font sizes, font families and radii are **replaced**, so off-palette classes such
as `text-red-500` or `text-xl` don't exist. Charts, the Shiki theme and the report HTML read the
same tokens. Severity, status and Novel always render a text label.

## Layout

```
src/
  types/contract.ts   mirrors CONTRACT.md (do not rename fields)
  api/                fetch client (ApiError), TanStack Query hooks
  hooks/              scan socket (reconnect + polling), URL filters, toasts, rescan
  lib/                tokens, labels, formatting, env/mock flags, snippet helpers
  mocks/              MSW handlers, in-memory db, templates, fake socket, report/PDF
  components/         shared UI + layout/ + charts/
  pages/<page>/       one folder per page, lazy-loaded
```

## Docker

```bash
docker build -t zerosentinel-frontend --build-arg VITE_USE_MOCKS=false --build-arg VITE_API_URL=http://localhost:8000 .
docker run -p 3000:80 zerosentinel-frontend
```

Compose service for the root `docker-compose.yml`:

```yaml
frontend:
  build:
    context: ./frontend
    args:
      VITE_API_URL: http://localhost:8000
      VITE_USE_MOCKS: 'false'
  ports: ['3000:80']
```
