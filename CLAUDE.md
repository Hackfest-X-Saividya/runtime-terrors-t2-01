# ZeroSentinel frontend

@PROJECT_CONTEXT.md
@CONTRACT.md
@design/stitch/DESIGN.md

## Stack
- Frontend lives in /frontend: React + Vite + TypeScript + Tailwind CSS,
  React Router, TanStack Query, Recharts, MSW for mocks, Shiki for code.

## Design rules
- Visual reference: design/stitch/screens/*.png and design/stitch/*.html.
  Rebuild them as React components; never paste raw Stitch HTML into the app.
- Every colour, font, size, spacing and radius comes from DESIGN.md tokens
  configured in the Tailwind theme. Never invent new values.
- Severity and the Novel badge always show a text label, never colour alone.

## Data rules
- Types in src/types/contract.ts mirror CONTRACT.md exactly.
- If the API disagrees with the contract, stop and tell me. Do not rename fields.
- API base URL from VITE_API_URL; mocks on when VITE_USE_MOCKS=true.

## Working rules
- Plan before large changes and wait for my OK.
- Small components in src/components, one folder per page in src/pages.
- After each task, run npm run build and fix type errors before saying done.