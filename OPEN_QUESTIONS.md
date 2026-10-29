# Open questions for the backend

The frontend is built against CONTRACT.md, including the section marked
**Feedback learning (PROPOSED)**. Everything in that section was drafted by the
frontend and needs backend sign-off. The mocks implement it exactly.

1. **Feedback learning fields and endpoints (proposed).** `ml_score_before`,
   `suppressed`, `feedback`, `Scan.rescan_of`, `Scan.model_version`, the PATCH body
   `{status, reason?, note?, train?}`, `POST /api/scans {rescan_of}`,
   `GET /api/scans/{id}/diff`, `learning` in `/api/model/info` and
   `POST /api/model/revert`. Please confirm names and shapes.
2. **Findings search and suppressed filter.** The Findings page needs text search and
   a "show suppressed" toggle with server-side pagination, so the proposal adds
   `?q` and `?include_suppressed` (default false: suppressed findings hidden).
3. **`model_card` and `eval` shapes.** The contract only says `{model_card, eval}`.
   The Model page reads the shapes written in the proposed section.
4. **`finished_at` while a scan is running.** The contract types it as always present.
   A queued or running scan has no finish time. Suggest `finished_at: string | null`.
   The frontend currently treats `finished_at === started_at` on a non-finished scan as "not finished".
5. **`snippet` line numbers and the bug line.** The frontend assumes `snippet` starts at
   `start_line` (line numbers in the code viewer count from it) and spans `start_line..end_line`.
   The contract has no field for the exact sink line, so the viewer highlights the line
   that calls a known Python sink (heuristic in `src/lib/snippet.ts`). A `sink_line` field
   would make this exact.
6. **`sort` values.** The contract has `?sort` but no values. The frontend sends
   `risk_score`, `-risk_score`, `severity`, `-severity`, `file_path`, `-file_path`
   (leading `-` = descending).
7. **Severity of a "both" finding vs. suppression.** The mocks suppress `ml` and `both`
   findings whose `ml_score` falls below the threshold on rescan; `rule` findings are
   never suppressed. Confirm that `both` findings should be suppressible.
8. **Report PDF.** In mock mode the PDF is a one-page text summary generated in the browser;
   the real `?format=pdf` should be the full report.
9. **CORS.** The frontend calls `VITE_API_URL` from another origin (port 5173/3000), and
   fetches the HTML report with `fetch`, so the backend must send CORS headers on `/api/*`
   and `/health`.
10. **Diff `suppressed` semantics.** The mocks return every suppressed finding of the scan in
    `diff.suppressed`, including ones already suppressed in the baseline. If only *newly*
    suppressed findings should be listed, the backend should say so.
