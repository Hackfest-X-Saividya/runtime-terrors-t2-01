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
