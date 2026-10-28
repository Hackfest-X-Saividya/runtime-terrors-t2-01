// Mirrors CONTRACT.md exactly, including the "Feedback learning (PROPOSED)" section.
// Do not rename or add fields here without changing CONTRACT.md first.

export type Severity = 'critical' | 'high' | 'medium' | 'low'
export type FindingSource = 'rule' | 'ml' | 'both'
export type FindingStatus = 'open' | 'fixed' | 'false_positive' | 'accepted'

export type ScanSourceType = 'zip' | 'git' | 'paste'
export type ScanStatus = 'queued' | 'running' | 'done' | 'failed' | 'partial'
export type ScanStage = 'unpack' | 'rules' | 'ml' | 'ranking'

export type SeverityCounts = Record<Severity, number>

/** (proposed) Feedback attached to a finding. */
export interface Feedback {
  reason: string | null
  note: string | null
  train: boolean
  /** ISO 8601 */
  created_at: string
  model_version: string
}

export interface Finding {
  id: string
  scan_id: string
  file_path: string
  start_line: number
  end_line: number
  snippet: string
  title: string
  /** e.g. "CWE-89" */
  cwe_id: string
  /** e.g. "A05:2025 Injection" */
  owasp: string
  source: FindingSource
  rule_id: string | null
  /** 0-1 */
  ml_score: number | null
  severity: Severity
  /** 0-10 */
  risk_score: number
  /** markdown */
  mitigation: string
  status: FindingStatus
  /** (proposed) ml_score before feedback lowered it, 0-1 */
  ml_score_before: number | null
  /** (proposed) hidden by feedback learning on rescan */
  suppressed: boolean
  /** (proposed) */
  feedback: Feedback | null
}

export interface Scan {
  id: string
  name: string
  source_type: ScanSourceType
  status: ScanStatus
  stage: ScanStage
  files_scanned: number
  functions_scanned: number
  risk_score: number
  counts_by_severity: SeverityCounts
  /** ISO 8601 */
  started_at: string
  /** ISO 8601 */
  finished_at: string
  /** (proposed) scan this one re-ran */
  rescan_of: string | null
  /** (proposed) ML model version used */
  model_version: string
}

/** GET /api/stats/summary */
export interface Summary {
  total_scans: number
  total_findings: number
  novel_count: number
  by_severity: SeverityCounts
  by_owasp: Record<string, number>
  by_source: Record<FindingSource, number>
  top_findings: Finding[]
  last_scan: Scan
}

/** POST /api/scans body: multipart zip | {git_url} | {code, filename} | (proposed) {rescan_of} */
export type CreateScanInput =
  | { kind: 'zip'; file: File }
  | { kind: 'git'; git_url: string }
  | { kind: 'paste'; code: string; filename: string }
  | { kind: 'rescan'; rescan_of: string }

export interface CreateScanResponse {
  scan_id: string
}

/** Sort values: field name, leading "-" = descending (see OPEN_QUESTIONS.md). */
export type FindingSort = 'risk_score' | '-risk_score' | 'severity' | '-severity' | 'file_path' | '-file_path'

/** GET /api/scans/{id}/findings query */
export interface FindingsQuery {
  severity?: Severity
  owasp?: string
  source?: FindingSource
  status?: FindingStatus
  sort?: FindingSort
  limit?: number
  offset?: number
  /** (proposed) text search */
  q?: string
  /** (proposed) default false */
  include_suppressed?: boolean
}

export interface FindingsPage {
  items: Finding[]
  total: number
}

/** PATCH /api/findings/{id} body. reason/note/train are (proposed). */
export interface UpdateFindingInput {
  status: FindingStatus
  reason?: string
  note?: string
  train?: boolean
}

/** (proposed) GET /api/scans/{id}/diff */
export interface ScanDiff {
  previous_scan_id: string | null
  new: Finding[]
  suppressed: Finding[]
  still_open: Finding[]
  resolved: Finding[]
}

export type ReportFormat = 'html' | 'pdf'

/** (proposed shape) */
export interface ModelCard {
  name: string
  version: string
  architecture: string
  training_data: string
  languages: string[]
  threshold: number
}

/** (proposed shape) one vulnerability type the model never saw in training */
export interface HeldOutType {
  vuln_type: string
  cwe_id: string
  detection_rate: number
  fpr: number
  samples: number
}

/** (proposed shape) */
export interface ModelEval {
  precision: number
  recall: number
  f1: number
  roc_auc: number
  held_out: HeldOutType[]
}

/** (proposed) */
export interface ModelVersion {
  version: string
  /** ISO 8601 */
  created_at: string
  trigger: string
  f1: number
  fpr: number
}

/** (proposed) */
export interface ModelLearning {
  version: string
  threshold: number
  feedback_count: number
  suppressed_count: number
  versions: ModelVersion[]
  recent_feedback: Finding[]
}

/** GET /api/model/info */
export interface ModelInfo {
  model_card: ModelCard
  eval: ModelEval
  /** (proposed) */
  learning: ModelLearning
}

/** (proposed) POST /api/model/revert */
export interface RevertModelInput {
  version: string
}

export interface RevertModelResponse {
  version: string
}

/** GET /health */
export interface Health {
  ok: true
}

/** WebSocket /ws/scans/{id} */
export type ScanSocketMessage =
  | { type: 'progress'; data: { stage: ScanStage; done: number; total: number } }
  | { type: 'finding'; data: Finding }
  | { type: 'done'; data: Scan }
