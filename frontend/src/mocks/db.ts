import type {
  Feedback,
  Finding,
  FindingSource,
  FindingsQuery,
  ModelInfo,
  ModelVersion,
  Scan,
  ScanDiff,
  ScanSocketMessage,
  ScanSourceType,
  ScanStage,
  Severity,
  SeverityCounts,
  Summary,
  UpdateFindingInput,
} from '@/types/contract'
import { templates, type Template } from './templates'

// In-memory mock backend. Everything resets on page reload (or resetDb() in tests).

const THRESHOLD = 0.5
/** Feedback multiplies the ML score by this for the finding and its same-file, same-CWE siblings. */
const FEEDBACK_FACTOR = 0.35
const SCAN_SECONDS = 20
const severityRank: Severity[] = ['critical', 'high', 'medium', 'low']

// ---------- deterministic randomness ----------

function hash(s: string): number {
  let h = 2166136261
  for (let i = 0; i < s.length; i++) h = Math.imul(h ^ s.charCodeAt(i), 16777619)
  return h >>> 0
}

/** Stable pseudo-random number in [0, 1) for a key. */
function rand(key: string): number {
  let t = hash(key) + 0x6d2b79f5
  t = Math.imul(t ^ (t >>> 15), t | 1)
  t ^= t + Math.imul(t ^ (t >>> 7), t | 61)
  return ((t ^ (t >>> 14)) >>> 0) / 4294967296
}

const round = (n: number, digits: number) => Math.round(n * 10 ** digits) / 10 ** digits

const riskBands: Record<Severity, [number, number]> = {
  critical: [9.0, 9.8],
  high: [7.0, 8.9],
  medium: [4.0, 6.9],
  low: [1.5, 3.9],
}

function scoresFor(t: Template, siteKey: string) {
  const [lo, hi] = riskBands[t.severity]
  const risk_score = round(lo + rand(`risk:${siteKey}`) * (hi - lo), 1)
  const ml_score = t.source === 'rule' ? null : round(0.58 + rand(`ml:${siteKey}`) * 0.39, 2)
  return { risk_score, ml_score }
}

// ---------- state ----------

interface VersionEffect {
  id: string
  ml_score: number | null
  ml_score_before: number | null
}

interface State {
  scans: Scan[]
  findings: Finding[]
  versions: ModelVersion[]
  /** file_path|cwe_id -> model version that learned to lower it */
  learned: Map<string, string>
  /** model version -> findings it changed, so Revert can restore them */
  effects: Map<string, VersionEffect[]>
  listeners: Map<string, Set<(msg: ScanSocketMessage) => void>>
  /** messages already sent per running scan, replayed to late socket connections */
  sent: Map<string, ScanSocketMessage[]>
  timers: ReturnType<typeof setTimeout>[]
  nextScan: number
  /** feedback events sent with train=true */
  trainEvents: number
}

const learnKey = (f: Pick<Finding, 'file_path' | 'cwe_id'>) => `${f.file_path}|${f.cwe_id}`
const fingerprint = (f: Pick<Finding, 'file_path' | 'cwe_id' | 'title'>) => `${f.file_path}|${f.cwe_id}|${f.title}`
const ago = (now: number, hours: number) => new Date(now - hours * 3_600_000).toISOString()

function siteOf(key: string): { t: Template; site: [string, number, string]; siteKey: string } {
  const [tKey, idx] = key.split('#')
  const t = templates.find((x) => x.key === tKey)
  if (!t) throw new Error(`unknown template ${tKey}`)
  const site = t.sites[Number(idx)]
  return { t, site, siteKey: key }
}

function makeFinding(id: string, scanId: string, key: string, filePath?: string, line?: number): Finding {
  const { t, site, siteKey } = siteOf(key)
  const snippet = t.snippet(site[2])
  const start = line ?? site[1]
  return {
    id,
    scan_id: scanId,
    file_path: filePath ?? site[0].replace(/^\w+:/, ''),
    start_line: start,
    end_line: start + snippet.split('\n').length - 1,
    snippet,
    title: t.title,
    cwe_id: t.cwe_id,
    owasp: t.owasp,
    source: t.source,
    rule_id: t.rule_id,
    ...scoresFor(t, siteKey),
    severity: t.severity,
    mitigation: t.mitigation,
    status: 'open',
    ml_score_before: null,
    suppressed: false,
    feedback: null,
    cvss_score: t.severity === 'critical' ? 9.8 : t.severity === 'high' ? 7.5 : t.severity === 'medium' ? 5.3 : 3.1,
    cvss_vector: t.severity === 'critical'
      ? 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H'
      : t.severity === 'high'
        ? 'CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N'
        : 'CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:N',
    cvss_severity: t.severity === 'critical' ? 'Critical' : t.severity === 'high' ? 'High' : t.severity === 'medium' ? 'Medium' : 'Low',
    cvss_provenance: 'rule_estimated',
    cvss: {
      version: '3.1',
      score: t.severity === 'critical' ? 9.8 : t.severity === 'high' ? 7.5 : t.severity === 'medium' ? 5.3 : 3.1,
      vector: t.severity === 'critical'
        ? 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H'
        : t.severity === 'high'
          ? 'CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N'
          : 'CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:N',
      severity: t.severity === 'critical' ? 'Critical' : t.severity === 'high' ? 'High' : t.severity === 'medium' ? 'Medium' : 'Low',
      provenance: 'rule_estimated',
    },
    owasp_mappings: [
      {
        version: '2025',
        category_id: t.owasp.split(' ')[0],
        category_name: t.owasp.split(' ').slice(1).join(' '),
        confidence: 'high',
        rationale: `Mapped to ${t.owasp} based on confirmed weakness classification for ${t.cwe_id}.`,
        primary: true,
        cwe_id: t.cwe_id,
      },
    ],
    nist_csf_mappings: [
      {
        version: '2.0',
        function_code: 'PR',
        function_name: 'PROTECT',
        category_code: 'PR.PS',
        category_name: 'Platform Security',
        subcategory_id: 'PR.PS-01',
        subcategory_title: 'Configuration and software security vulnerabilities are managed',
        rationale: `Defect in ${t.title} requires secure configuration and vulnerability mitigation per PR.PS-01.`,
        reference: 'NIST SP 800-53 Rev. 5: SI-2, SI-10',
      },
    ],
    correlation: {
      cluster_id: `cl_${id.slice(0, 8)}`,
      correlation_type: t.source === 'both' ? 'corroborated' : t.source === 'ml' ? 'standalone_candidate' : 'unassigned',
      primary_finding_id: null,
      is_primary: true,
      confidence: t.source === 'both' ? 0.95 : 0.82,
      rationale: t.source === 'both'
        ? 'Both static AST patterns and ML inference corroborated this vulnerability.'
        : t.source === 'ml'
          ? 'Candidate zero-day flagged solely by ML model.'
          : 'Rule-only pattern match.',
      evidence: [
        {
          source: t.source,
          evidence_type: 'ast_pattern',
          detail: `Matched rule ${t.rule_id ?? 'ML embedding similarity'}`,
        },
      ],
      limitations: t.source === 'ml' ? 'Unverified ML candidate — not a confirmed zero-day' : undefined,
      related_finding_ids: [],
    },
  }
}

function countsFor(findings: Finding[], scanId: string): SeverityCounts {
  const counts: SeverityCounts = { critical: 0, high: 0, medium: 0, low: 0 }
  for (const f of findings) if (f.scan_id === scanId && !f.suppressed) counts[f.severity]++
  return counts
}

function scanRisk(findings: Finding[], scanId: string): number {
  const top = findings
    .filter((f) => f.scan_id === scanId && !f.suppressed && f.status === 'open')
    .map((f) => f.risk_score)
    .sort((a, b) => b - a)
    .slice(0, 3)
  return top.length ? round(top.reduce((a, b) => a + b, 0) / top.length, 1) : 0
}

// Order of the acme-shop findings: v1.4 has RESOLVED + STILL, v1.5 has STILL + NEW.
const RESOLVED = ['md5-password#0', 'flask-debug#0', 'random-token#0']
const STILL = [
  'sqli-fstring#0',
  'subprocess-shell#0',
  'pickle#0',
  'path-traversal#0',
  'ssrf#0',
  'idor#0',
  'jwt-noverify#0',
  'cors-wildcard#0',
  'yaml-load#0',
  'os-system#0',
  'open-redirect#0',
  'hardcoded-secret#0',
  'verify-false#0',
  'redos#0',
  'bare-except#0',
  'assert-auth#0',
  'log-secrets#0',
  'ssti#0',
  'sqli-raw-orm#0',
]
const NEW = [
  'dynamic-import#0',
  'toctou#0',
  'mass-assignment#0',
  'missing-auth#0',
  'eval#0',
  'xxe#0',
  'tar-extract#0',
  'stack-trace#0',
  'sqli-format#0',
  'ssrf#1',
  'idor#1',
]
const BILLING = [
  'sqli-fstring#2',
  'os-system#1',
  'pickle#1',
  'yaml-load#1',
  'hardcoded-secret#1',
  'verify-false#1',
  'bind-all#0',
  'bare-except#1',
]
/** Seeded feedback: marked false positive (with training) on v1.4, suppressed on v1.5. */
const TRAINED: Record<string, string> = {
  'cors-wildcard#0': 'Origins are restricted by the API gateway',
  'redos#0': 'Input length capped at 254 by the form layer',
}
/** Templates used for a brand-new scan (15 findings). */
const NEW_SCAN_KEYS = [
  'sqli-fstring#0',
  'subprocess-shell#0',
  'pickle#0',
  'ssrf#0',
  'ssti#0',
  'md5-password#0',
  'open-redirect#0',
  'flask-debug#0',
  'hardcoded-secret#0',
  'path-traversal#0',
  'idor#0',
  'log-secrets#0',
  'redos#0',
  'verify-false#0',
  'toctou#0',
]

function seed(now: number): State {
  const s: State = {
    scans: [],
    findings: [],
    versions: [
      {
        version: 'v1.2',
        created_at: ago(now, 26),
        trigger: '2 false positives marked for training',
        f1: 0.818,
        fpr: 0.041,
      },
      {
        version: 'v1.1',
        created_at: ago(now, 16 * 24),
        trigger: 'Scheduled retrain on new CVE fixes',
        f1: 0.812,
        fpr: 0.047,
      },
      {
        version: 'v1.0',
        created_at: ago(now, 40 * 24),
        trigger: 'Initial training on CVE-fix corpus',
        f1: 0.801,
        fpr: 0.052,
      },
    ],
    learned: new Map(),
    effects: new Map(),
    listeners: new Map(),
    sent: new Map(),
    timers: [],
    nextScan: 4,
    trainEvents: Object.keys(TRAINED).length,
  }

  const scan = (
    id: string,
    name: string,
    type: ScanSourceType,
    hoursAgo: number,
    model: string,
    rescanOf: string | null,
    files: number,
    fns: number,
  ): Scan => ({
    id,
    name,
    source_type: type,
    status: 'done',
    stage: 'ranking',
    files_scanned: files,
    functions_scanned: fns,
    risk_score: 0,
    counts_by_severity: { critical: 0, high: 0, medium: 0, low: 0 },
    started_at: ago(now, hoursAgo),
    finished_at: ago(now, hoursAgo - 0.05),
    rescan_of: rescanOf,
    model_version: model,
  })

  const s3 = scan('scan-003', 'github.com/acme/billing-worker', 'git', 5 * 24, 'v1.1', null, 87, 612)
  s3.status = 'partial'
  s3.stage = 'ml'
  const s1 = scan('scan-001', 'acme-shop-v1.4.zip', 'zip', 2 * 24, 'v1.1', null, 212, 1840)
  const s2 = scan('scan-002', 'acme-shop-v1.5.zip', 'zip', 3, 'v1.2', 'scan-001', 219, 1903)
  s.scans.push(s2, s1, s3)

  BILLING.forEach((key, i) => s.findings.push(makeFinding(`f-003-${String(i + 1).padStart(2, '0')}`, 'scan-003', key)))
  ;[...RESOLVED, ...STILL].forEach((key, i) => {
    const f = makeFinding(`f-001-${String(i + 1).padStart(2, '0')}`, 'scan-001', key)
    if (RESOLVED.includes(key)) f.status = 'fixed'
    if (key === 'bare-except#0') {
      f.status = 'accepted'
      f.feedback = {
        reason: 'Job runner reports failures upstream',
        note: null,
        train: false,
        created_at: ago(now, 30),
        model_version: 'v1.1',
      }
    }
    s.findings.push(f)
  })
  ;[...STILL, ...NEW].forEach((key, i) => {
    const f = makeFinding(`f-002-${String(i + 1).padStart(2, '0')}`, 'scan-002', key)
    // Accepted triage carries over to the rescan by fingerprint.
    const prev = s.findings.find((p) => p.scan_id === 'scan-001' && fingerprint(p) === fingerprint(f))
    if (prev?.status === 'accepted') {
      f.status = 'accepted'
      f.feedback = prev.feedback && { ...prev.feedback }
    }
    s.findings.push(f)
  })

  // Seeded training feedback (produced v1.2) and its effect on both scans.
  const effects: VersionEffect[] = []
  for (const [key, reason] of Object.entries(TRAINED)) {
    const { t, site } = siteOf(key)
    const path = site[0].replace(/^\w+:/, '')
    s.learned.set(`${path}|${t.cwe_id}`, 'v1.2')
    for (const f of s.findings) {
      if (f.file_path !== path || f.cwe_id !== t.cwe_id || f.ml_score === null) continue
      effects.push({ id: f.id, ml_score: f.ml_score, ml_score_before: f.ml_score_before })
      f.ml_score_before = f.ml_score
      f.ml_score = round(f.ml_score * FEEDBACK_FACTOR, 2)
      f.status = 'false_positive'
      f.feedback = { reason, note: null, train: true, created_at: ago(now, 26.5), model_version: 'v1.2' }
      if (f.scan_id === 'scan-002') f.suppressed = true
    }
  }
  s.effects.set('v1.2', effects)

  for (const sc of s.scans) {
    sc.counts_by_severity = countsFor(s.findings, sc.id)
    sc.risk_score = scanRisk(s.findings, sc.id)
  }
  return s
}

// ---------- persistence (browser tab only) ----------

const STORAGE_KEY = 'zs-mock-db-v1'

interface Saved {
  scans: Scan[]
  findings: Finding[]
  versions: ModelVersion[]
  learned: [string, string][]
  effects: [string, VersionEffect[]][]
  nextScan: number
  trainEvents: number
}

function storage(): Storage | null {
  try {
    return typeof sessionStorage === 'undefined' ? null : sessionStorage
  } catch {
    return null
  }
}

/** Keeps demo changes across reloads within the tab. */
function persist() {
  const s = storage()
  if (!s) return
  const saved: Saved = {
    scans: state.scans,
    findings: state.findings,
    versions: state.versions,
    learned: [...state.learned],
    effects: [...state.effects],
    nextScan: state.nextScan,
    trainEvents: state.trainEvents,
  }
  try {
    s.setItem(STORAGE_KEY, JSON.stringify(saved))
  } catch {
    // Storage full or blocked: keep working in memory.
  }
}

function load(): State {
  const fresh = seed(Date.now())
  const raw = storage()?.getItem(STORAGE_KEY)
  if (!raw) return fresh
  try {
    const saved = JSON.parse(raw) as Saved
    // A scan that was mid-run when the page unloaded can't resume.
    for (const scan of saved.scans) if (scan.status === 'queued' || scan.status === 'running') scan.status = 'failed'
    return {
      ...fresh,
      scans: saved.scans,
      findings: saved.findings,
      versions: saved.versions,
      learned: new Map(saved.learned),
      effects: new Map(saved.effects),
      nextScan: saved.nextScan,
      trainEvents: saved.trainEvents,
    }
  } catch {
    return fresh
  }
}

let state = load()

/** Fresh seed data, no running scans, saved demo state cleared. */
export function resetDb(now = Date.now()) {
  state.timers.forEach(clearTimeout)
  storage()?.removeItem(STORAGE_KEY)
  state = seed(now)
}

export class MockHttpError extends Error {
  readonly status: number
  constructor(status: number, message: string) {
    super(message)
    this.status = status
  }
}

const notFound = (what: string) => new MockHttpError(404, `${what} not found`)

// ---------- reads ----------

export const listScans = () => [...state.scans].sort((a, b) => b.started_at.localeCompare(a.started_at))

export function getScan(id: string): Scan {
  const scan = state.scans.find((s) => s.id === id)
  if (!scan) throw notFound('scan')
  return scan
}

export function getFinding(id: string): Finding {
  const f = state.findings.find((x) => x.id === id)
  if (!f) throw notFound('finding')
  return f
}

export function scanFindings(scanId: string) {
  return state.findings.filter((f) => f.scan_id === scanId)
}

function compare(a: Finding, b: Finding, field: string): number {
  if (field === 'severity') return severityRank.indexOf(b.severity) - severityRank.indexOf(a.severity)
  if (field === 'file_path') return a.file_path.localeCompare(b.file_path) || a.start_line - b.start_line
  return a.risk_score - b.risk_score
}

export function listFindings(scanId: string, q: FindingsQuery) {
  getScan(scanId)
  const text = q.q?.trim().toLowerCase()
  let items = scanFindings(scanId).filter(
    (f) =>
      (q.include_suppressed || !f.suppressed) &&
      (!q.severity || f.severity === q.severity) &&
      (!q.owasp || f.owasp === q.owasp) &&
      (!q.source || f.source === q.source) &&
      (!q.status || f.status === q.status) &&
      (!text || [f.title, f.file_path, f.cwe_id, f.owasp, f.rule_id ?? ''].some((v) => v.toLowerCase().includes(text))),
  )
  const sort = q.sort ?? '-risk_score'
  const field = sort.replace(/^-/, '')
  const dir = sort.startsWith('-') ? -1 : 1
  items = [...items].sort((a, b) => dir * compare(a, b, field) || b.risk_score - a.risk_score)
  const offset = Math.max(0, q.offset ?? 0)
  const limit = Math.min(500, Math.max(1, q.limit ?? 50))
  return { items: items.slice(offset, offset + limit), total: items.length }
}

function previousScan(scan: Scan): Scan | null {
  if (scan.rescan_of) return state.scans.find((s) => s.id === scan.rescan_of) ?? null
  return listScans().find((s) => s.id !== scan.id && s.name === scan.name && s.started_at < scan.started_at) ?? null
}

export function diff(scanId: string): ScanDiff {
  const scan = getScan(scanId)
  const prev = previousScan(scan)
  const current = scanFindings(scanId)
  const before = prev ? scanFindings(prev.id) : []
  const prevKeys = new Set(before.map(fingerprint))
  const curKeys = new Set(current.map(fingerprint))
  const visible = current.filter((f) => !f.suppressed)
  return {
    previous_scan_id: prev?.id ?? null,
    new: prev ? visible.filter((f) => !prevKeys.has(fingerprint(f))) : visible,
    suppressed: current.filter((f) => f.suppressed),
    still_open: prev ? visible.filter((f) => prevKeys.has(fingerprint(f)) && f.status === 'open') : [],
    resolved: before.filter((f) => !curKeys.has(fingerprint(f))),
  }
}

export function summary(): Summary {
  const visible = state.findings.filter((f) => !f.suppressed)
  const by_severity: SeverityCounts = { critical: 0, high: 0, medium: 0, low: 0 }
  const by_source: Record<FindingSource, number> = { rule: 0, ml: 0, both: 0 }
  const by_owasp: Record<string, number> = {}
  for (const f of visible) {
    by_severity[f.severity]++
    by_source[f.source]++
    by_owasp[f.owasp] = (by_owasp[f.owasp] ?? 0) + 1
  }
  return {
    total_scans: state.scans.length,
    total_findings: visible.length,
    novel_count: by_source.ml,
    by_severity,
    by_owasp,
    by_source,
    top_findings: visible
      .filter((f) => f.status === 'open')
      .sort((a, b) => b.risk_score - a.risk_score)
      .slice(0, 5),
    last_scan: listScans()[0],
  }
}

export const currentVersion = () => state.versions[0].version

export function modelInfo(): ModelInfo {
  const feedbackFindings = state.findings.filter((f) => f.feedback)
  const latestPerFingerprint = new Map<string, Finding>()
  for (const f of feedbackFindings.sort((a, b) =>
    (b.feedback?.created_at ?? '').localeCompare(a.feedback?.created_at ?? ''),
  )) {
    const key = `${fingerprint(f)}|${f.feedback?.created_at}`
    if (!latestPerFingerprint.has(key)) latestPerFingerprint.set(key, f)
  }
  return {
    model_card: {
      name: 'ZeroSentinel Dual-Engine Vulnerability Detector',
      version: currentVersion(),
      architecture: 'TF-IDF Code Vectorizer + Class-Weighted Logistic Regression (with Contextual Bandit RL)',
      training_data: 'VUDENC Curated Python Vulnerability Dataset (75 train, 18 val, 18 test)',
      languages: ['Python'],
      threshold: 0.53,
    },
    eval: {
      precision: 1.0,
      recall: 0.75,
      f1: 0.857,
      roc_auc: 0.925,
      held_out: [
        { vuln_type: 'sql', cwe_id: 'CWE-89', detection_rate: 1.0, fpr: 0.0, samples: 1 },
        { vuln_type: 'xss', cwe_id: 'CWE-79', detection_rate: 1.0, fpr: 0.0, samples: 1 },
        { vuln_type: 'command_injection', cwe_id: 'CWE-78', detection_rate: 1.0, fpr: 0.0, samples: 1 },
        { vuln_type: 'xsrf', cwe_id: 'CWE-352', detection_rate: 0.0, fpr: 0.0, samples: 2 },
        { vuln_type: 'remote_code_execution', cwe_id: 'CWE-94', detection_rate: 1.0, fpr: 0.0, samples: 1 },
        { vuln_type: 'path_disclosure', cwe_id: 'CWE-22', detection_rate: 1.0, fpr: 0.0, samples: 1 },
        { vuln_type: 'open_redirect', cwe_id: 'CWE-601', detection_rate: 1.0, fpr: 0.0, samples: 1 },
      ],
    },
    learning: {
      version: currentVersion(),
      threshold: THRESHOLD,
      feedback_count: state.trainEvents,
      suppressed_count: state.findings.filter((f) => f.suppressed).length,
      versions: state.versions,
      recent_feedback: [...latestPerFingerprint.values()].filter((f) => !f.suppressed).slice(0, 8),
    },
  }
}

// ---------- feedback learning ----------

function bumpVersion(v: string): string {
  const [major, minor] = v.replace(/^v/, '').split('.').map(Number)
  return `v${major}.${minor + 1}`
}

export function updateFinding(id: string, input: UpdateFindingInput): Finding {
  const f = getFinding(id)
  if (input.status === 'false_positive' && !input.reason?.trim()) {
    throw new MockHttpError(422, 'reason is required when marking a false positive')
  }
  const now = new Date().toISOString()
  f.status = input.status
  const feedback: Feedback = {
    reason: input.reason?.trim() || null,
    note: input.note?.trim() || null,
    train: !!input.train,
    created_at: now,
    model_version: currentVersion(),
  }

  // Only ML evidence can be un-learned; rule-only findings never change the model.
  if (input.train && input.status === 'false_positive' && f.source !== 'rule' && f.ml_score !== null) {
    const prev = state.versions[0]
    const version = bumpVersion(prev.version)
    const effects: VersionEffect[] = []
    for (const g of state.findings) {
      if (g.source === 'rule' || g.ml_score === null || learnKey(g) !== learnKey(f)) continue
      effects.push({ id: g.id, ml_score: g.ml_score, ml_score_before: g.ml_score_before })
      g.ml_score_before = g.ml_score_before ?? g.ml_score
      g.ml_score = round(g.ml_score * FEEDBACK_FACTOR, 2)
    }
    state.learned.set(learnKey(f), version)
    state.effects.set(version, effects)
    state.versions.unshift({
      version,
      created_at: now,
      trigger: `False positive: ${f.title}`,
      f1: round(Math.min(0.99, prev.f1 + 0.002), 3),
      fpr: round(Math.max(0.005, prev.fpr - 0.002), 3),
    })
    feedback.model_version = version
  }
  if (feedback.train) state.trainEvents++
  f.feedback = feedback
  const scan = getScan(f.scan_id)
  scan.risk_score = scanRisk(state.findings, scan.id)
  persist()
  return f
}

export function revertModel(version: string): { version: string } {
  const idx = state.versions.findIndex((v) => v.version === version)
  if (idx < 0) throw notFound('model version')
  for (const v of state.versions.slice(0, idx)) {
    for (const e of [...(state.effects.get(v.version) ?? [])].reverse()) {
      const f = state.findings.find((x) => x.id === e.id)
      if (f) {
        f.ml_score = e.ml_score
        f.ml_score_before = e.ml_score_before
      }
    }
    state.effects.delete(v.version)
    for (const [key, learnedIn] of state.learned) if (learnedIn === v.version) state.learned.delete(key)
  }
  state.versions = state.versions.slice(idx)
  persist()
  return { version }
}

// ---------- scans and the fake scan run ----------

function emit(scanId: string, msg: ScanSocketMessage) {
  const sent = state.sent.get(scanId) ?? []
  sent.push(msg)
  state.sent.set(scanId, sent)
  state.listeners.get(scanId)?.forEach((fn) => fn(msg))
}

/** Subscribe to a scan's socket messages. Already-sent messages are replayed first. */
export function subscribe(scanId: string, fn: (msg: ScanSocketMessage) => void): () => void {
  getScan(scanId)
  for (const msg of state.sent.get(scanId) ?? []) fn(msg)
  const scan = getScan(scanId)
  if (!state.sent.has(scanId) && (scan.status === 'done' || scan.status === 'partial' || scan.status === 'failed')) {
    fn({ type: 'done', data: scan })
  }
  const set = state.listeners.get(scanId) ?? new Set()
  set.add(fn)
  state.listeners.set(scanId, set)
  return () => set.delete(fn)
}

/** Applies what the model has learned: lowered ML score, suppressed below threshold. */
function applyLearning(f: Finding): Finding {
  if (f.source === 'rule' || f.ml_score === null) return f
  if (state.learned.has(learnKey(f)) && f.ml_score_before === null) {
    f.ml_score_before = f.ml_score
    f.ml_score = round(f.ml_score * FEEDBACK_FACTOR, 2)
  }
  f.suppressed = f.ml_score < THRESHOLD
  return f
}

export type CreateScanBody =
  | { kind: 'zip'; name: string }
  | { kind: 'git'; git_url: string }
  | { kind: 'paste'; code: string; filename: string }
  | { kind: 'rescan'; rescan_of: string }

export function createScan(body: CreateScanBody): { scan_id: string } {
  const now = Date.now()
  const id = `scan-${String(state.nextScan++).padStart(3, '0')}`
  let planned: Finding[]
  let name: string
  let type: ScanSourceType
  let files: number
  let fns: number
  const fid = (i: number) => `f-${id.slice(5)}-${String(i + 1).padStart(2, '0')}`

  if (body.kind === 'rescan') {
    const base = getScan(body.rescan_of)
    name = base.name
    type = base.source_type
    files = base.files_scanned
    fns = base.functions_scanned
    planned = scanFindings(base.id)
      .filter((f) => f.status !== 'fixed')
      .map((f, i) =>
        applyLearning({ ...f, id: fid(i), scan_id: id, suppressed: false, feedback: f.feedback && { ...f.feedback } }),
      )
  } else {
    type = body.kind
    if (body.kind === 'zip') name = body.name
    else if (body.kind === 'git') name = body.git_url.replace(/^https?:\/\//, '').replace(/\.git$/, '')
    else name = body.filename || 'snippet.py'
    files = body.kind === 'paste' ? 1 : body.kind === 'zip' ? 48 : 64
    fns = body.kind === 'paste' ? 14 : files * 9
    planned = NEW_SCAN_KEYS.map((key, i) =>
      applyLearning(
        body.kind === 'paste' ? makeFinding(fid(i), id, key, name, 8 + i * 6) : makeFinding(fid(i), id, key),
      ),
    )
  }

  const scan: Scan = {
    id,
    name,
    source_type: type,
    status: 'queued',
    stage: 'unpack',
    files_scanned: 0,
    functions_scanned: 0,
    risk_score: 0,
    counts_by_severity: { critical: 0, high: 0, medium: 0, low: 0 },
    started_at: new Date(now).toISOString(),
    finished_at: new Date(now).toISOString(),
    rescan_of: body.kind === 'rescan' ? body.rescan_of : null,
    model_version: currentVersion(),
  }
  state.scans.push(scan)
  run(scan, planned, files, fns)
  persist()
  return { scan_id: id }
}

/** Plays a SCAN_SECONDS scan: unpack, rules, ml, ranking; findings stream during rules and ml. */
function run(scan: Scan, planned: Finding[], files: number, fns: number) {
  const ms = SCAN_SECONDS * 1000
  const visible = planned.filter((f) => !f.suppressed)
  const ruleHits = visible.filter((f) => f.source !== 'ml')
  const mlHits = visible.filter((f) => f.source === 'ml')
  const at = (fraction: number, fn: () => void) => state.timers.push(setTimeout(fn, Math.round(ms * fraction)))
  const stages: { stage: ScanStage; from: number; to: number; total: number; apply?: (done: number) => void }[] = [
    { stage: 'unpack', from: 0.02, to: 0.15, total: files, apply: (d) => (scan.files_scanned = d) },
    { stage: 'rules', from: 0.15, to: 0.45, total: 300 },
    { stage: 'ml', from: 0.45, to: 0.8, total: fns, apply: (d) => (scan.functions_scanned = d) },
    { stage: 'ranking', from: 0.8, to: 0.95, total: Math.max(1, visible.length) },
  ]

  for (const s of stages) {
    const steps = 6
    for (let i = 1; i <= steps; i++) {
      at(s.from + ((s.to - s.from) * i) / steps, () => {
        scan.status = 'running'
        scan.stage = s.stage
        const done = Math.round((s.total * i) / steps)
        s.apply?.(done)
        emit(scan.id, { type: 'progress', data: { stage: s.stage, done, total: s.total } })
      })
    }
  }
  const stream = (hits: Finding[], from: number, to: number) =>
    hits.forEach((f, i) =>
      at(from + ((to - from) * (i + 0.5)) / hits.length, () => {
        state.findings.push(f)
        scan.counts_by_severity = countsFor(state.findings, scan.id)
        emit(scan.id, { type: 'finding', data: f })
      }),
    )
  stream(ruleHits, 0.17, 0.44)
  stream(mlHits, 0.47, 0.79)

  at(1, () => {
    for (const f of planned) if (f.suppressed) state.findings.push(f)
    Object.assign(scan, {
      status: 'done',
      stage: 'ranking',
      files_scanned: files,
      functions_scanned: fns,
      counts_by_severity: countsFor(state.findings, scan.id),
      risk_score: scanRisk(state.findings, scan.id),
      finished_at: new Date().toISOString(),
    } satisfies Partial<Scan>)
    persist()
    emit(scan.id, { type: 'done', data: scan })
  })
}
