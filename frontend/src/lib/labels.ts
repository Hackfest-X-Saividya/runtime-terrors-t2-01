import type { Finding, FindingSource, FindingStatus, ScanStage, ScanStatus, Severity } from '@/types/contract'
import { colors } from './tokens'

// Styles from DESIGN.md "Severity" table (Findings screen 03 is canonical).
export const severityMeta: Record<
  Severity,
  { label: string; short: string; dot: string; badge: string; text: string; hex: string }
> = {
  critical: {
    label: 'Critical',
    short: 'CRIT',
    dot: 'bg-error',
    badge: 'bg-error-container',
    text: 'text-on-error-container',
    hex: colors.error,
  },
  high: {
    label: 'High',
    short: 'HIGH',
    dot: 'bg-tertiary-container',
    badge: 'bg-tertiary-container/20',
    text: 'text-tertiary',
    hex: colors['tertiary-container'],
  },
  medium: {
    label: 'Medium',
    short: 'MED',
    dot: 'bg-tertiary',
    badge: 'bg-tertiary/15',
    text: 'text-tertiary',
    hex: colors.tertiary,
  },
  low: {
    label: 'Low',
    short: 'LOW',
    dot: 'bg-secondary',
    badge: 'bg-secondary/15',
    text: 'text-secondary',
    hex: colors.secondary,
  },
}

export const severityOrder: Severity[] = ['critical', 'high', 'medium', 'low']

/** A finding is Novel (zero-day candidate) when only the ML model caught it. */
export const isNovel = (finding: Pick<Finding, 'source'>) => finding.source === 'ml'

export const sourceLabel: Record<FindingSource, string> = { rule: 'Rule', ml: 'ML only', both: 'Rule + ML' }

interface ChipStyle {
  label: string
  dot: string
  chip: string
}

// Finding status colours follow the feedback labels on the Model screen (06).
export const findingStatusMeta: Record<FindingStatus, ChipStyle> = {
  open: { label: 'Open', dot: 'bg-on-surface-variant', chip: 'bg-surface-container-high text-on-surface' },
  fixed: { label: 'Fixed', dot: 'bg-primary', chip: 'bg-primary/10 text-primary' },
  false_positive: {
    label: 'False positive',
    dot: 'bg-tertiary-container',
    chip: 'bg-tertiary-container/20 text-tertiary',
  },
  accepted: { label: 'Accepted', dot: 'bg-secondary', chip: 'bg-secondary/15 text-secondary' },
}

export const findingStatusOrder: FindingStatus[] = ['open', 'fixed', 'false_positive', 'accepted']

export const scanStatusMeta: Record<ScanStatus, ChipStyle> = {
  queued: { label: 'Queued', dot: 'bg-outline', chip: 'bg-surface-container-high text-on-surface-variant' },
  running: { label: 'Running', dot: 'bg-primary animate-pulse', chip: 'bg-primary/10 text-primary' },
  done: { label: 'Done', dot: 'bg-primary', chip: 'bg-surface-container-high text-on-surface' },
  failed: { label: 'Failed', dot: 'bg-error', chip: 'bg-error-container/40 text-error' },
  partial: { label: 'Partial', dot: 'bg-tertiary-container', chip: 'bg-tertiary-container/20 text-tertiary' },
}

export const stageMeta: Record<ScanStage, { label: string; unit: string }> = {
  unpack: { label: 'Unpack', unit: 'files' },
  rules: { label: 'Rule scan', unit: 'rules evaluated' },
  ml: { label: 'ML analysis', unit: 'functions scored' },
  ranking: { label: 'Ranking', unit: 'findings ranked' },
}

export const stageOrder: ScanStage[] = ['unpack', 'rules', 'ml', 'ranking']

/** OWASP Top 10 2025 category names used by the backend. */
export const owaspCategories = [
  'A01:2025 Broken Access Control',
  'A02:2025 Security Misconfiguration',
  'A03:2025 Software Supply Chain Failures',
  'A04:2025 Cryptographic Failures',
  'A05:2025 Injection',
  'A06:2025 Insecure Design',
  'A07:2025 Authentication Failures',
  'A08:2025 Software or Data Integrity Failures',
  'A09:2025 Security Logging and Alerting Failures',
  'A10:2025 Mishandling of Exceptional Conditions',
]

/** "A05:2025 Injection" -> { code: "A05", name: "Injection" } */
export function splitOwasp(owasp: string) {
  const m = /^(A\d{2})(?::\d{4})?\s*(.*)$/.exec(owasp)
  return m ? { code: m[1], name: m[2] || owasp } : { code: '', name: owasp }
}

export const cweUrl = (cwe: string) => `https://cwe.mitre.org/data/definitions/${cwe.replace(/^CWE-/, '')}.html`
export const owaspUrl = () => 'https://owasp.org/Top10/2025/'

/** Text colour for a 0-10 risk score, using the severity bands of the mocks/backend. */
export function riskTextClass(score: number): string {
  if (score >= 9) return 'text-error'
  if (score >= 7) return 'text-tertiary-container'
  if (score >= 4) return 'text-tertiary'
  return 'text-secondary'
}

export const falsePositiveReasons = [
  'Test or example code',
  'Input already sanitised',
  'Not reachable from user input',
  'Mitigated elsewhere',
  'Other',
]

export function riskLabel(score: number): string {
  if (score >= 9) return 'Critical risk'
  if (score >= 7) return 'High risk'
  if (score >= 4) return 'Elevated risk'
  return 'Low risk'
}
