import { findingStatusMeta, getScanStatusMeta, severityMeta } from '@/lib/labels'
import type { FindingSource, FindingStatus, ScanStatus, Severity } from '@/types/contract'
import { Icon } from './Icon'

const chip =
  'inline-flex items-center gap-1.5 whitespace-nowrap rounded px-2 py-0.5 font-label-code-sm text-label-code-sm'

interface SeverityBadgeProps {
  severity: Severity
  /** Shows "CRIT 9.6" instead of "CRITICAL". */
  score?: number
  /** Greyed and struck through, for suppressed rows. */
  muted?: boolean
}

/** Severity is always shown as text; the dot is decoration only. */
export function SeverityBadge({ severity, score, muted }: SeverityBadgeProps) {
  const m = severityMeta[severity] ?? severityMeta.low
  const hasScore = typeof score === 'number' && !isNaN(score)
  return (
    <span
      className={`${chip} ${muted ? 'bg-surface-container text-on-surface-variant line-through' : `${m.badge} ${m.text}`}`}
    >
      <span aria-hidden="true" className={`h-1.5 w-1.5 rounded-full ${muted ? 'bg-outline' : m.dot}`} />
      {!hasScore ? m.label.toUpperCase() : `${m.short} ${score.toFixed(1)}`}
      <span className="sr-only"> severity</span>
    </span>
  )
}

/** Legend item: dot + label, for charts and filters. */
export function SeverityLabel({
  severity,
  className = '',
  large,
}: {
  severity: Severity
  className?: string
  large?: boolean
}) {
  const m = severityMeta[severity]
  const size = large ? 'font-label-code-lg text-label-code-lg' : 'font-label-code-sm text-label-code-sm'
  return (
    <span className={`inline-flex items-center gap-1.5 ${size} ${className}`}>
      <span aria-hidden="true" className={`h-2.5 w-2.5 rounded-full ${m.dot}`} />
      {m.label.toUpperCase()}
    </span>
  )
}

/** Green "Novel" badge (DESIGN.md decision): only the ML model found this. */
export function NovelBadge({ label = 'Novel' }: { label?: 'Novel' | 'Novel ML' }) {
  return (
    <span
      className={`${chip} bg-primary-container text-on-primary-container shadow-sm`}
      title="Only the ML model detected this: a zero-day candidate pending independent validation"
    >
      <Icon name="auto_awesome" />
      {label}
    </span>
  )
}

/** Which detector found it. ML-only findings get the Novel badge. */
export function SourceBadge({ source, ruleId }: { source: FindingSource; ruleId?: string | null }) {
  if (source === 'ml') return <NovelBadge label="Novel ML" />
  return (
    <span className={`${chip} bg-surface-container-high text-on-surface-variant`} title={ruleId ?? undefined}>
      <Icon name={source === 'both' ? 'join' : 'rule'} />
      {source === 'both' ? 'Rule + ML corroborated' : 'Rule'}
    </span>
  )
}

export function FindingStatusPill({ status }: { status: FindingStatus }) {
  const m = findingStatusMeta[status]
  return (
    <span className={`${chip} ${m.chip}`}>
      <span aria-hidden="true" className={`h-1.5 w-1.5 rounded-full ${m.dot}`} />
      {m.label}
    </span>
  )
}

export function ScanStatusPill({ status }: { status: ScanStatus | string }) {
  const m = getScanStatusMeta(status)
  return (
    <span className={`${chip} ${m.chip}`}>
      <span aria-hidden="true" className={`h-1.5 w-1.5 rounded-full ${m.dot}`} />
      {m.label}
    </span>
  )
}

export function SuppressedBadge() {
  return (
    <span
      className={`${chip} bg-secondary-container/30 text-secondary`}
      title="Hidden by feedback learning on this scan"
    >
      <Icon name="visibility_off" />
      Suppressed by feedback
    </span>
  )
}

/** ML score lowered by feedback: "0.91 → 0.34". */
export function ScoreChange({ before, after }: { before?: number | null; after?: number | null }) {
  const b = typeof before === 'number' && !isNaN(before) ? before.toFixed(2) : '-'
  const a = typeof after === 'number' && !isNaN(after) ? after.toFixed(2) : '-'
  return (
    <span
      className={`${chip} bg-surface-container-highest text-primary`}
      title="ML score lowered by feedback"
      aria-label={`ML score lowered by feedback from ${b} to ${a}`}
    >
      <Icon name="trending_down" />
      {b} → {a}
    </span>
  )
}

/** Small neutral tag (CWE id, rule id, counts). */
export function Tag({ children, className = '' }: { children: React.ReactNode; className?: string }) {
  return (
    <span
      className={`inline-flex items-center gap-1 whitespace-nowrap rounded bg-surface-container-highest px-1.5 py-0.5 font-label-code-sm text-label-code-sm text-on-surface-variant ${className}`}
    >
      {children}
    </span>
  )
}
