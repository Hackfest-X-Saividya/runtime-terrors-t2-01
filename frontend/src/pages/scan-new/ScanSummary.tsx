import { useScanDiff } from '@/api/hooks'
import { ScanStatusPill } from '@/components/Badges'
import { ButtonLink } from '@/components/Button'
import { Icon } from '@/components/Icon'
import { RiskScore } from '@/components/RiskScore'
import { Skeleton } from '@/components/States'
import { fmtDuration, fmtNumber } from '@/lib/format'
import { riskLabel, riskTextClass } from '@/lib/labels'
import type { Scan } from '@/types/contract'

function Stat({
  label,
  value,
  hint,
  className = 'text-on-surface',
}: {
  label: string
  value: React.ReactNode
  hint?: string
  className?: string
}) {
  return (
    <div className="rounded-lg bg-surface-container p-space-sm">
      <div className="font-label-code-sm text-label-code-sm uppercase text-on-surface-variant">{label}</div>
      <div className={`font-mono text-headline-md font-bold ${className}`}>{value}</div>
      {hint && <div className="font-label-code-sm text-label-code-sm text-on-surface-variant">{hint}</div>}
    </div>
  )
}

/** Finished-scan card: totals, previous-scan comparison and the next steps. */
export function ScanSummary({ scan, novel }: { scan: Scan; novel: number }) {
  const diff = useScanDiff(scan.id)
  const c = scan.counts_by_severity
  const total = c.critical + c.high + c.medium + c.low

  return (
    <div className="flex flex-col gap-space-md">
      <div className="flex items-start justify-between gap-space-sm">
        <div>
          <p className="font-label-code-sm text-label-code-sm uppercase text-primary">Scan finished</p>
          <h2 className="font-headline-md text-headline-md text-on-surface">Scan assessment</h2>
          <p className="font-label-code-sm text-label-code-sm text-on-surface-variant">
            {scan.name} · {fmtDuration(scan.started_at, scan.finished_at)}
          </p>
        </div>
        <ScanStatusPill status={scan.status} />
      </div>
      <div className="flex items-center justify-between rounded-lg bg-surface-container p-space-md">
        <div>
          <div className="font-label-code-sm text-label-code-sm uppercase text-on-surface-variant">Risk score</div>
          <RiskScore score={scan.risk_score} size="lg" />
        </div>
        <span
          className={`rounded bg-surface-container-high px-2 py-1 font-label-code-sm text-label-code-sm uppercase ${riskTextClass(scan.risk_score)}`}
        >
          {riskLabel(scan.risk_score)}
        </span>
      </div>
      <div className="grid grid-cols-2 gap-space-sm">
        <Stat label="Findings" value={total} hint={`${fmtNumber(scan.functions_scanned)} functions scored`} />
        <Stat
          label="Critical"
          value={c.critical}
          className="text-error"
          hint={c.critical ? 'Release blockers' : 'None'}
        />
        <Stat label="Novel ML" value={novel} className="text-primary" hint="Zero-day candidates" />
        <Stat label="Files" value={fmtNumber(scan.files_scanned)} hint={`model ${scan.model_version}`} />
      </div>

      <div className="rounded-lg bg-surface-container p-space-md">
        <div className="mb-space-sm flex items-center justify-between">
          <span className="font-label-code-sm text-label-code-sm uppercase text-on-surface-variant">
            Compared with previous scan
          </span>
          {diff.data?.previous_scan_id && (
            <span className="font-label-code-sm text-label-code-sm text-on-surface-variant">
              {diff.data.previous_scan_id}
            </span>
          )}
        </div>
        {diff.isPending ? (
          <Skeleton className="h-8 w-full" />
        ) : diff.isError ? (
          <p className="font-body-md text-body-md text-on-surface-variant">Comparison unavailable.</p>
        ) : diff.data.previous_scan_id ? (
          <div className="flex flex-wrap gap-space-sm font-label-code-md text-label-code-md">
            <span className="rounded bg-error-container/40 px-2 py-1 text-error">+{diff.data.new.length} new</span>
            <span className="rounded bg-primary/10 px-2 py-1 text-primary">−{diff.data.resolved.length} resolved</span>
            <span className="rounded bg-secondary/15 px-2 py-1 text-secondary">
              <Icon name="visibility_off" /> {diff.data.suppressed.length} suppressed by feedback
            </span>
          </div>
        ) : (
          <p className="font-body-md text-body-md text-on-surface-variant">
            First scan of this project: nothing to compare yet.
          </p>
        )}
      </div>

      <div className="flex flex-col gap-space-sm">
        <ButtonLink
          to={`/scans/${scan.id}/findings`}
          variant="primary"
          icon="shield_with_house"
          className="w-full py-2.5"
        >
          View findings
        </ButtonLink>
        <div className="grid grid-cols-2 gap-space-sm">
          <ButtonLink to={`/scans/${scan.id}/changes`} icon="difference">
            View changes
          </ButtonLink>
          <ButtonLink to={`/reports/${scan.id}`} icon="description">
            Report
          </ButtonLink>
        </div>
      </div>
    </div>
  )
}
