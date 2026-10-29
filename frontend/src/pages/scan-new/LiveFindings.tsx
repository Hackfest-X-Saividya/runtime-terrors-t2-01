import { Link } from 'react-router-dom'
import { SeverityBadge, SeverityLabel, SourceBadge } from '@/components/Badges'
import { EmptyState } from '@/components/States'
import { severityOrder } from '@/lib/labels'
import type { Finding } from '@/types/contract'

export function LiveFindings({ findings, waiting }: { findings: Finding[]; waiting: boolean }) {
  const newestFirst = [...findings].reverse()
  const count = (s: Finding['severity']) => findings.filter((f) => f.severity === s).length
  const novel = findings.filter((f) => f.source === 'ml').length

  return (
    <div className="flex flex-col gap-space-md">
      <div className="flex flex-wrap gap-space-sm" aria-label="Counts so far">
        {severityOrder.map((s) => (
          <span key={s} className="flex items-center gap-space-sm rounded bg-surface-container px-2.5 py-1">
            <SeverityLabel severity={s} className="text-on-surface" />
            <span className="font-mono text-label-code-md">{count(s)}</span>
          </span>
        ))}
        <span className="flex items-center gap-space-sm rounded bg-surface-container px-2.5 py-1 font-label-code-sm text-label-code-sm text-primary">
          NOVEL ML <span className="font-mono text-label-code-md">{novel}</span>
        </span>
      </div>
      {newestFirst.length === 0 ? (
        <EmptyState
          icon={waiting ? 'hourglass_top' : 'radar'}
          title={waiting ? 'Waiting for the first finding…' : 'Findings will stream in here'}
        >
          Rule hits arrive during the rule scan, ML-only findings during ML analysis.
        </EmptyState>
      ) : (
        <ul aria-live="polite" className="flex max-h-[32rem] flex-col gap-space-sm overflow-y-auto pr-1">
          {newestFirst.map((f) => (
            <li key={f.id}>
              <Link
                to={`/findings/${f.id}`}
                className="flex flex-wrap items-center gap-space-md rounded-lg bg-surface-container p-space-md transition-colors hover:bg-surface-container-high"
              >
                <SeverityBadge severity={f.severity} score={f.risk_score} />
                <span className="flex min-w-0 flex-1 flex-col">
                  <span className="truncate font-headline-sm text-headline-sm text-on-surface">{f.title}</span>
                  <span className="truncate font-label-code-md text-label-code-md text-on-surface-variant">
                    {f.file_path}:{f.start_line} · {f.cwe_id}
                  </span>
                </span>
                <SourceBadge source={f.source} ruleId={f.rule_id} />
              </Link>
            </li>
          ))}
        </ul>
      )}
    </div>
  )
}
