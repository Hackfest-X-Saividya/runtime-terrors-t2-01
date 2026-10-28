import { Link } from 'react-router-dom'
import { SeverityBadge, SourceBadge, Tag } from '@/components/Badges'
import { RiskScore } from '@/components/RiskScore'
import type { Finding } from '@/types/contract'

export function TopRisks({ findings }: { findings: Finding[] }) {
  return (
    <ol className="flex flex-col gap-space-sm">
      {findings.map((f) => (
        <li key={f.id}>
          <Link
            to={`/findings/${f.id}`}
            className="flex flex-col gap-space-xs rounded-lg bg-surface-container p-space-sm transition-colors hover:bg-surface-container-high"
          >
            <span className="flex items-center justify-between gap-space-sm">
              <SeverityBadge severity={f.severity} />
              <RiskScore score={f.risk_score} />
            </span>
            <span className="truncate font-headline-sm text-headline-sm text-on-surface">{f.title}</span>
            <span className="flex flex-wrap items-center gap-space-sm">
              <span className="min-w-0 flex-1 truncate font-label-code-md text-label-code-md text-on-surface-variant">
                {f.file_path}:{f.start_line}
              </span>
              <Tag>{f.cwe_id}</Tag>
              <SourceBadge source={f.source} ruleId={f.rule_id} />
            </span>
          </Link>
        </li>
      ))}
    </ol>
  )
}
