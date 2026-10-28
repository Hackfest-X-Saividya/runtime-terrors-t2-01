import { Link } from 'react-router-dom'
import { CorrelationBadge, FindingStatusPill, NovelBadge, ScoreChange, SeverityBadge, SuppressedBadge, Tag } from '@/components/Badges'
import { Icon } from '@/components/Icon'
import { isNovel, splitOwasp } from '@/lib/labels'
import { sinkLine } from '@/lib/snippet'
import type { Finding, FindingSort } from '@/types/contract'

interface FindingsTableProps {
  items: Finding[]
  selected: Set<string>
  onToggle: (id: string) => void
  onToggleAll: (checked: boolean) => void
  sort: FindingSort
  onSort: (sort: FindingSort) => void
  /** Search params to carry into the detail page for previous/next. */
  backQuery: string
}

function SortHeader({
  field,
  label,
  sort,
  onSort,
}: {
  field: 'severity' | 'risk_score' | 'file_path'
  label: string
  sort: FindingSort
  onSort: (s: FindingSort) => void
}) {
  const active = sort.replace(/^-/, '') === field
  const desc = sort.startsWith('-')
  const next = (active && desc ? field : `-${field}`) as FindingSort
  return (
    <button
      type="button"
      onClick={() => onSort(field === 'file_path' && !active ? 'file_path' : next)}
      className={`flex items-center gap-1 rounded uppercase ${active ? 'text-on-surface' : ''} hover:text-on-surface`}
    >
      {label}
      <Icon name={active ? (desc ? 'arrow_downward' : 'arrow_upward') : 'unfold_more'} />
    </button>
  )
}

export function FindingsTable({ items, selected, onToggle, onToggleAll, sort, onSort, backQuery }: FindingsTableProps) {
  const allOn = items.length > 0 && items.every((f) => selected.has(f.id))
  const ariaSort = (field: string) =>
    sort.replace(/^-/, '') === field ? (sort.startsWith('-') ? 'descending' : 'ascending') : 'none'

  return (
    <div className="overflow-x-auto">
      <table className="w-full min-w-[960px] text-left">
        <caption className="sr-only">Findings, {items.length} on this page</caption>
        <thead className="bg-surface-container font-label-code-sm text-label-code-sm uppercase text-on-surface-variant">
          <tr>
            <th scope="col" className="w-12 px-space-md py-space-sm">
              <input
                type="checkbox"
                aria-label="Select all on this page"
                checked={allOn}
                onChange={(e) => onToggleAll(e.target.checked)}
                className="h-4 w-4 accent-primary"
              />
            </th>
            <th scope="col" aria-sort={ariaSort('severity')} className="px-space-sm py-space-sm font-semibold">
              <SortHeader field="severity" label="Severity" sort={sort} onSort={onSort} />
            </th>
            <th scope="col" aria-sort={ariaSort('risk_score')} className="px-space-sm py-space-sm font-semibold">
              <SortHeader field="risk_score" label="Risk" sort={sort} onSort={onSort} />
            </th>
            <th scope="col" className="px-space-sm py-space-sm font-semibold">
              Finding
            </th>
            <th scope="col" aria-sort={ariaSort('file_path')} className="px-space-sm py-space-sm font-semibold">
              <SortHeader field="file_path" label="File : line" sort={sort} onSort={onSort} />
            </th>
            <th scope="col" className="px-space-sm py-space-sm font-semibold">
              CWE
            </th>
            <th scope="col" className="px-space-sm py-space-sm font-semibold">
              OWASP
            </th>
            <th scope="col" className="px-space-md py-space-sm font-semibold">
              Status
            </th>
          </tr>
        </thead>
        <tbody>
          {items.map((f) => {
            const muted = f.suppressed || f.status === 'false_positive'
            const owasp = splitOwasp(f.owasp)
            return (
              <tr
                key={f.id}
                className={`border-t border-surface-container ${selected.has(f.id) ? 'bg-surface-container-high/60' : 'hover:bg-surface-container'} ${muted ? 'opacity-70' : ''}`}
              >
                <td className="px-space-md py-3 align-top">
                  <input
                    type="checkbox"
                    aria-label={`Select ${f.title}`}
                    checked={selected.has(f.id)}
                    onChange={() => onToggle(f.id)}
                    className="mt-1 h-4 w-4 accent-primary"
                  />
                </td>
                <td className="px-space-sm py-3 align-top">
                  <SeverityBadge severity={f.severity} muted={f.suppressed} />
                </td>
                <td className="px-space-sm py-3 align-top font-mono text-label-code-lg text-on-surface">
                  <div>{typeof f.risk_score === 'number' ? f.risk_score.toFixed(1) : '-'}</div>
                  {typeof (f.cvss?.score ?? f.cvss_score) === 'number' && (
                    <div className="text-[10px] text-primary font-sans font-medium" title="CVSS v3.1 Base Score">
                      CVSS {(f.cvss?.score ?? f.cvss_score)?.toFixed(1)}
                    </div>
                  )}
                </td>
                <td className="max-w-md px-space-sm py-3 align-top">
                  <div className="flex flex-col gap-1">
                    <Link
                      to={`/findings/${f.id}${backQuery}`}
                      className={`truncate font-headline-sm text-headline-sm hover:text-primary ${f.suppressed ? 'text-on-surface-variant line-through' : 'text-on-surface'}`}
                    >
                      {f.title}
                    </Link>
                    <code className="truncate font-label-code-md text-label-code-md text-on-surface-variant">
                      {sinkLine(f.snippet)}
                    </code>
                    {(isNovel(f) || typeof f.ml_score_before === 'number' || f.suppressed || f.correlation || f.correlation_data) && (
                      <div className="flex flex-wrap items-center gap-1">
                        {isNovel(f) && <NovelBadge />}
                        {(f.correlation || f.correlation_data) && (
                          <CorrelationBadge
                            type={f.correlation?.correlation_type ?? (f.correlation_data?.correlation_type as string | undefined)}
                            isPrimary={f.correlation?.is_primary ?? (f.correlation_data?.is_primary as boolean | undefined)}
                          />
                        )}
                        {typeof f.ml_score_before === 'number' && typeof f.ml_score === 'number' && (
                          <ScoreChange before={f.ml_score_before} after={f.ml_score} />
                        )}
                        {f.suppressed && <SuppressedBadge />}
                      </div>
                    )}
                  </div>
                </td>
                <td className="px-space-sm py-3 align-top font-label-code-md text-label-code-md text-on-surface">
                  {f.file_path}:{f.start_line}
                </td>
                <td className="px-space-sm py-3 align-top">
                  <Tag>{f.cwe_id}</Tag>
                </td>
                <td
                  className="px-space-sm py-3 align-top font-body-md text-body-md text-on-surface-variant"
                  title={f.owasp}
                >
                  <span className="font-mono text-on-surface">{owasp.code}</span> {owasp.name}
                </td>
                <td className="px-space-md py-3 align-top">
                  <FindingStatusPill status={f.status} />
                </td>
              </tr>
            )
          })}
        </tbody>
      </table>
    </div>
  )
}
