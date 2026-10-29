import { useState } from 'react'
import { useLocation, useParams } from 'react-router-dom'
import { useFindings, useScan } from '@/api/hooks'
import { ScanStatusPill, Tag } from '@/components/Badges'
import { Button, ButtonLink } from '@/components/Button'
import { CompareStrip } from '@/components/CompareStrip'
import { Icon } from '@/components/Icon'
import { PageHeader } from '@/components/PageHeader'
import { RiskScore } from '@/components/RiskScore'
import { EmptyState, ErrorState, Skeleton, SkeletonRows } from '@/components/States'
import { pageSizes, useFindingFilters } from '@/hooks/useFindingFilters'
import { useRescan } from '@/hooks/useRescan'
import { fmtDateTime, fmtNumber } from '@/lib/format'
import { riskLabel, riskTextClass, severityMeta, severityOrder } from '@/lib/labels'
import { isFinished } from '@/lib/scans'
import { BulkBar } from './BulkBar'
import { FilterBar } from './FilterBar'
import { FindingsTable } from './FindingsTable'

export default function FindingsPage() {
  const { scanId } = useParams()
  const { search } = useLocation()
  const scan = useScan(scanId)
  const { filters, query, update, clear, active } = useFindingFilters()
  const page = useFindings(scanId, query)
  const facets = useFindings(scanId, { limit: 500, include_suppressed: true })
  const [selected, setSelected] = useState<Set<string>>(new Set())
  const { rescan, pending } = useRescan()

  if (scan.isError) {
    return (
      <>
        <PageHeader title="Findings" crumbs={[{ label: 'Scans', to: '/' }, { label: scanId ?? '' }]} />
        <ErrorState error={scan.error} onRetry={() => scan.refetch()} />
      </>
    )
  }

  const s = scan.data
  const items = page.data?.items ?? []
  const total = page.data?.total ?? 0
  const pages = Math.max(1, Math.ceil(total / filters.size))
  const suppressedCount = facets.data?.items.filter((f) => f.suppressed).length ?? 0
  const novel = facets.data?.items.filter((f) => f.source === 'ml' && !f.suppressed).length ?? 0
  const selectedFindings = items.filter((f) => selected.has(f.id))

  const toggle = (id: string) =>
    setSelected((prev) => {
      const next = new Set(prev)
      if (next.has(id)) next.delete(id)
      else next.add(id)
      return next
    })

  return (
    <>
      <PageHeader
        crumbs={[{ label: 'Scans', to: '/' }, { label: s?.name ?? scanId ?? '' }]}
        title={s ? `Findings: ${s.name}` : <Skeleton className="h-9 w-96" />}
        meta={
          s && (
            <>
              <ScanStatusPill status={s.status} />
              <Tag>
                <Icon name="schedule" /> {fmtDateTime(s.started_at)}
              </Tag>
              <Tag>
                <Icon name="description" /> {fmtNumber(s.files_scanned)} files · {fmtNumber(s.functions_scanned)}{' '}
                functions
              </Tag>
              <Tag className="text-primary">rules + ML {s.model_version}</Tag>
              {s.rescan_of && <Tag>rescan of {s.rescan_of}</Tag>}
            </>
          )
        }
        actions={
          s && (
            <div className="flex flex-col items-stretch gap-space-sm">
              <div className="flex items-center gap-space-md rounded-xl bg-surface-container-low px-space-md py-space-sm shadow-sm">
                <div>
                  <span className="flex items-center gap-space-sm font-label-code-sm text-label-code-sm uppercase text-on-surface-variant">
                    Scan risk
                    <span className={`rounded bg-surface-container-high px-1.5 py-0.5 ${riskTextClass(s.risk_score)}`}>
                      {riskLabel(s.risk_score)}
                    </span>
                  </span>
                  <RiskScore score={s.risk_score} size="lg" />
                </div>
                <div className="flex flex-col gap-1 border-l border-outline-variant pl-space-md font-label-code-sm text-label-code-sm">
                  <span className="text-on-surface">
                    {fmtNumber(severityOrder.reduce((n, k) => n + (s.counts_by_severity?.[k] ?? 0), 0))} findings ·{' '}
                    <span className="text-primary">{novel} Novel ML</span>
                  </span>
                  <span className="flex flex-wrap gap-space-sm">
                    {severityOrder.map((k) => (
                      <span key={k} className={severityMeta[k]?.text ?? ''}>
                        ● {s.counts_by_severity?.[k] ?? 0} {severityMeta[k]?.short ?? k.toUpperCase()}
                      </span>
                    ))}
                  </span>
                </div>
              </div>
              <div className="flex flex-wrap justify-end gap-space-sm">
                <ButtonLink to={`/reports/${s.id}`} icon="download">
                  Export report
                </ButtonLink>
                <Button
                  variant="primary"
                  icon="autorenew"
                  disabled={pending || !isFinished(s)}
                  onClick={() => rescan(s.id)}
                >
                  {pending ? 'Starting…' : 'Re-scan'}
                </Button>
              </div>
            </div>
          )
        }
      />

      {scanId && <CompareStrip scanId={scanId} />}

      <FilterBar
        filters={filters}
        facets={facets.data?.items ?? []}
        suppressedCount={suppressedCount}
        active={active}
        update={update}
        clear={clear}
      />

      {selectedFindings.length > 0 && <BulkBar selected={selectedFindings} onDone={() => setSelected(new Set())} />}

      <section aria-label="Findings table" className="overflow-hidden rounded-xl bg-surface-container-low shadow-sm">
        {page.isError ? (
          <div className="p-space-lg">
            <ErrorState error={page.error} onRetry={() => page.refetch()} />
          </div>
        ) : page.isPending ? (
          <div className="p-space-lg">
            <SkeletonRows rows={8} />
          </div>
        ) : items.length === 0 ? (
          <EmptyState icon="search_off" title={active ? 'No findings match these filters' : 'No findings in this scan'}>
            {active ? (
              <button type="button" onClick={clear} className="rounded text-primary underline">
                Clear filters
              </button>
            ) : (
              'Nothing was flagged by the rule engine or the model.'
            )}
          </EmptyState>
        ) : (
          <FindingsTable
            items={items}
            selected={selected}
            onToggle={toggle}
            onToggleAll={(on) => setSelected(on ? new Set(items.map((f) => f.id)) : new Set())}
            sort={filters.sort}
            onSort={(sort) => update({ sort })}
            backQuery={search}
          />
        )}

        <footer className="flex flex-wrap items-center justify-between gap-space-md border-t border-surface-container px-space-md py-space-sm font-label-code-md text-label-code-md text-on-surface-variant">
          <span aria-live="polite">
            {total
              ? `Showing ${(filters.page - 1) * filters.size + 1}–${Math.min(total, filters.page * filters.size)} of ${total} findings`
              : '0 findings'}
            {page.isFetching && !page.isPending && ' · updating…'}
          </span>
          <label className="flex items-center gap-space-sm">
            Rows
            <select
              value={filters.size}
              onChange={(e) => update({ size: Number(e.target.value) })}
              className="rounded bg-surface-container px-space-sm py-1 text-on-surface"
            >
              {pageSizes.map((n) => (
                <option key={n} value={n}>
                  {n} per page
                </option>
              ))}
            </select>
          </label>
          <nav aria-label="Pagination" className="flex items-center gap-1">
            <button
              type="button"
              aria-label="Previous page"
              disabled={filters.page <= 1}
              onClick={() => update({ page: filters.page - 1 })}
              className="rounded px-2 py-1 hover:bg-surface-container-high disabled:opacity-40"
            >
              <Icon name="chevron_left" />
            </button>
            {Array.from({ length: pages }, (_, i) => i + 1).map((p) => (
              <button
                key={p}
                type="button"
                aria-current={p === filters.page ? 'page' : undefined}
                onClick={() => update({ page: p })}
                className={`min-w-8 rounded px-2 py-1 ${p === filters.page ? 'bg-primary-container text-on-primary-container' : 'hover:bg-surface-container-high'}`}
              >
                {p}
              </button>
            ))}
            <button
              type="button"
              aria-label="Next page"
              disabled={filters.page >= pages}
              onClick={() => update({ page: filters.page + 1 })}
              className="rounded px-2 py-1 hover:bg-surface-container-high disabled:opacity-40"
            >
              <Icon name="chevron_right" />
            </button>
          </nav>
        </footer>
      </section>
    </>
  )
}
