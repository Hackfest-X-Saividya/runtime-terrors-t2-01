import { useEffect, useState } from 'react'
import { Icon } from '@/components/Icon'
import type { FindingFilters } from '@/hooks/useFindingFilters'
import {
  findingStatusMeta,
  findingStatusOrder,
  owaspCategories,
  severityMeta,
  severityOrder,
  sourceLabel,
} from '@/lib/labels'
import type { Finding, FindingSource } from '@/types/contract'

interface FilterBarProps {
  filters: FindingFilters
  /** All findings of the scan (for facet counts). */
  facets: Finding[]
  suppressedCount: number
  active: number
  update: (patch: Partial<FindingFilters>) => void
  clear: () => void
}

const select =
  'rounded-lg bg-surface-container px-space-sm py-1.5 font-label-code-md text-label-code-md text-on-surface'

export function FilterBar({ filters, facets, suppressedCount, active, update, clear }: FilterBarProps) {
  const [q, setQ] = useState(filters.q ?? '')
  useEffect(() => setQ(filters.q ?? ''), [filters.q])
  useEffect(() => {
    const t = setTimeout(() => {
      if ((filters.q ?? '') !== q.trim()) update({ q: q.trim() || undefined })
    }, 300)
    return () => clearTimeout(t)
  }, [q, filters.q, update])

  const visible = facets.filter((f) => filters.suppressed || !f.suppressed)
  const count = (pred: (f: Finding) => boolean) => visible.filter(pred).length
  const owaspPresent = owaspCategories.filter((c) => visible.some((f) => f.owasp === c))

  return (
    <section
      aria-label="Filters"
      className="mb-space-lg flex flex-col gap-space-md rounded-xl bg-surface-container-low p-space-md shadow-sm"
    >
      <div className="flex flex-wrap items-center gap-space-md">
        <div className="relative min-w-64 flex-1">
          <Icon
            name="search"
            className="pointer-events-none absolute left-3 top-1/2 -translate-y-1/2 text-on-surface-variant"
          />
          <input
            type="search"
            value={q}
            onChange={(e) => setQ(e.target.value)}
            aria-label="Search title, file, CWE, rule"
            placeholder="Search title, file, CWE, rule…"
            className="w-full rounded-lg bg-surface-container py-2 pl-9 pr-space-md font-label-code-md text-label-code-md text-on-surface placeholder:text-outline"
          />
        </div>
        <div role="radiogroup" aria-label="Status" className="flex flex-wrap gap-1 rounded-lg bg-surface-container p-1">
          {[undefined, ...findingStatusOrder].map((s) => {
            const on = filters.status === s
            return (
              <button
                key={s ?? 'all'}
                type="button"
                role="radio"
                aria-checked={on}
                onClick={() => update({ status: s })}
                className={`rounded px-space-sm py-1 font-label-code-md text-label-code-md ${on ? 'bg-surface-container-highest text-on-surface' : 'text-on-surface-variant hover:text-on-surface'}`}
              >
                {s ? findingStatusMeta[s].label : 'All'}{' '}
                <span className="text-on-surface-variant">{s ? count((f) => f.status === s) : visible.length}</span>
              </button>
            )
          })}
        </div>
      </div>

      <div className="flex flex-wrap items-center gap-space-sm">
        <span className="font-label-code-sm text-label-code-sm uppercase text-on-surface-variant">Severity</span>
        {severityOrder.map((s) => {
          const on = filters.severity === s
          const m = severityMeta[s]
          return (
            <button
              key={s}
              type="button"
              aria-pressed={on}
              onClick={() => update({ severity: on ? undefined : s })}
              className={`flex items-center gap-1.5 rounded px-2.5 py-1 font-label-code-sm text-label-code-sm ${on ? `${m.badge} ${m.text} shadow-sm` : 'bg-surface-container text-on-surface-variant hover:text-on-surface'}`}
            >
              <span aria-hidden="true" className={`h-2 w-2 rounded-full ${m.dot}`} />
              {m.label.toUpperCase()} <span className="opacity-80">{count((f) => f.severity === s)}</span>
              {on && <Icon name="close" />}
            </button>
          )
        })}

        <span aria-hidden="true" className="mx-1 h-5 w-px bg-outline-variant" />

        <label className="sr-only" htmlFor="f-owasp">
          OWASP category
        </label>
        <select
          id="f-owasp"
          value={filters.owasp ?? ''}
          onChange={(e) => update({ owasp: e.target.value || undefined })}
          className={select}
        >
          <option value="">OWASP: all Top 10 (2025)</option>
          {owaspPresent.map((c) => (
            <option key={c} value={c}>
              {c} ({count((f) => f.owasp === c)})
            </option>
          ))}
        </select>

        <label className="sr-only" htmlFor="f-source">
          Detection source
        </label>
        <select
          id="f-source"
          value={filters.source ?? ''}
          onChange={(e) => update({ source: (e.target.value || undefined) as FindingSource | undefined })}
          className={select}
        >
          <option value="">Source: all detectors</option>
          {(['rule', 'ml', 'both'] as const).map((s) => (
            <option key={s} value={s}>
              {sourceLabel[s]}
              {s === 'ml' ? ' (Novel)' : ''} ({count((f) => f.source === s)})
            </option>
          ))}
        </select>

        <label className="ml-auto flex cursor-pointer items-center gap-space-sm rounded-lg bg-surface-container px-space-sm py-1.5 font-label-code-md text-label-code-md text-on-surface">
          <input
            type="checkbox"
            role="switch"
            checked={filters.suppressed}
            onChange={(e) => update({ suppressed: e.target.checked })}
            className="h-4 w-4 accent-primary"
          />
          Show suppressed <span className="text-on-surface-variant">({suppressedCount})</span>
        </label>

        {active > 0 && (
          <button
            type="button"
            onClick={clear}
            className="flex items-center gap-1 rounded font-label-code-md text-label-code-md text-primary hover:underline"
          >
            <Icon name="filter_alt_off" /> Clear filters ({active} active)
          </button>
        )}
      </div>
    </section>
  )
}
