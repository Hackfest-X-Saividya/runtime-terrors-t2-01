import { useCallback, useMemo } from 'react'
import { useSearchParams } from 'react-router-dom'
import type { FindingSort, FindingSource, FindingStatus, FindingsQuery, Severity } from '@/types/contract'

export interface FindingFilters {
  severity?: Severity
  owasp?: string
  source?: FindingSource
  status?: FindingStatus
  q?: string
  suppressed: boolean
  sort: FindingSort
  page: number
  size: number
}

const severities: Severity[] = ['critical', 'high', 'medium', 'low']
const sources: FindingSource[] = ['rule', 'ml', 'both']
const statuses: FindingStatus[] = ['open', 'fixed', 'false_positive', 'accepted']
const sorts: FindingSort[] = ['risk_score', '-risk_score', 'severity', '-severity', 'file_path', '-file_path']
export const pageSizes = [25, 50, 100]

const pick = <T extends string>(value: string | null, allowed: readonly T[]): T | undefined =>
  allowed.find((a) => a === value)

/** Findings filters kept in the URL so views can be shared and survive reloads. */
export function useFindingFilters() {
  const [params, setParams] = useSearchParams()

  const filters: FindingFilters = useMemo(
    () => ({
      severity: pick(params.get('severity'), severities),
      owasp: params.get('owasp') || undefined,
      source: pick(params.get('source'), sources),
      status: pick(params.get('status'), statuses),
      q: params.get('q') || undefined,
      suppressed: params.get('suppressed') === '1',
      sort: pick(params.get('sort'), sorts) ?? '-risk_score',
      page: Math.max(1, Number(params.get('page')) || 1),
      size: pageSizes.find((s) => s === Number(params.get('size'))) ?? 50,
    }),
    [params],
  )

  /** Changing any filter except page resets to page 1. */
  const update = useCallback(
    (patch: Partial<FindingFilters>) => {
      setParams(
        (prev) => {
          const next = new URLSearchParams(prev)
          for (const [key, value] of Object.entries(patch)) {
            const k = key === 'suppressed' ? 'suppressed' : key
            if (value === undefined || value === '' || value === false) next.delete(k)
            else next.set(k, value === true ? '1' : String(value))
          }
          if (!('page' in patch)) next.delete('page')
          if (next.get('sort') === '-risk_score') next.delete('sort')
          if (next.get('size') === '50') next.delete('size')
          if (next.get('page') === '1') next.delete('page')
          return next
        },
        { replace: true },
      )
    },
    [setParams],
  )

  const clear = useCallback(() => setParams({}, { replace: true }), [setParams])

  const query: FindingsQuery = {
    severity: filters.severity,
    owasp: filters.owasp,
    source: filters.source,
    status: filters.status,
    q: filters.q,
    include_suppressed: filters.suppressed || undefined,
    sort: filters.sort,
    limit: filters.size,
    offset: (filters.page - 1) * filters.size,
  }

  const active = [filters.severity, filters.owasp, filters.source, filters.status, filters.q].filter(Boolean).length

  return { filters, query, update, clear, active }
}
