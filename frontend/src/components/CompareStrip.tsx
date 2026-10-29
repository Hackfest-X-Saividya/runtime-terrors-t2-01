import { Link } from 'react-router-dom'
import { useScanDiff, useScans } from '@/api/hooks'
import { fmtDateTime } from '@/lib/format'
import { Icon } from './Icon'
import { Skeleton } from './States'

/** "Compared with previous scan: +N new, −N resolved, N suppressed by feedback". */
export function CompareStrip({ scanId, showLink = true }: { scanId: string; showLink?: boolean }) {
  const diff = useScanDiff(scanId)
  const scans = useScans()
  if (diff.isPending) return <Skeleton className="mb-space-lg h-12 w-full rounded-xl" />
  if (diff.isError || !diff.data.previous_scan_id) return null
  const d = diff.data
  const prev = scans.data?.find((s) => s.id === d.previous_scan_id)

  return (
    <section
      aria-label="Comparison with previous scan"
      className="mb-space-lg flex flex-wrap items-center gap-space-md rounded-xl bg-surface-container-low px-space-md py-space-sm shadow-sm"
    >
      <span className="flex items-center gap-space-sm font-label-code-md text-label-code-md text-on-surface">
        <Icon name="compare_arrows" className="text-primary" />
        Compared with previous scan
        <span className="text-on-surface-variant">
          ({prev ? `${prev.name} · ${fmtDateTime(prev.started_at)}` : d.previous_scan_id})
        </span>
      </span>
      <span className="rounded bg-error-container/40 px-2 py-0.5 font-label-code-md text-label-code-md text-error">
        +{d.new.length} new
      </span>
      <span className="rounded bg-primary/10 px-2 py-0.5 font-label-code-md text-label-code-md text-primary">
        −{d.resolved.length} resolved
      </span>
      <span className="rounded bg-secondary/15 px-2 py-0.5 font-label-code-md text-label-code-md text-secondary">
        Suppressed by feedback: {d.suppressed.length}
      </span>
      <span className="rounded bg-surface-container-high px-2 py-0.5 font-label-code-md text-label-code-md text-on-surface-variant">
        {d.still_open.length} still open
      </span>
      {showLink && (
        <Link
          to={`/scans/${scanId}/changes`}
          className="ml-auto flex items-center gap-1 rounded font-label-code-md text-label-code-md text-primary hover:underline"
        >
          View changes <Icon name="arrow_forward" />
        </Link>
      )}
    </section>
  )
}
