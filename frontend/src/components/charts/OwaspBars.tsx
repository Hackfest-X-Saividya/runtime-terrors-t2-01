import { splitOwasp } from '@/lib/labels'
import { EmptyState } from '../States'

/** Horizontal bars per OWASP category, largest first (dashboard screen 01). */
export function OwaspBars({
  counts,
  onSelect,
}: {
  counts: Record<string, number>
  onSelect?: (category: string) => void
}) {
  const rows = Object.entries(counts).sort((a, b) => b[1] - a[1])
  const max = Math.max(1, ...rows.map(([, n]) => n))
  if (!rows.length) return <EmptyState icon="bar_chart" title="No findings to categorise yet" />

  return (
    <ul className="flex flex-col gap-space-md" aria-label="Findings by OWASP Top 10 2025 category">
      {rows.map(([category, n]) => {
        const { code, name } = splitOwasp(category)
        const label = (
          <>
            <span className="flex items-baseline justify-between gap-space-sm">
              <span className="min-w-0 truncate font-body-md text-body-md text-on-surface">
                <span className="mr-space-sm font-mono font-semibold text-primary">{code}</span>
                {name}
              </span>
              <span className="font-mono text-label-code-lg text-on-surface-variant">{n}</span>
            </span>
            <span className="mt-1 block h-2 rounded-full bg-surface-container-high" aria-hidden="true">
              <span className="block h-2 rounded-full bg-primary" style={{ width: `${(n / max) * 100}%` }} />
            </span>
          </>
        )
        return (
          <li key={category}>
            {onSelect ? (
              <button
                type="button"
                onClick={() => onSelect(category)}
                className="block w-full rounded text-left hover:opacity-90"
                aria-label={`${category}: ${n} findings. Show these findings`}
              >
                {label}
              </button>
            ) : (
              <div aria-label={`${category}: ${n} findings`}>{label}</div>
            )}
          </li>
        )
      })}
    </ul>
  )
}
