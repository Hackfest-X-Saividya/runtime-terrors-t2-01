import type { ReactNode } from 'react'
import { Icon } from './Icon'
import { Skeleton } from './States'

interface KpiCardProps {
  label: string
  value: ReactNode
  icon?: string
  badge?: ReactNode
  footer?: ReactNode
  valueClassName?: string
  loading?: boolean
}

export function KpiCard({
  label,
  value,
  icon,
  badge,
  footer,
  valueClassName = 'text-on-surface',
  loading,
}: KpiCardProps) {
  return (
    <div className="flex min-h-36 flex-col justify-between gap-space-sm rounded-xl bg-surface-container-low p-space-md shadow-sm">
      <div className="flex items-center justify-between gap-space-sm text-on-surface-variant">
        <span className="font-body-sm text-body-sm font-medium uppercase tracking-wide">{label}</span>
        {icon && <Icon name={icon} />}
      </div>
      {loading ? (
        <Skeleton className="h-9 w-20" />
      ) : (
        <div className="flex flex-col items-start gap-space-xs">
          {badge}
          <div className={`font-mono text-headline-lg font-bold ${valueClassName}`}>{value}</div>
        </div>
      )}
      <div className="min-h-4 font-label-code-sm text-label-code-sm text-on-surface-variant">{!loading && footer}</div>
    </div>
  )
}
