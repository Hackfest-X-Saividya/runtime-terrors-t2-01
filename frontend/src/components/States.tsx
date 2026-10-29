import type { ReactNode } from 'react'
import { ApiError } from '@/api/client'
import { Button } from './Button'
import { Icon } from './Icon'

export function Skeleton({ className = '' }: { className?: string }) {
  return <div aria-hidden="true" className={`animate-pulse rounded bg-surface-container-high ${className}`} />
}

export function SkeletonRows({ rows = 5 }: { rows?: number }) {
  return (
    <div role="status" aria-label="Loading" className="flex flex-col gap-space-sm">
      {Array.from({ length: rows }, (_, i) => (
        <Skeleton key={i} className="h-10 w-full" />
      ))}
    </div>
  )
}

export function EmptyState({
  icon = 'inbox',
  title,
  children,
}: {
  icon?: string
  title: string
  children?: ReactNode
}) {
  return (
    <div className="flex flex-col items-center gap-space-sm px-space-md py-space-xl text-center">
      <Icon name={icon} className="text-headline-lg text-outline" />
      <p className="font-headline-sm text-headline-sm text-on-surface">{title}</p>
      {children && <div className="max-w-md font-body-md text-body-md text-on-surface-variant">{children}</div>}
    </div>
  )
}

function describe(error: unknown): string {
  if (error instanceof ApiError) {
    if (error.status === 0) return error.message + ' Check that the backend is running, or open the app with ?mock=1.'
    if (error.status === 404) return 'Not found. It may have been removed, or the link is wrong.'
    return error.message
  }
  return error instanceof Error ? error.message : 'Something went wrong.'
}

export function ErrorState({
  error,
  onRetry,
  title = "Couldn't load this",
}: {
  error: unknown
  onRetry?: () => void
  title?: string
}) {
  return (
    <div role="alert" className="flex flex-col items-start gap-space-sm rounded-lg bg-error-container/30 p-space-md">
      <div className="flex items-center gap-space-sm text-error">
        <Icon name="error" />
        <span className="font-headline-sm text-headline-sm">{title}</span>
      </div>
      <p className="font-body-md text-body-md text-on-error-container">{describe(error)}</p>
      {onRetry && (
        <Button icon="refresh" onClick={onRetry}>
          Retry
        </Button>
      )}
    </div>
  )
}
