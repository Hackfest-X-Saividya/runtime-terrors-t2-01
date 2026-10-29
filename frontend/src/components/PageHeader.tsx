import { Fragment, type ReactNode } from 'react'
import { Link } from 'react-router-dom'

export interface Crumb {
  label: string
  to?: string
}

interface PageHeaderProps {
  title: ReactNode
  description?: ReactNode
  crumbs?: Crumb[]
  meta?: ReactNode
  actions?: ReactNode
}

export function PageHeader({ title, description, crumbs, meta, actions }: PageHeaderProps) {
  return (
    <header className="mb-space-lg flex flex-col justify-between gap-space-md pt-space-lg xl:flex-row xl:items-end">
      <div className="flex min-w-0 flex-col gap-space-xs">
        {crumbs && (
          <nav
            aria-label="Breadcrumb"
            className="flex flex-wrap items-center gap-space-sm font-label-code-sm text-label-code-sm uppercase text-on-surface-variant"
          >
            {crumbs.map((c, i) => (
              <Fragment key={i}>
                {i > 0 && <span aria-hidden="true">/</span>}
                {c.to ? (
                  <Link to={c.to} className="rounded hover:text-on-surface">
                    {c.label}
                  </Link>
                ) : (
                  <span className="normal-case text-primary" aria-current="page">
                    {c.label}
                  </span>
                )}
              </Fragment>
            ))}
          </nav>
        )}
        <h1 className="break-words font-headline-lg text-headline-lg font-bold text-on-surface">{title}</h1>
        {description && <div className="font-body-md text-body-md text-on-surface-variant">{description}</div>}
        {meta && <div className="mt-space-xs flex flex-wrap items-center gap-space-sm">{meta}</div>}
      </div>
      {actions && <div className="flex flex-wrap items-center gap-space-sm">{actions}</div>}
    </header>
  )
}
