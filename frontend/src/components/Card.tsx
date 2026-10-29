import type { ReactNode } from 'react'
import { Icon } from './Icon'

interface CardProps {
  title?: ReactNode
  subtitle?: ReactNode
  icon?: string
  action?: ReactNode
  className?: string
  padding?: 'md' | 'lg' | 'none'
  children: ReactNode
  /** Labels the section for screen readers when the title is not plain text. */
  label?: string
}

const pad = { none: '', md: 'p-space-md', lg: 'p-space-lg' }

export function Card({ title, subtitle, icon, action, className = '', padding = 'lg', children, label }: CardProps) {
  return (
    <section
      aria-label={label}
      className={`rounded-xl bg-surface-container-low shadow-sm ${pad[padding]} ${className}`}
    >
      {(title || action || icon) && (
        <header
          className={`mb-space-md flex items-start justify-between gap-space-md ${padding === 'none' ? 'px-space-lg pt-space-lg' : ''}`}
        >
          <div className="min-w-0">
            {title && <h2 className="font-headline-md text-headline-md text-on-surface">{title}</h2>}
            {subtitle && <p className="font-body-md text-body-md text-on-surface-variant">{subtitle}</p>}
          </div>
          {action ?? (icon && <Icon name={icon} className="text-headline-sm text-on-surface-variant" />)}
        </header>
      )}
      {children}
    </section>
  )
}
