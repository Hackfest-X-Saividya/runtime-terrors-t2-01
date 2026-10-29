import type { ButtonHTMLAttributes, ReactNode } from 'react'
import { Link } from 'react-router-dom'
import { Icon } from './Icon'

type Variant = 'primary' | 'secondary' | 'ghost' | 'danger'

const styles: Record<Variant, string> = {
  primary: 'bg-primary-container text-on-primary-container hover:bg-primary font-headline-sm text-headline-sm',
  secondary: 'bg-surface-container-high text-on-surface hover:bg-surface-bright font-label-code-md text-label-code-md',
  ghost:
    'text-on-surface-variant hover:bg-surface-container-high hover:text-on-surface font-label-code-md text-label-code-md',
  danger:
    'bg-error-container text-on-error-container hover:bg-error-container/80 font-label-code-md text-label-code-md',
}

const base =
  'inline-flex items-center justify-center gap-1.5 whitespace-nowrap rounded-lg px-space-md py-1.5 transition-colors disabled:cursor-not-allowed disabled:opacity-50'

interface ButtonProps extends ButtonHTMLAttributes<HTMLButtonElement> {
  variant?: Variant
  icon?: string
  children?: ReactNode
}

export function Button({
  variant = 'secondary',
  icon,
  className = '',
  children,
  type = 'button',
  ...rest
}: ButtonProps) {
  return (
    <button type={type} className={`${base} ${styles[variant]} ${className}`} {...rest}>
      {icon && <Icon name={icon} />}
      {children}
    </button>
  )
}

interface ButtonLinkProps {
  to: string
  variant?: Variant
  icon?: string
  className?: string
  children: ReactNode
}

export function ButtonLink({ to, variant = 'secondary', icon, className = '', children }: ButtonLinkProps) {
  return (
    <Link to={to} className={`${base} ${styles[variant]} ${className}`}>
      {icon && <Icon name={icon} />}
      {children}
    </Link>
  )
}
