interface IconProps {
  name: string
  className?: string
  filled?: boolean
}

/** Material Symbols Outlined icon. Decorative: always pair it with visible text. */
export function Icon({ name, className = '', filled }: IconProps) {
  return (
    <span
      aria-hidden="true"
      className={`material-symbols-outlined select-none ${className}`}
      style={filled ? { fontVariationSettings: "'FILL' 1" } : undefined}
    >
      {name}
    </span>
  )
}
