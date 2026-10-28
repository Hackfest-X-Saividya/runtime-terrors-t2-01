import { useEffect, useRef, type ReactNode } from 'react'

interface PopoverProps {
  open: boolean
  onClose: () => void
  label: string
  align?: 'left' | 'right'
  children: ReactNode
  /** The trigger, rendered in place; the panel opens below it. */
  anchor: ReactNode
}

/** Anchored dialog: closes on Escape or outside click, focuses its first field. */
export function Popover({ open, onClose, label, align = 'left', children, anchor }: PopoverProps) {
  const wrap = useRef<HTMLDivElement>(null)
  const panel = useRef<HTMLDivElement>(null)

  useEffect(() => {
    if (!open) return
    panel.current?.querySelector<HTMLElement>('select, textarea, input, button')?.focus()
    const onKey = (e: KeyboardEvent) => e.key === 'Escape' && onClose()
    const onDown = (e: MouseEvent) => {
      if (wrap.current && !wrap.current.contains(e.target as Node)) onClose()
    }
    document.addEventListener('keydown', onKey)
    document.addEventListener('mousedown', onDown)
    return () => {
      document.removeEventListener('keydown', onKey)
      document.removeEventListener('mousedown', onDown)
    }
  }, [open, onClose])

  return (
    <div ref={wrap} className="relative">
      {anchor}
      {open && (
        <div
          ref={panel}
          role="dialog"
          aria-label={label}
          className={`absolute top-full z-30 mt-space-sm w-96 max-w-[90vw] rounded-xl bg-surface-container-highest p-space-md shadow-md ${align === 'right' ? 'right-0' : 'left-0'}`}
        >
          {children}
        </div>
      )}
    </div>
  )
}
