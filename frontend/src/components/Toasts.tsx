import { useCallback, useState, type ReactNode } from 'react'
import { ToastContext, type Toast, type ToastTone } from '@/hooks/useToast'
import { Icon } from './Icon'

const tones: Record<ToastTone, { icon: string; className: string }> = {
  success: { icon: 'check_circle', className: 'text-primary' },
  error: { icon: 'error', className: 'text-error' },
  info: { icon: 'info', className: 'text-secondary' },
}

let nextId = 1

export function ToastProvider({ children }: { children: ReactNode }) {
  const [toasts, setToasts] = useState<Toast[]>([])
  const dismiss = useCallback((id: number) => setToasts((t) => t.filter((x) => x.id !== id)), [])
  const show = useCallback(
    (tone: ToastTone, message: string) => {
      const id = nextId++
      setToasts((t) => [...t.slice(-3), { id, tone, message }])
      setTimeout(() => dismiss(id), tone === 'error' ? 8000 : 5000)
    },
    [dismiss],
  )

  return (
    <ToastContext.Provider value={show}>
      {children}
      <div
        aria-live="polite"
        className="pointer-events-none fixed bottom-space-lg right-space-lg z-[60] flex w-96 max-w-[calc(100vw-2rem)] flex-col gap-space-sm"
      >
        {toasts.map((t) => (
          <div
            key={t.id}
            role={t.tone === 'error' ? 'alert' : 'status'}
            className="pointer-events-auto flex items-start gap-space-sm rounded-lg bg-surface-container-highest p-space-md shadow-md"
          >
            <Icon name={tones[t.tone].icon} className={tones[t.tone].className} />
            <p className="flex-1 font-body-md text-body-md text-on-surface">{t.message}</p>
            <button
              type="button"
              aria-label="Dismiss notification"
              onClick={() => dismiss(t.id)}
              className="rounded text-on-surface-variant hover:text-on-surface"
            >
              <Icon name="close" />
            </button>
          </div>
        ))}
      </div>
    </ToastContext.Provider>
  )
}
