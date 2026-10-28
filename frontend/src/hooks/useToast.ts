import { createContext, useContext } from 'react'

export type ToastTone = 'success' | 'error' | 'info'

export interface Toast {
  id: number
  tone: ToastTone
  message: string
}

export const ToastContext = createContext<(tone: ToastTone, message: string) => void>(() => undefined)

/** toast('success', 'Saved') */
export const useToast = () => useContext(ToastContext)
