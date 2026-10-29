const nf = new Intl.NumberFormat('en-US')

export const fmtNumber = (n: number) => nf.format(n)
export const fmtScore = (n?: number | null) => (typeof n === 'number' && !isNaN(n) ? n.toFixed(1) : '-')
export const fmtPct = (n?: number | null, digits = 1) =>
  typeof n === 'number' && !isNaN(n) ? `${(n * 100).toFixed(digits)}%` : '-'

export function fmtDateTime(iso: string) {
  return new Date(iso).toLocaleString('en-GB', {
    day: 'numeric',
    month: 'short',
    hour: '2-digit',
    minute: '2-digit',
  })
}

export function fmtRelative(iso: string, now = Date.now()) {
  const s = Math.round((now - new Date(iso).getTime()) / 1000)
  if (s < 45) return 'just now'
  const m = Math.round(s / 60)
  if (m < 60) return `${m}m ago`
  const h = Math.round(m / 60)
  if (h < 24) return `${h}h ago`
  const d = Math.round(h / 24)
  return `${d}d ago`
}

export function fmtDuration(fromIso: string, toIso: string) {
  const s = Math.max(0, Math.round((new Date(toIso).getTime() - new Date(fromIso).getTime()) / 1000))
  return s < 60 ? `${s}s` : `${Math.floor(s / 60)}m ${String(s % 60).padStart(2, '0')}s`
}

export function fmtBytes(bytes: number) {
  if (bytes < 1024) return `${bytes} B`
  if (bytes < 1024 ** 2) return `${(bytes / 1024).toFixed(1)} KB`
  return `${(bytes / 1024 ** 2).toFixed(1)} MB`
}
