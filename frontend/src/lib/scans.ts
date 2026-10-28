import type { Scan } from '@/types/contract'

/** The scan this one should be compared with: its rescan_of, else the previous scan with the same name. */
export function previousScanOf(scan: Scan, scans: Scan[]): Scan | null {
  if (scan.rescan_of) return scans.find((s) => s.id === scan.rescan_of) ?? null
  return (
    [...scans]
      .sort((a, b) => b.started_at.localeCompare(a.started_at))
      .find((s) => s.id !== scan.id && s.name === scan.name && s.started_at < scan.started_at) ?? null
  )
}

export const isFinished = (scan: Pick<Scan, 'status'>) =>
  scan.status === 'done' || scan.status === 'partial' || scan.status === 'failed'
