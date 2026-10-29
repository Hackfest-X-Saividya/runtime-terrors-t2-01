import type { ScanSocketLike } from '@/lib/socket'
import { subscribe } from './db'

/** In-page stand-in for /ws/scans/{id}: relays the mock db's scan events as JSON messages. */
export class MockScanSocket implements ScanSocketLike {
  onopen: (() => void) | null = null
  onmessage: ((event: { data: string }) => void) | null = null
  onclose: (() => void) | null = null
  onerror: (() => void) | null = null
  private unsubscribe: (() => void) | null = null
  private closed = false

  constructor(scanId: string) {
    // Connect asynchronously, like a real socket.
    setTimeout(() => {
      if (this.closed) return
      try {
        this.onopen?.()
        this.unsubscribe = subscribe(scanId, (msg) => {
          if (!this.closed) this.onmessage?.({ data: JSON.stringify(msg) })
        })
      } catch {
        this.onerror?.()
        this.close()
      }
    }, 50)
  }

  close() {
    if (this.closed) return
    this.closed = true
    this.unsubscribe?.()
    this.onclose?.()
  }
}
