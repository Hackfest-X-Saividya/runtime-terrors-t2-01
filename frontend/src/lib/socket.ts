/** The subset of WebSocket the scan socket hook uses, so mocks can provide a fake. */
export interface ScanSocketLike {
  onopen: (() => void) | null
  onmessage: ((event: { data: string }) => void) | null
  onclose: (() => void) | null
  onerror: (() => void) | null
  close(): void
}

type Factory = (url: string, scanId: string) => ScanSocketLike

function realSocket(url: string): ScanSocketLike {
  const ws = new WebSocket(url)
  const like: ScanSocketLike = {
    onopen: null,
    onmessage: null,
    onclose: null,
    onerror: null,
    close: () => ws.close(),
  }
  ws.onopen = () => like.onopen?.()
  ws.onmessage = (event: MessageEvent<string>) => like.onmessage?.({ data: event.data })
  ws.onclose = () => like.onclose?.()
  ws.onerror = () => like.onerror?.()
  return like
}

let factory: Factory = realSocket

export const openScanSocket: Factory = (url, scanId) => factory(url, scanId)

/** Mock mode swaps in an in-page socket that plays the fake scan. */
export function setScanSocketFactory(next: Factory) {
  factory = next
}
