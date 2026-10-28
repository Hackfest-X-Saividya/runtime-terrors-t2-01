import { useEffect, useState } from 'react'
import { scanSocketUrl } from '@/api/client'
import { openScanSocket, type ScanSocketLike } from '@/lib/socket'
import type { Finding, Scan, ScanSocketMessage, ScanStage } from '@/types/contract'

export interface ScanProgress {
  stage: ScanStage
  done: number
  total: number
}

/**
 * connecting / live: socket open. reconnecting: retrying with backoff.
 * polling: gave up on the socket; callers should poll REST instead. closed: scan finished.
 */
export type SocketMode = 'idle' | 'connecting' | 'live' | 'reconnecting' | 'polling' | 'closed'

export interface ScanSocketState {
  mode: SocketMode
  progress: ScanProgress | null
  findings: Finding[]
  result: Scan | null
}

const MAX_RETRIES = 3
const initial: ScanSocketState = { mode: 'idle', progress: null, findings: [], result: null }

function parse(data: string): ScanSocketMessage | null {
  try {
    const msg: unknown = JSON.parse(data)
    if (msg && typeof msg === 'object' && 'type' in msg && 'data' in msg) return msg as ScanSocketMessage
  } catch {
    // Ignore malformed frames.
  }
  return null
}

/** Live updates for one scan over /ws/scans/{id}, with reconnect and a polling fallback. */
export function useScanSocket(scanId: string | undefined): ScanSocketState {
  const [state, setState] = useState<ScanSocketState>(initial)

  useEffect(() => {
    if (!scanId) return
    let socket: ScanSocketLike | null = null
    let retry: ReturnType<typeof setTimeout> | undefined
    let attempts = 0
    let stopped = false
    let finished = false
    setState({ ...initial, mode: 'connecting' })

    const connect = () => {
      socket = openScanSocket(scanSocketUrl(scanId), scanId)
      socket.onopen = () => {
        attempts = 0
        setState((s) => ({ ...s, mode: 'live' }))
      }
      socket.onmessage = (event) => {
        const msg = parse(event.data)
        if (!msg) return
        setState((s) => {
          switch (msg.type) {
            case 'progress':
              return { ...s, progress: msg.data }
            case 'finding':
              return s.findings.some((f) => f.id === msg.data.id) ? s : { ...s, findings: [...s.findings, msg.data] }
            case 'done':
              return { ...s, result: msg.data, mode: 'closed' }
          }
        })
        if (msg.type === 'done') {
          finished = true
          socket?.close()
        }
      }
      socket.onclose = () => {
        if (stopped || finished) return
        attempts++
        if (attempts > MAX_RETRIES) {
          setState((s) => ({ ...s, mode: 'polling' }))
          return
        }
        setState((s) => ({ ...s, mode: 'reconnecting' }))
        retry = setTimeout(connect, 1000 * 2 ** (attempts - 1))
      }
      socket.onerror = null
    }
    connect()

    return () => {
      stopped = true
      clearTimeout(retry)
      socket?.close()
    }
  }, [scanId])

  return scanId ? state : initial
}
