import { API_URL } from '@/lib/env'
import type {
  CreateScanInput,
  CreateScanResponse,
  Finding,
  FindingsPage,
  FindingsQuery,
  Health,
  ModelInfo,
  ReportFormat,
  RevertModelInput,
  RevertModelResponse,
  Scan,
  ScanDiff,
  Summary,
  UpdateFindingInput,
} from '@/types/contract'

/** Any failed request. status 0 = network error (backend unreachable). */
export class ApiError extends Error {
  readonly status: number
  readonly path: string
  readonly detail: string | null

  constructor(status: number, path: string, detail: string | null = null) {
    super(
      status === 0
        ? `Can't reach the API at ${API_URL}.`
        : `${path} failed with ${status}${detail ? `: ${detail}` : ''}`,
    )
    this.name = 'ApiError'
    this.status = status
    this.path = path
    this.detail = detail
  }
}

async function readDetail(res: Response): Promise<string | null> {
  try {
    const text = await res.text()
    if (!text) return null
    try {
      const body: unknown = JSON.parse(text)
      if (body && typeof body === 'object' && 'detail' in body) return String(body.detail)
    } catch {
      // Not JSON: use the raw text.
    }
    return text.slice(0, 200)
  } catch {
    return null
  }
}

async function send(path: string, init?: RequestInit): Promise<Response> {
  let res: Response
  try {
    res = await fetch(`${API_URL}${path}`, init)
  } catch {
    throw new ApiError(0, path)
  }
  if (!res.ok) throw new ApiError(res.status, path, await readDetail(res))
  return res
}

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  return (await send(path, init)).json() as Promise<T>
}

const json = (method: string, body: unknown): RequestInit => ({
  method,
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify(body),
})

export function toQuery(params: object): string {
  const q = new URLSearchParams()
  for (const [key, value] of Object.entries(params)) {
    if (value !== undefined && value !== null && value !== '' && value !== false) q.set(key, String(value))
  }
  const s = q.toString()
  return s ? `?${s}` : ''
}

export function getReportUrl(scanId: string, format: ReportFormat): string {
  return `${API_URL}/api/scans/${encodeURIComponent(scanId)}/report${toQuery({ format })}`
}

export const api = {
  createScan(input: CreateScanInput): Promise<CreateScanResponse> {
    switch (input.kind) {
      case 'zip': {
        const body = new FormData()
        body.append('file', input.file)
        return request('/api/scans', { method: 'POST', body })
      }
      case 'git':
        return request('/api/scans', json('POST', { git_url: input.git_url }))
      case 'paste':
        return request('/api/scans', json('POST', { code: input.code, filename: input.filename }))
      case 'rescan':
        return request('/api/scans', json('POST', { rescan_of: input.rescan_of }))
    }
  },
  listScans: () => request<Scan[]>('/api/scans'),
  getScan: (id: string) => request<Scan>(`/api/scans/${encodeURIComponent(id)}`),
  listFindings: async (scanId: string, query: FindingsQuery = {}): Promise<FindingsPage> => {
    const raw = await request<FindingsPage | Finding[]>(
      `/api/scans/${encodeURIComponent(scanId)}/findings${toQuery(query)}`,
    )
    if (Array.isArray(raw)) {
      return {
        items: raw,
        total: raw.length,
      }
    }
    if (raw && typeof raw === 'object' && Array.isArray((raw as FindingsPage).items)) {
      return {
        items: (raw as FindingsPage).items,
        total: typeof (raw as FindingsPage).total === 'number' ? (raw as FindingsPage).total : (raw as FindingsPage).items.length,
      }
    }
    return { items: [], total: 0 }
  },
  getScanDiff: (scanId: string) => request<ScanDiff>(`/api/scans/${encodeURIComponent(scanId)}/diff`),
  getFinding: (id: string) => request<Finding>(`/api/findings/${encodeURIComponent(id)}`),
  updateFinding: (id: string, input: UpdateFindingInput) =>
    request<Finding>(`/api/findings/${encodeURIComponent(id)}`, json('PATCH', input)),
  getSummary: () => request<Summary>('/api/stats/summary'),
  getModelInfo: () => request<ModelInfo>('/api/model/info'),
  revertModel: (input: RevertModelInput) => request<RevertModelResponse>('/api/model/revert', json('POST', input)),
  health: () => request<Health>('/health'),
  /** Report as text (HTML) for the preview iframe. */
  getReportHtml: async (scanId: string) =>
    (await send(`/api/scans/${encodeURIComponent(scanId)}/report${toQuery({ format: 'html' })}`)).text(),
  /** Report as a Blob, for downloads. */
  getReportBlob: async (scanId: string, format: ReportFormat) =>
    (await send(`/api/scans/${encodeURIComponent(scanId)}/report${toQuery({ format })}`)).blob(),
}

/** ws(s)://host/ws/scans/{id}, derived from VITE_API_URL. */
export function scanSocketUrl(scanId: string): string {
  return `${API_URL.replace(/^http/, 'ws')}/ws/scans/${encodeURIComponent(scanId)}`
}
