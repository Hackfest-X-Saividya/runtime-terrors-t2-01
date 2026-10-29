import { keepPreviousData, useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import type { CreateScanInput, Finding, FindingsQuery, Scan, UpdateFindingInput } from '@/types/contract'
import { api } from './client'

export const keys = {
  scans: ['scans'] as const,
  scan: (id: string) => ['scans', id] as const,
  findings: (scanId: string, query: FindingsQuery) => ['scans', scanId, 'findings', query] as const,
  diff: (scanId: string) => ['scans', scanId, 'diff'] as const,
  finding: (id: string) => ['findings', id] as const,
  summary: ['summary'] as const,
  modelInfo: ['model-info'] as const,
  health: ['health'] as const,
  report: (scanId: string) => ['report', scanId] as const,
}

export const isScanActive = (scan: Pick<Scan, 'status'> | undefined) =>
  scan?.status === 'queued' || scan?.status === 'running'

export const useScans = () => useQuery({ queryKey: keys.scans, queryFn: api.listScans })

/** Polls every `pollMs` while the scan is queued/running (WebSocket fallback). */
export const useScan = (id: string | undefined, pollMs?: number) =>
  useQuery({
    queryKey: keys.scan(id ?? ''),
    queryFn: () => api.getScan(id ?? ''),
    enabled: !!id,
    refetchInterval: (q) => (pollMs && isScanActive(q.state.data) ? pollMs : false),
  })

export const useFindings = (scanId: string | undefined, query: FindingsQuery = {}, pollMs?: number) =>
  useQuery({
    queryKey: keys.findings(scanId ?? '', query),
    queryFn: () => api.listFindings(scanId ?? '', query),
    enabled: !!scanId,
    placeholderData: keepPreviousData,
    refetchInterval: pollMs || false,
  })

export const useScanDiff = (scanId: string | undefined) =>
  useQuery({ queryKey: keys.diff(scanId ?? ''), queryFn: () => api.getScanDiff(scanId ?? ''), enabled: !!scanId })

export const useFinding = (id: string | undefined) =>
  useQuery({ queryKey: keys.finding(id ?? ''), queryFn: () => api.getFinding(id ?? ''), enabled: !!id })

export const useSummary = () => useQuery({ queryKey: keys.summary, queryFn: api.getSummary })

export const useModelInfo = () => useQuery({ queryKey: keys.modelInfo, queryFn: api.getModelInfo })

export const useHealth = () =>
  useQuery({ queryKey: keys.health, queryFn: api.health, refetchInterval: 30_000, retry: false })

export const useReportHtml = (scanId: string | undefined) =>
  useQuery({ queryKey: keys.report(scanId ?? ''), queryFn: () => api.getReportHtml(scanId ?? ''), enabled: !!scanId })

export function useCreateScan() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: (input: CreateScanInput) => api.createScan(input),
    onSuccess: () => qc.invalidateQueries({ queryKey: keys.scans }),
  })
}

/** Everything a feedback change can touch: findings, scores, model version, summary. */
function invalidateAfterFeedback(qc: ReturnType<typeof useQueryClient>, findings: Finding[]) {
  for (const f of findings) qc.setQueryData(keys.finding(f.id), f)
  qc.invalidateQueries({ queryKey: keys.scans })
  qc.invalidateQueries({ queryKey: ['findings'] })
  qc.invalidateQueries({ queryKey: keys.summary })
  qc.invalidateQueries({ queryKey: keys.modelInfo })
}

export function useUpdateFinding() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: ({ id, ...input }: UpdateFindingInput & { id: string }) => api.updateFinding(id, input),
    onSuccess: (finding) => invalidateAfterFeedback(qc, [finding]),
  })
}

/** Same feedback for several findings (Findings page bulk actions). */
export function useBulkUpdateFindings() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: async ({ ids, ...input }: UpdateFindingInput & { ids: string[] }) => {
      const results: Finding[] = []
      // Sequential so each feedback event sees the model version the previous one produced.
      for (const id of ids) results.push(await api.updateFinding(id, input))
      return results
    },
    onSuccess: (findings) => invalidateAfterFeedback(qc, findings),
  })
}

export function useRevertModel() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: (version: string) => api.revertModel({ version }),
    onSuccess: () => invalidateAfterFeedback(qc, []),
  })
}
