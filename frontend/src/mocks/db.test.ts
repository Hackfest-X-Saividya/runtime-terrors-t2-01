import { setupServer } from 'msw/node'
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest'
import { api, ApiError } from '@/api/client'
import { resetDb, scanFindings } from './db'
import { handlers } from './handlers'

const server = setupServer(...handlers)
beforeAll(() => server.listen({ onUnhandledRequest: 'error' }))
afterAll(() => server.close())
beforeEach(() => resetDb())
afterEach(() => vi.useRealTimers())

async function allFindings(scanId: string) {
  return (await api.listFindings(scanId, { limit: 500, include_suppressed: true })).items
}

describe('seed data', () => {
  it('has 3 scans and 60 realistic findings', async () => {
    const scans = await api.listScans()
    expect(scans).toHaveLength(3)
    const findings = (await Promise.all(scans.map((s) => allFindings(s.id)))).flat()
    expect(findings).toHaveLength(60)
    expect(new Set(findings.map((f) => f.severity))).toEqual(new Set(['critical', 'high', 'medium', 'low']))
    expect(new Set(findings.map((f) => f.source))).toEqual(new Set(['rule', 'ml', 'both']))
    expect(findings.filter((f) => f.source === 'ml').length).toBeGreaterThanOrEqual(8)
    expect(new Set(findings.map((f) => f.owasp)).size).toBeGreaterThanOrEqual(6)
    for (const f of findings) {
      expect(f.cwe_id).toMatch(/^CWE-\d+$/)
      expect(f.end_line).toBeGreaterThanOrEqual(f.start_line)
      expect(f.risk_score).toBeGreaterThanOrEqual(0)
      expect(f.risk_score).toBeLessThanOrEqual(10)
      expect(f.source === 'rule' ? f.ml_score === null : f.ml_score !== null).toBe(true)
    }
  })

  it('hides suppressed findings unless asked', async () => {
    const visible = await api.listFindings('scan-002', { limit: 500 })
    const all = await allFindings('scan-002')
    expect(all.length - visible.total).toBe(2)
  })

  it('filters, sorts and paginates', async () => {
    const crit = await api.listFindings('scan-002', { severity: 'critical', sort: '-risk_score' })
    expect(crit.items.every((f) => f.severity === 'critical')).toBe(true)
    const scores = crit.items.map((f) => f.risk_score)
    expect(scores).toEqual([...scores].sort((a, b) => b - a))
    const page = await api.listFindings('scan-002', { limit: 5, offset: 5 })
    expect(page.items).toHaveLength(5)
    const search = await api.listFindings('scan-002', { q: 'pickle' })
    expect(search.items.every((f) => /pickle/i.test(f.title + f.snippet))).toBe(true)
  })
})

describe('feedback learning', () => {
  it('requires a reason for false positives', async () => {
    const err = await api.updateFinding('f-002-01', { status: 'false_positive' }).catch((e: unknown) => e)
    expect(err).toBeInstanceOf(ApiError)
    expect((err as ApiError).status).toBe(422)
  })

  it('training on an ML finding bumps the model and lowers same-file, same-CWE scores', async () => {
    const before = await api.getModelInfo()
    const target = (await allFindings('scan-002')).find((f) => f.source === 'ml' && f.cwe_id === 'CWE-918')
    if (!target || target.ml_score === null) throw new Error('fixture missing')
    const sibling = scanFindings('scan-001').find((f) => f.file_path === target.file_path && f.cwe_id === target.cwe_id)

    const updated = await api.updateFinding(target.id, { status: 'false_positive', reason: 'Test code', train: true })
    expect(updated.ml_score_before).toBe(target.ml_score)
    expect(updated.ml_score).toBeLessThan(target.ml_score)
    expect(updated.feedback?.train).toBe(true)

    const after = await api.getModelInfo()
    expect(after.learning.version).not.toBe(before.learning.version)
    expect(after.learning.versions).toHaveLength(before.learning.versions.length + 1)
    expect(after.learning.feedback_count).toBe(before.learning.feedback_count + 1)
    if (sibling) expect((await api.getFinding(sibling.id)).ml_score_before).not.toBeNull()
  })

  it('never changes the model for rule-only findings', async () => {
    const before = await api.getModelInfo()
    const rule = (await allFindings('scan-002')).find((f) => f.source === 'rule')
    if (!rule) throw new Error('fixture missing')
    const updated = await api.updateFinding(rule.id, { status: 'false_positive', reason: 'Not reachable', train: true })
    expect(updated.ml_score).toBeNull()
    expect(updated.suppressed).toBe(false)
    expect((await api.getModelInfo()).learning.version).toBe(before.learning.version)
  })

  it('a rescan suppresses findings the model learned to ignore and lists them in the diff', async () => {
    vi.useFakeTimers({ toFake: ['setTimeout', 'clearTimeout'] })
    const target = (await allFindings('scan-002')).find((f) => f.source === 'ml' && f.cwe_id === 'CWE-918')
    if (!target) throw new Error('fixture missing')
    await api.updateFinding(target.id, { status: 'false_positive', reason: 'Internal only', train: true })

    const { scan_id } = await api.createScan({ kind: 'rescan', rescan_of: 'scan-002' })
    expect((await api.getScan(scan_id)).status).toBe('queued')
    await vi.advanceTimersByTimeAsync(21_000)
    const scan = await api.getScan(scan_id)
    expect(scan.status).toBe('done')
    expect(scan.rescan_of).toBe('scan-002')

    const d = await api.getScanDiff(scan_id)
    expect(d.previous_scan_id).toBe('scan-002')
    expect(d.suppressed.some((f) => f.file_path === target.file_path && f.cwe_id === target.cwe_id)).toBe(true)
    expect(d.suppressed.every((f) => f.source !== 'rule')).toBe(true)
  })

  it('revert restores scores and the previous model version', async () => {
    const target = (await allFindings('scan-002')).find((f) => f.source === 'ml' && f.cwe_id === 'CWE-918')
    if (!target) throw new Error('fixture missing')
    const before = await api.getModelInfo()
    await api.updateFinding(target.id, { status: 'false_positive', reason: 'x', train: true })
    await api.revertModel({ version: before.learning.version })
    expect((await api.getModelInfo()).learning.version).toBe(before.learning.version)
    expect((await api.getFinding(target.id)).ml_score).toBe(target.ml_score)
  })
})

describe('reports', () => {
  it('serves an HTML report and a PDF', async () => {
    const html = await api.getReportHtml('scan-002')
    expect(html).toContain('acme-shop-v1.5.zip')
    const pdf = await api.getReportBlob('scan-002', 'pdf')
    expect(new TextDecoder().decode(await pdf.arrayBuffer()).startsWith('%PDF-1.4')).toBe(true)
  })
})
