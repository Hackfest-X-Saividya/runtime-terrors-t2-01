import { http, HttpResponse } from 'msw'
import { setupServer } from 'msw/node'
import { afterAll, afterEach, beforeAll, describe, expect, it } from 'vitest'
import { API_URL } from '@/lib/env'
import { api, ApiError, getReportUrl, scanSocketUrl, toQuery } from './client'

const server = setupServer()
beforeAll(() => server.listen({ onUnhandledRequest: 'error' }))
afterEach(() => server.resetHandlers())
afterAll(() => server.close())

describe('client helpers', () => {
  it('toQuery drops empty values', () => {
    expect(toQuery({ a: 'x', b: undefined, c: '', d: false, e: 0, f: true })).toBe('?a=x&e=0&f=true')
    expect(toQuery({})).toBe('')
  })

  it('builds report and socket URLs from VITE_API_URL', () => {
    expect(getReportUrl('scan-1', 'pdf')).toBe(`${API_URL}/api/scans/scan-1/report?format=pdf`)
    expect(scanSocketUrl('scan-1')).toBe(`${API_URL.replace(/^http/, 'ws')}/ws/scans/scan-1`)
  })
})

describe('ApiError', () => {
  it('carries status and FastAPI detail', async () => {
    server.use(http.get('*/api/scans/:id', () => HttpResponse.json({ detail: 'scan not found' }, { status: 404 })))
    const err = await api.getScan('nope').catch((e: unknown) => e)
    expect(err).toBeInstanceOf(ApiError)
    expect((err as ApiError).status).toBe(404)
    expect((err as ApiError).detail).toBe('scan not found')
  })

  it('uses status 0 when the API is unreachable', async () => {
    server.use(http.get('*/health', () => HttpResponse.error()))
    const err = await api.health().catch((e: unknown) => e)
    expect((err as ApiError).status).toBe(0)
  })

  it('sends the feedback body on PATCH', async () => {
    let body: unknown
    server.use(
      http.patch('*/api/findings/:id', async ({ request }) => {
        body = await request.json()
        return HttpResponse.json({})
      }),
    )
    await api.updateFinding('f1', { status: 'false_positive', reason: 'test', note: 'n', train: true })
    expect(body).toEqual({ status: 'false_positive', reason: 'test', note: 'n', train: true })
  })

  it('normalizes findings response from raw array or envelope', async () => {
    const mockFinding = { id: 'f1', title: 'Test', severity: 'high', risk_score: 8.0, status: 'open' }

    // Array response
    server.use(
      http.get('*/api/scans/:id/findings', () => HttpResponse.json([mockFinding])),
    )
    const resArray = await api.listFindings('scan-1')
    expect(resArray.items).toHaveLength(1)
    expect(resArray.total).toBe(1)
    expect(resArray.items[0].id).toBe('f1')

    // Envelope response
    server.use(
      http.get('*/api/scans/:id/findings', () =>
        HttpResponse.json({ items: [mockFinding, { ...mockFinding, id: 'f2' }], total: 10 }),
      ),
    )
    const resEnvelope = await api.listFindings('scan-1', { limit: 2, offset: 0 })
    expect(resEnvelope.items).toHaveLength(2)
    expect(resEnvelope.total).toBe(10)
  })
})
