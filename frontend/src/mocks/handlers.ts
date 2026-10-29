import { http, HttpResponse, type HttpResponseResolver } from 'msw'
import type {
  FindingSource,
  FindingSort,
  FindingStatus,
  FindingsQuery,
  RevertModelInput,
  Severity,
  UpdateFindingInput,
} from '@/types/contract'
import * as db from './db'
import { buildReportHtml, buildReportPdf } from './report'

/** Turns MockHttpError into a JSON error response like FastAPI's {detail}. */
const safe =
  (resolver: HttpResponseResolver): HttpResponseResolver =>
  async (info) => {
    try {
      return await resolver(info)
    } catch (e) {
      if (e instanceof db.MockHttpError) return HttpResponse.json({ detail: e.message }, { status: e.status })
      throw e
    }
  }

const param = (v: string | readonly string[] | undefined) => (typeof v === 'string' ? v : '')

function findingsQuery(url: URL): FindingsQuery {
  const q = url.searchParams
  const str = (k: string) => q.get(k) || undefined
  const num = (k: string) => (q.get(k) ? Number(q.get(k)) : undefined)
  return {
    severity: str('severity') as Severity | undefined,
    owasp: str('owasp'),
    source: str('source') as FindingSource | undefined,
    status: str('status') as FindingStatus | undefined,
    sort: str('sort') as FindingSort | undefined,
    limit: num('limit'),
    offset: num('offset'),
    q: str('q'),
    include_suppressed: q.get('include_suppressed') === 'true',
  }
}

export const handlers = [
  http.get('*/health', () => HttpResponse.json({ ok: true })),

  http.get('*/api/stats/summary', () => HttpResponse.json(db.summary())),

  http.get('*/api/scans', () => HttpResponse.json(db.listScans())),

  http.post(
    '*/api/scans',
    safe(async ({ request }) => {
      if (request.headers.get('Content-Type')?.includes('application/json')) {
        const body = (await request.json()) as {
          git_url?: string
          code?: string
          filename?: string
          rescan_of?: string
        }
        if (body.rescan_of)
          return HttpResponse.json(db.createScan({ kind: 'rescan', rescan_of: body.rescan_of }), { status: 201 })
        if (body.git_url)
          return HttpResponse.json(db.createScan({ kind: 'git', git_url: body.git_url }), { status: 201 })
        if (body.code) {
          return HttpResponse.json(db.createScan({ kind: 'paste', code: body.code, filename: body.filename ?? '' }), {
            status: 201,
          })
        }
        throw new db.MockHttpError(422, 'Send a zip file, git_url, code or rescan_of')
      }
      const file = (await request.formData()).get('file')
      if (!(file instanceof File)) throw new db.MockHttpError(422, 'file is required')
      return HttpResponse.json(db.createScan({ kind: 'zip', name: file.name }), { status: 201 })
    }),
  ),

  http.get(
    '*/api/scans/:id',
    safe(({ params }) => HttpResponse.json(db.getScan(param(params.id)))),
  ),

  http.get(
    '*/api/scans/:id/findings',
    safe(({ params, request }) =>
      HttpResponse.json(db.listFindings(param(params.id), findingsQuery(new URL(request.url)))),
    ),
  ),

  http.get(
    '*/api/scans/:id/diff',
    safe(({ params }) => HttpResponse.json(db.diff(param(params.id)))),
  ),

  http.get(
    '*/api/scans/:id/report',
    safe(({ params, request }) => {
      const scan = db.getScan(param(params.id))
      const findings = db.scanFindings(scan.id)
      if (new URL(request.url).searchParams.get('format') === 'pdf') {
        return new HttpResponse(buildReportPdf(scan, findings), {
          headers: {
            'Content-Type': 'application/pdf',
            'Content-Disposition': `attachment; filename="zerosentinel-${scan.id}.pdf"`,
          },
        })
      }
      return HttpResponse.html(buildReportHtml(scan, findings))
    }),
  ),

  http.get(
    '*/api/findings/:id',
    safe(({ params }) => HttpResponse.json(db.getFinding(param(params.id)))),
  ),

  http.patch(
    '*/api/findings/:id',
    safe(async ({ params, request }) =>
      HttpResponse.json(db.updateFinding(param(params.id), (await request.json()) as UpdateFindingInput)),
    ),
  ),

  http.get('*/api/model/info', () => HttpResponse.json(db.modelInfo())),

  http.post(
    '*/api/model/revert',
    safe(async ({ request }) =>
      HttpResponse.json(db.revertModel(((await request.json()) as RevertModelInput).version)),
    ),
  ),
]
