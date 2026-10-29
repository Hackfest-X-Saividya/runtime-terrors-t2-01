import { useState } from 'react'
import { Navigate, useNavigate, useParams } from 'react-router-dom'
import { api, getReportUrl } from '@/api/client'
import { useReportHtml, useScan, useScans, useSummary } from '@/api/hooks'
import { ScanStatusPill, SeverityBadge } from '@/components/Badges'
import { Button } from '@/components/Button'
import { Card } from '@/components/Card'
import { Icon } from '@/components/Icon'
import { PageHeader } from '@/components/PageHeader'
import { RiskScore } from '@/components/RiskScore'
import { EmptyState, ErrorState, Skeleton, SkeletonRows } from '@/components/States'
import { useToast } from '@/hooks/useToast'
import { fmtDateTime } from '@/lib/format'
import { mockTransport } from '@/lib/runtime'
import { riskLabel, riskTextClass, severityOrder } from '@/lib/labels'
import type { ReportFormat } from '@/types/contract'

export default function ReportPage() {
  const { scanId } = useParams()
  const navigate = useNavigate()
  const toast = useToast()
  const summary = useSummary()
  const scans = useScans()
  const scan = useScan(scanId)
  const report = useReportHtml(scanId)
  const [downloading, setDownloading] = useState<ReportFormat | null>(null)

  if (!scanId) {
    if (summary.data) return <Navigate replace to={`/reports/${summary.data.last_scan.id}`} />
    return (
      <>
        <PageHeader title="Risk reports" />
        {summary.isError ? <ErrorState error={summary.error} onRetry={() => summary.refetch()} /> : <SkeletonRows />}
      </>
    )
  }

  const download = async (format: ReportFormat) => {
    setDownloading(format)
    try {
      const blob = await api.getReportBlob(scanId, format)
      const url = URL.createObjectURL(blob)
      const a = document.createElement('a')
      a.href = url
      a.download = `zerosentinel-${scanId}.${format}`
      a.click()
      setTimeout(() => URL.revokeObjectURL(url), 1000)
      toast('success', `${format.toUpperCase()} report downloaded.`)
    } catch (e) {
      toast('error', e instanceof Error ? e.message : 'Download failed.')
    } finally {
      setDownloading(null)
    }
  }

  const s = scan.data
  const c = s?.counts_by_severity

  return (
    <>
      <PageHeader
        crumbs={[{ label: 'Reports', to: '/reports' }, { label: s?.name ?? scanId }]}
        title="Risk reports"
        description="Preview the scan's risk report and download it as PDF or HTML for the audit trail."
        actions={
          <>
            <Button icon="code" disabled={!!downloading || !s} onClick={() => download('html')}>
              {downloading === 'html' ? 'Preparing…' : 'HTML'}
            </Button>
            <Button
              variant="primary"
              icon="picture_as_pdf"
              disabled={!!downloading || !s}
              onClick={() => download('pdf')}
            >
              {downloading === 'pdf' ? 'Preparing…' : 'Download PDF'}
            </Button>
          </>
        }
      />

      <section
        aria-label="Report summary"
        className="mb-space-lg grid grid-cols-1 gap-space-md rounded-xl bg-surface-container-low p-space-md shadow-sm lg:grid-cols-12"
      >
        <div className="flex flex-col gap-space-sm lg:col-span-5">
          <label
            htmlFor="report-scan"
            className="flex items-center gap-1 font-label-code-sm text-label-code-sm uppercase text-on-surface-variant"
          >
            <Icon name="inventory_2" className="text-primary" /> Scan
          </label>
          {scans.data ? (
            <select
              id="report-scan"
              value={scanId}
              onChange={(e) => navigate(`/reports/${e.target.value}`)}
              className="rounded-lg bg-surface-container px-space-sm py-2 font-label-code-md text-label-code-md text-on-surface"
            >
              {scans.data.map((x) => (
                <option key={x.id} value={x.id}>
                  {x.name} · {x.id} · {fmtDateTime(x.started_at)}
                </option>
              ))}
            </select>
          ) : (
            <Skeleton className="h-9 w-full" />
          )}
          {s && (
            <span className="flex flex-wrap items-center gap-space-sm font-label-code-sm text-label-code-sm text-on-surface-variant">
              <ScanStatusPill status={s.status} /> {s.source_type} · model {s.model_version}
            </span>
          )}
        </div>
        <div className="flex flex-col gap-1 lg:col-span-3">
          <span className="font-label-code-sm text-label-code-sm uppercase text-on-surface-variant">
            Aggregated risk
          </span>
          {s ? (
            <>
              <RiskScore score={s.risk_score} size="lg" />
              <span className={`font-label-code-sm text-label-code-sm uppercase ${riskTextClass(s.risk_score)}`}>
                {riskLabel(s.risk_score)}
              </span>
            </>
          ) : (
            <Skeleton className="h-10 w-28" />
          )}
        </div>
        <div className="flex flex-col gap-space-sm lg:col-span-4">
          <span className="font-label-code-sm text-label-code-sm uppercase text-on-surface-variant">
            Triage breakdown
          </span>
          {c ? (
            <div className="flex flex-wrap gap-space-sm">
              {severityOrder.map((k) => (
                <span key={k} className="flex items-center gap-1">
                  <SeverityBadge severity={k} />
                  <span className="font-mono text-label-code-lg text-on-surface">{c[k]}</span>
                </span>
              ))}
            </div>
          ) : (
            <Skeleton className="h-6 w-full" />
          )}
        </div>
      </section>

      <Card
        title="Report preview"
        subtitle={mockTransport() ? 'Sample data: generated in the browser in mock mode' : getReportUrl(scanId, 'html')}
        action={
          <span className="rounded bg-surface-container-high px-2 py-0.5 font-label-code-sm text-label-code-sm text-on-surface-variant">
            Sandboxed, scripts disabled
          </span>
        }
      >
        {scan.isError ? (
          <ErrorState error={scan.error} onRetry={() => scan.refetch()} />
        ) : report.isError ? (
          <ErrorState title="Couldn't load the report" error={report.error} onRetry={() => report.refetch()} />
        ) : report.data ? (
          <iframe
            title={`Risk report for ${s?.name ?? scanId}`}
            sandbox=""
            srcDoc={report.data}
            className="h-[75vh] min-h-[32rem] w-full rounded-lg bg-inverse-surface"
          />
        ) : report.isPending ? (
          <Skeleton className="h-[75vh] w-full rounded-lg" />
        ) : (
          <EmptyState icon="description" title="No report" />
        )}
      </Card>
    </>
  )
}
