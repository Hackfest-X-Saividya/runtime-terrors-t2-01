import { useQueryClient } from '@tanstack/react-query'
import { useEffect, useState } from 'react'
import { useSearchParams } from 'react-router-dom'
import { keys, useCreateScan, useFindings, useScan } from '@/api/hooks'
import { Tag } from '@/components/Badges'
import { Button } from '@/components/Button'
import { Card } from '@/components/Card'
import { Icon } from '@/components/Icon'
import { PageHeader } from '@/components/PageHeader'
import { ErrorState, SkeletonRows } from '@/components/States'
import { useScanSocket } from '@/hooks/useScanSocket'
import { useToast } from '@/hooks/useToast'
import { fmtDuration } from '@/lib/format'
import { stageMeta, stageOrder } from '@/lib/labels'
import { isFinished } from '@/lib/scans'
import type { CreateScanInput, Finding } from '@/types/contract'
import { LiveFindings } from './LiveFindings'
import { ScanSummary } from './ScanSummary'
import { SourceForm } from './SourceForm'
import { StageProgress } from './StageProgress'

function useNow(active: boolean) {
  const [now, setNow] = useState(() => Date.now())
  useEffect(() => {
    if (!active) return
    const t = setInterval(() => setNow(Date.now()), 1000)
    return () => clearInterval(t)
  }, [active])
  return now
}

export default function NewScanPage() {
  const [params, setParams] = useSearchParams()
  const scanId = params.get('scan') ?? undefined
  const qc = useQueryClient()
  const toast = useToast()
  const create = useCreateScan()

  const socket = useScanSocket(scanId)
  const polling = socket.mode === 'polling'
  const scanQ = useScan(scanId, polling ? 2000 : undefined)
  const scan = socket.result ?? scanQ.data
  const finished = !!scan && isFinished(scan)
  // REST fallback for the feed: while polling, and once finished (covers anything the socket missed).
  const listQ = useFindings(
    polling || finished ? scanId : undefined,
    { limit: 100, sort: '-risk_score' },
    polling && !finished ? 2000 : undefined,
  )
  const now = useNow(!!scan && !finished)

  useEffect(() => {
    if (!socket.result) return
    qc.setQueryData(keys.scan(socket.result.id), socket.result)
    qc.invalidateQueries({ queryKey: keys.scans })
    qc.invalidateQueries({ queryKey: keys.summary })
    qc.invalidateQueries({ queryKey: keys.modelInfo })
  }, [socket.result, qc])

  const start = (input: CreateScanInput) =>
    create.mutate(input, {
      onSuccess: ({ scan_id }) => {
        setParams({ scan: scan_id })
        toast('success', `Scan ${scan_id} started.`)
      },
      onError: (e) => toast('error', e.message),
    })

  const byId = new Map<string, Finding>()
  for (const f of socket.findings) byId.set(f.id, f)
  for (const f of listQ.data?.items ?? []) byId.set(f.id, f)
  const feed = [...byId.values()]
  const progressScan =
    scan && socket.progress && !finished ? { ...scan, stage: socket.progress.stage, status: 'running' as const } : scan

  return (
    <>
      <PageHeader
        crumbs={[{ label: 'Scans', to: '/' }, { label: 'New static and ML run' }]}
        title="New Scan"
        description="Upload a project, point at a Git repository or paste code. The rule engine and the ML model run side by side."
        actions={
          scanId && (
            <Button icon="restart_alt" onClick={() => setParams({})}>
              Start another scan
            </Button>
          )
        }
      />

      <div className="mb-space-lg grid grid-cols-1 gap-space-lg xl:grid-cols-12">
        <Card className="xl:col-span-7" title="Source" subtitle="Python first. Max 50 MB per archive.">
          <SourceForm
            busy={create.isPending || (!!scan && !finished)}
            busyLabel={create.isPending ? 'Starting…' : 'Scan running…'}
            onStart={start}
          />
        </Card>

        <Card className="xl:col-span-5" label="Scan status">
          {!scanId && (
            <div className="flex flex-col gap-space-md">
              <h2 className="font-headline-md text-headline-md text-on-surface">What happens next</h2>
              <ol className="flex flex-col gap-space-sm">
                {stageOrder.map((s, i) => (
                  <li key={s} className="flex gap-space-sm rounded-lg bg-surface-container p-space-sm">
                    <span className="flex h-6 w-6 shrink-0 items-center justify-center rounded-full bg-surface-container-highest font-label-code-sm text-label-code-sm text-primary">
                      {i + 1}
                    </span>
                    <span className="font-body-md text-body-md text-on-surface-variant">
                      <b className="text-on-surface">{stageMeta[s].label}.</b>{' '}
                      {
                        {
                          unpack: 'Unpack the archive and index Python files. Nothing is executed.',
                          rules: 'Bandit and Semgrep rules, each hit mapped to a CWE and OWASP 2025 category.',
                          ml: 'The model scores every function; findings only it catches are marked Novel.',
                          ranking: 'Merge both detectors into ranked findings with a 0-10 risk score and a fix.',
                        }[s]
                      }
                    </span>
                  </li>
                ))}
              </ol>
            </div>
          )}
          {scanId && scanQ.isError && !scan && <ErrorState error={scanQ.error} onRetry={() => scanQ.refetch()} />}
          {scanId && !scan && !scanQ.isError && <SkeletonRows rows={4} />}
          {scan && !finished && (
            <div className="flex flex-col gap-space-md">
              <p className="font-label-code-sm text-label-code-sm uppercase text-primary">Scan in progress</p>
              <h2 className="break-all font-headline-md text-headline-md text-on-surface">{scan.name}</h2>
              <div className="flex flex-wrap gap-space-sm">
                <Tag>{scan.id}</Tag>
                <Tag>
                  <Icon name="timer" /> {fmtDuration(scan.started_at, new Date(now).toISOString())} elapsed
                </Tag>
                <Tag>model {scan.model_version}</Tag>
              </div>
              <p className="font-body-md text-body-md text-on-surface-variant">
                {feed.length} findings so far. You can leave this page; the scan keeps running and appears on the
                dashboard.
              </p>
            </div>
          )}
          {scan && finished && <ScanSummary scan={scan} novel={feed.filter((f) => f.source === 'ml').length} />}
        </Card>
      </div>

      {scan && progressScan && (
        <>
          <Card
            title="Live execution"
            subtitle="Stage progress streamed over the scan WebSocket"
            className="mb-space-lg"
          >
            <StageProgress scan={progressScan} progress={finished ? null : socket.progress} mode={socket.mode} />
          </Card>
          <Card title="Live findings" subtitle="Newest first">
            <LiveFindings findings={feed} waiting={!finished} />
          </Card>
        </>
      )}
    </>
  )
}
