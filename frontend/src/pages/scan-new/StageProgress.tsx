import { Icon } from '@/components/Icon'
import type { ScanProgress, SocketMode } from '@/hooks/useScanSocket'
import { fmtNumber } from '@/lib/format'
import { stageMeta, stageOrder } from '@/lib/labels'
import type { Scan, ScanStage } from '@/types/contract'

type StageState = 'done' | 'running' | 'waiting' | 'failed'

const stateStyle: Record<StageState, { label: string; chip: string; bar: string }> = {
  done: { label: 'DONE', chip: 'bg-primary/10 text-primary', bar: 'bg-primary' },
  running: { label: 'RUNNING', chip: 'bg-primary-container text-on-primary-container', bar: 'bg-primary' },
  waiting: { label: 'WAITING', chip: 'bg-surface-container-high text-on-surface-variant', bar: 'bg-outline' },
  failed: { label: 'STOPPED', chip: 'bg-error-container/40 text-error', bar: 'bg-error' },
}

const modeLabel: Record<SocketMode, { label: string; className: string }> = {
  idle: { label: 'Idle', className: 'text-on-surface-variant' },
  connecting: { label: 'Connecting…', className: 'text-on-surface-variant' },
  live: { label: 'Live', className: 'text-primary' },
  reconnecting: { label: 'Reconnecting…', className: 'text-tertiary' },
  polling: { label: 'Socket lost: polling every 2 s', className: 'text-tertiary' },
  closed: { label: 'Finished', className: 'text-on-surface-variant' },
}

export function StageProgress({
  scan,
  progress,
  mode,
}: {
  scan: Scan
  progress: ScanProgress | null
  mode: SocketMode
}) {
  const current = progress?.stage ?? scan.stage
  const normalizedCurrent = (current as string) === 'ingest' ? 'unpack' : (current as string) === 'aggregation' ? 'ranking' : current
  const currentIdx = stageOrder.indexOf(normalizedCurrent as ScanStage)
  const finished = scan.status === 'done' || scan.status === 'completed'
  const stopped = scan.status === 'failed' || scan.status === 'partial'

  return (
    <div className="flex flex-col gap-space-sm">
      <div className="flex items-center justify-between font-label-code-sm text-label-code-sm">
        <span className="uppercase text-on-surface-variant">Pipeline</span>
        <span className={`flex items-center gap-1 ${modeLabel[mode].className}`} aria-live="polite">
          <Icon name={mode === 'polling' ? 'sync' : mode === 'live' ? 'sensors' : 'wifi_tethering'} />
          {modeLabel[mode].label}
        </span>
      </div>
      <ol className="grid grid-cols-1 gap-space-sm md:grid-cols-2 2xl:grid-cols-4">
        {stageOrder.map((stage, i) => {
          const state: StageState =
            finished || i < currentIdx
              ? 'done'
              : i === currentIdx
                ? stopped
                  ? 'failed'
                  : scan.status === 'queued'
                    ? 'waiting'
                    : 'running'
                : 'waiting'
          const p = progress?.stage === stage ? progress : null
          const pct = state === 'done' ? 100 : p && p.total ? Math.round((p.done / p.total) * 100) : 0
          const s = stateStyle[state]
          return (
            <li
              key={stage}
              className={`flex flex-col gap-space-sm rounded-lg p-space-md ${state === 'running' ? 'bg-surface-container-high' : 'bg-surface-container'}`}
            >
              <div className="flex items-center justify-between gap-space-sm">
                <span className="flex items-center gap-space-sm font-label-code-lg text-label-code-lg text-on-surface">
                  <Icon
                    name={
                      state === 'done' ? 'check_circle' : state === 'running' ? 'progress_activity' : 'hourglass_empty'
                    }
                    className={
                      state === 'running'
                        ? 'animate-spin text-primary'
                        : state === 'done'
                          ? 'text-primary'
                          : 'text-outline'
                    }
                  />
                  {i + 1}. {stageMeta[stage].label}
                </span>
                <span className={`rounded px-1.5 py-0.5 font-label-code-sm text-label-code-sm ${s.chip}`}>
                  {s.label}
                </span>
              </div>
              <div
                className="h-1.5 rounded-full bg-surface-container-highest"
                role="progressbar"
                aria-label={`${stageMeta[stage].label} progress`}
                aria-valuemin={0}
                aria-valuemax={100}
                aria-valuenow={pct}
              >
                <div className={`h-1.5 rounded-full transition-all ${s.bar}`} style={{ width: `${pct}%` }} />
              </div>
              <div className="flex justify-between font-label-code-sm text-label-code-sm text-on-surface-variant">
                <span>
                  {p ? `${fmtNumber(p.done)} / ${fmtNumber(p.total)} ${stageMeta[stage].unit}` : stageMeta[stage].unit}
                </span>
                <span>{pct}%</span>
              </div>
            </li>
          )
        })}
      </ol>
    </div>
  )
}
