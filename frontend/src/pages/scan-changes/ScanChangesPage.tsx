import type { ReactNode } from 'react'
import { Link, useParams } from 'react-router-dom'
import { useScan, useScanDiff, useScans } from '@/api/hooks'
import { FindingStatusPill, NovelBadge, ScoreChange, SeverityBadge, Tag } from '@/components/Badges'
import { Button, ButtonLink } from '@/components/Button'
import { Card } from '@/components/Card'
import { Icon } from '@/components/Icon'
import { KpiCard } from '@/components/KpiCard'
import { PageHeader } from '@/components/PageHeader'
import { EmptyState, ErrorState, SkeletonRows } from '@/components/States'
import { useRescan } from '@/hooks/useRescan'
import { fmtDateTime } from '@/lib/format'
import { isNovel } from '@/lib/labels'
import { isFinished } from '@/lib/scans'
import { sinkLine } from '@/lib/snippet'
import type { Finding } from '@/types/contract'

function ChangeRow({ f, right, muted }: { f: Finding; right?: ReactNode; muted?: boolean }) {
  return (
    <li className="flex flex-wrap items-start gap-space-md rounded-xl bg-surface-container-low p-space-md shadow-sm">
      <SeverityBadge severity={f.severity} score={f.risk_score} muted={muted} />
      <div className="flex min-w-0 flex-1 flex-col gap-1">
        <div className="flex flex-wrap items-center gap-space-sm">
          <Link
            to={`/findings/${f.id}`}
            className="font-headline-sm text-headline-sm text-on-surface hover:text-primary"
          >
            {f.title}
          </Link>
          <Tag>{f.cwe_id}</Tag>
          {isNovel(f) && <NovelBadge label="Novel ML" />}
        </div>
        <code className="truncate font-label-code-md text-label-code-md text-on-surface-variant">
          {sinkLine(f.snippet)}
        </code>
        <span className="flex items-center gap-1 font-label-code-md text-label-code-md text-secondary">
          <Icon name="description" /> {f.file_path}:{f.start_line}
          {f.feedback?.reason && <span className="text-on-surface-variant"> · Reason: {f.feedback.reason}</span>}
        </span>
      </div>
      {right && <div className="flex flex-col items-end gap-1">{right}</div>}
    </li>
  )
}

function Group({
  dot,
  title,
  badge,
  hint,
  children,
}: {
  dot: string
  title: string
  badge: ReactNode
  hint?: string
  children: ReactNode
}) {
  return (
    <section className="mb-space-xl" aria-label={title}>
      <header className="mb-space-md flex flex-wrap items-center gap-space-sm">
        <span aria-hidden="true" className={`h-3 w-3 rounded-full ${dot}`} />
        <h2 className="font-headline-md text-headline-md text-on-surface">{title}</h2>
        {badge}
        {hint && <span className="ml-auto font-label-code-md text-label-code-md text-on-surface-variant">{hint}</span>}
      </header>
      {children}
    </section>
  )
}

export default function ScanChangesPage() {
  const { scanId } = useParams()
  const scan = useScan(scanId)
  const diff = useScanDiff(scanId)
  const scans = useScans()
  const { rescan, pending } = useRescan()

  const s = scan.data
  const d = diff.data
  const prev = d?.previous_scan_id ? scans.data?.find((x) => x.id === d.previous_scan_id) : undefined
  const delta = s && prev ? s.risk_score - prev.risk_score : null
  const newCritical = d?.new.filter((f) => f.severity === 'critical').length ?? 0

  const header = (
    <PageHeader
      crumbs={[
        { label: 'Scans', to: '/' },
        { label: s?.name ?? scanId ?? '', to: `/scans/${scanId}/findings` },
        { label: 'Scan changes' },
      ]}
      title="Scan changes"
      description="What changed since the previous scan of this project: new findings, findings the model learned to suppress, and findings still open."
      actions={
        s && (
          <>
            {prev && (
              <span className="flex items-center gap-space-sm rounded-lg bg-surface-container px-space-sm py-1.5 font-label-code-md text-label-code-md text-on-surface">
                <Icon name="compare_arrows" className="text-primary" />
                Compared with {prev.name} ({fmtDateTime(prev.started_at)})
              </span>
            )}
            <ButtonLink to={`/reports/${s.id}`} icon="download">
              Export
            </ButtonLink>
            <Button
              variant="primary"
              icon="autorenew"
              disabled={pending || !isFinished(s)}
              onClick={() => rescan(s.id)}
            >
              Re-scan
            </Button>
          </>
        )
      }
    />
  )

  if (scan.isError || diff.isError) {
    return (
      <>
        {header}
        <ErrorState
          error={scan.error ?? diff.error}
          onRetry={() => {
            scan.refetch()
            diff.refetch()
          }}
        />
      </>
    )
  }
  if (!d || !s) {
    return (
      <>
        {header}
        <SkeletonRows rows={8} />
      </>
    )
  }
  if (!d.previous_scan_id) {
    return (
      <>
        {header}
        <Card>
          <EmptyState icon="history" title="Nothing to compare yet">
            This is the first scan of {s.name}. Re-scan after fixing or triaging findings to see what changed.
          </EmptyState>
        </Card>
      </>
    )
  }

  const total = d.new.length + d.resolved.length + d.suppressed.length

  return (
    <>
      {header}

      <section aria-label="Change summary" className="mb-space-xl grid grid-cols-2 gap-4 md:grid-cols-3 xl:grid-cols-5">
        <KpiCard label="Total changes" icon="tune" value={total} footer="new + resolved + suppressed" />
        <KpiCard
          label="New findings"
          icon="notifications_active"
          value={`+${d.new.length}`}
          valueClassName="text-error"
          footer={
            newCritical ? (
              <span className="text-error">{newCritical} new critical: release blocker</span>
            ) : (
              'No new critical findings'
            )
          }
        />
        <KpiCard
          label="Resolved"
          icon="task_alt"
          value={`−${d.resolved.length}`}
          valueClassName="text-primary"
          footer="Gone from this scan"
        />
        <KpiCard
          label="Suppressed by feedback"
          icon="model_training"
          value={d.suppressed.length}
          valueClassName="text-secondary"
          footer={`ML below threshold · model ${s.model_version}`}
        />
        <KpiCard
          label="Net risk delta"
          icon="trending_down"
          value={delta === null || typeof delta !== 'number' ? '–' : `${delta > 0 ? '+' : ''}${delta.toFixed(1)}`}
          valueClassName={delta !== null && delta > 0 ? 'text-error' : 'text-primary'}
          footer={prev && typeof prev.risk_score === 'number' && typeof s.risk_score === 'number' ? `${prev.risk_score.toFixed(1)} → ${s.risk_score.toFixed(1)}` : undefined}
        />
      </section>

      <Group
        dot="bg-error"
        title="New findings"
        badge={
          <span className="rounded bg-error-container px-2 py-0.5 font-label-code-sm text-label-code-sm text-on-error-container">
            {d.new.length} unseen in baseline
          </span>
        }
        hint="Highest risk first"
      >
        {d.new.length ? (
          <ul className="flex flex-col gap-space-sm">
            {[...d.new]
              .sort((a, b) => b.risk_score - a.risk_score)
              .map((f) => (
                <ChangeRow
                  key={f.id}
                  f={f}
                  right={
                    <span className="rounded bg-error-container/40 px-2 py-0.5 font-label-code-sm text-label-code-sm text-error">
                      +{typeof f.risk_score === 'number' ? f.risk_score.toFixed(1) : '-'} NEW
                    </span>
                  }
                />
              ))}
          </ul>
        ) : (
          <Card padding="md">
            <EmptyState icon="verified" title="No new findings" />
          </Card>
        )}
      </Group>

      <Group
        dot="bg-secondary"
        title="Suppressed by feedback"
        badge={
          <span className="rounded bg-secondary-container/40 px-2 py-0.5 font-label-code-sm text-label-code-sm text-secondary">
            {d.suppressed.length} downweighted via active learning
          </span>
        }
        hint="Hidden from the findings list; toggle 'Show suppressed' to see them"
      >
        {d.suppressed.length ? (
          <ul className="flex flex-col gap-space-sm">
            {d.suppressed.map((f) => (
              <ChangeRow
                key={f.id}
                f={f}
                muted
                right={
                  typeof f.ml_score_before === 'number' && typeof f.ml_score === 'number' ? (
                    <>
                      <ScoreChange before={f.ml_score_before} after={f.ml_score} />
                      {f.feedback && (
                        <span className="font-label-code-sm text-label-code-sm text-on-surface-variant">
                          learned in {f.feedback.model_version}
                        </span>
                      )}
                    </>
                  ) : undefined
                }
              />
            ))}
          </ul>
        ) : (
          <Card padding="md">
            <EmptyState icon="model_training" title="Nothing suppressed">
              Mark ML false positives with "Use this to improve the model", then re-scan.
            </EmptyState>
          </Card>
        )}
      </Group>

      <Group
        dot="bg-outline"
        title="Still open"
        badge={
          <span className="rounded bg-surface-container-high px-2 py-0.5 font-label-code-sm text-label-code-sm text-on-surface-variant">
            {d.still_open.length} carried over from baseline
          </span>
        }
        hint="Sort: risk descending"
      >
        {d.still_open.length ? (
          <ul className="flex flex-col gap-space-sm">
            {[...d.still_open]
              .sort((a, b) => b.risk_score - a.risk_score)
              .map((f) => (
                <ChangeRow key={f.id} f={f} right={<FindingStatusPill status={f.status} />} />
              ))}
          </ul>
        ) : (
          <Card padding="md">
            <EmptyState icon="done_all" title="Nothing carried over" />
          </Card>
        )}
      </Group>

      {d.resolved.length > 0 && (
        <details className="rounded-xl bg-surface-container-low p-space-md shadow-sm">
          <summary className="cursor-pointer font-headline-sm text-headline-sm text-on-surface">
            Resolved since baseline ({d.resolved.length})
          </summary>
          <ul className="mt-space-md flex flex-col gap-space-sm">
            {d.resolved.map((f) => (
              <ChangeRow key={f.id} f={f} right={<FindingStatusPill status={f.status} />} />
            ))}
          </ul>
        </details>
      )}
    </>
  )
}
