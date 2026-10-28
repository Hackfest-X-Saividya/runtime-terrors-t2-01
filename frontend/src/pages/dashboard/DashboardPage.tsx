import { Link, useNavigate } from 'react-router-dom'
import { useModelInfo, useScans, useSummary } from '@/api/hooks'
import { NovelBadge, SeverityBadge, Tag } from '@/components/Badges'
import { ButtonLink } from '@/components/Button'
import { Card } from '@/components/Card'
import { OwaspBars } from '@/components/charts/OwaspBars'
import { SeverityDonut } from '@/components/charts/SeverityDonut'
import { Icon } from '@/components/Icon'
import { KpiCard } from '@/components/KpiCard'
import { PageHeader } from '@/components/PageHeader'
import { EmptyState, ErrorState, Skeleton, SkeletonRows } from '@/components/States'
import { fmtNumber, fmtRelative } from '@/lib/format'
import { riskLabel, riskTextClass } from '@/lib/labels'
import { previousScanOf } from '@/lib/scans'
import { RecentScans } from './RecentScans'
import { TopRisks } from './TopRisks'

export default function DashboardPage() {
  const summary = useSummary()
  const scans = useScans()
  const model = useModelInfo()
  const navigate = useNavigate()
  const s = summary.data
  const last = s?.last_scan
  const prev = last && scans.data ? previousScanOf(last, scans.data) : null
  const delta = last && prev ? last.risk_score - prev.risk_score : null

  if (summary.isError) {
    return (
      <>
        <PageHeader title="Security Posture Overview" />
        <ErrorState error={summary.error} onRetry={() => summary.refetch()} />
      </>
    )
  }

  return (
    <>
      <PageHeader
        title="Security Posture Overview"
        description="Rule engine and ML findings across every scan, ranked by risk."
        meta={
          last ? (
            <>
              <Tag className="text-primary">
                <Icon name="inventory_2" />
                {last.name}
              </Tag>
              <Tag>
                <span aria-hidden="true" className="h-1.5 w-1.5 rounded-full bg-primary" />
                Last scanned {fmtRelative(last.started_at)}
              </Tag>
              <Tag>model {last.model_version}</Tag>
            </>
          ) : (
            <Skeleton className="h-5 w-64" />
          )
        }
        actions={
          last && (
            <>
              <ButtonLink to={`/reports/${last.id}`} icon="download">
                Risk report
              </ButtonLink>
              <ButtonLink to={`/scans/${last.id}/findings`} icon="shield_with_house">
                Latest findings
              </ButtonLink>
            </>
          )
        }
      />

      <section aria-label="Key metrics" className="mb-space-lg grid grid-cols-2 gap-4 md:grid-cols-3 2xl:grid-cols-6">
        <KpiCard
          label="Total findings"
          icon="analytics"
          loading={!s}
          value={s && fmtNumber(s.total_findings)}
          footer={s && `across ${s.total_scans} scans`}
        />
        <KpiCard
          label="Critical findings"
          icon="crisis_alert"
          loading={!s}
          badge={s && <SeverityBadge severity="critical" />}
          value={s?.by_severity.critical}
          valueClassName="text-error"
          footer={s && `${s.by_source.rule + s.by_source.both} with rule evidence`}
        />
        <KpiCard
          label="High severity"
          icon="warning"
          loading={!s}
          badge={s && <SeverityBadge severity="high" />}
          value={s?.by_severity.high}
          valueClassName="text-tertiary-container"
          footer={s && `${s.by_severity.medium} medium · ${s.by_severity.low} low`}
        />
        <KpiCard
          label="Novel ML findings"
          icon="psychology"
          loading={!s}
          badge={<NovelBadge label="Novel ML" />}
          value={s?.novel_count}
          valueClassName="text-primary"
          footer="Zero-day candidates: ML only"
        />
        <KpiCard
          label="Risk score index"
          icon="speed"
          loading={!last}
          badge={
            last && (
              <span
                className={`rounded bg-surface-container-high px-2 py-0.5 font-label-code-sm text-label-code-sm uppercase ${riskTextClass(last.risk_score)}`}
              >
                {riskLabel(last.risk_score)}
              </span>
            )
          }
          value={
            last && (
              <>
                <span className={riskTextClass(last.risk_score)}>{last.risk_score.toFixed(1)}</span>
                <span className="font-label-code-lg text-label-code-lg text-on-surface-variant"> / 10</span>
              </>
            )
          }
          footer={
            delta !== null && (
              <span className={delta > 0 ? 'text-error' : 'text-primary'}>
                {delta > 0 ? '+' : ''}
                {delta.toFixed(1)} vs previous scan
              </span>
            )
          }
        />
        <KpiCard
          label="False positives suppressed"
          icon="filter_alt_off"
          loading={!model.data}
          value={model.data?.learning.suppressed_count}
          valueClassName="text-secondary"
          footer={
            model.data && `${model.data.learning.feedback_count} training events · ${model.data.learning.version}`
          }
        />
      </section>

      <div className="mb-space-lg grid grid-cols-1 gap-space-lg lg:grid-cols-12">
        <Card
          title="Findings by severity"
          subtitle="Open and triaged findings, excluding suppressed"
          icon="pie_chart"
          className="lg:col-span-5"
        >
          {s ? <SeverityDonut counts={s.by_severity} /> : <Skeleton className="mx-auto h-56 w-56 rounded-full" />}
        </Card>
        <Card
          title="Findings by OWASP Top 10 2025"
          subtitle="Each rule and ML hit is mapped to a category"
          className="lg:col-span-7"
          action={s && <Tag>Total mapped: {fmtNumber(Object.values(s.by_owasp).reduce((a, b) => a + b, 0))}</Tag>}
        >
          {s ? (
            <OwaspBars
              counts={s.by_owasp}
              onSelect={(category) =>
                last && navigate(`/scans/${last.id}/findings?owasp=${encodeURIComponent(category)}`)
              }
            />
          ) : (
            <SkeletonRows rows={6} />
          )}
        </Card>
      </div>

      <div className="grid grid-cols-1 gap-space-lg xl:grid-cols-12">
        <Card
          title="Recent scans"
          subtitle="Uploads, Git repositories and pasted code"
          className="xl:col-span-7"
          padding="none"
          action={
            <Link
              to="/scan/new"
              className="flex items-center gap-1 rounded font-label-code-md text-label-code-md text-primary hover:underline"
            >
              New scan <Icon name="arrow_forward" />
            </Link>
          }
        >
          {scans.isError ? (
            <div className="p-space-lg">
              <ErrorState error={scans.error} onRetry={() => scans.refetch()} />
            </div>
          ) : scans.data ? (
            scans.data.length ? (
              <RecentScans scans={scans.data.slice(0, 6)} />
            ) : (
              <EmptyState icon="radar" title="No scans yet">
                Start one from New Scan.
              </EmptyState>
            )
          ) : (
            <div className="px-space-lg pb-space-lg">
              <SkeletonRows />
            </div>
          )}
        </Card>
        <Card
          title="Top risks"
          subtitle="Highest-scoring open findings"
          icon="local_fire_department"
          className="xl:col-span-5"
        >
          {s ? (
            s.top_findings.length ? (
              <TopRisks findings={s.top_findings} />
            ) : (
              <EmptyState icon="verified_user" title="No open findings" />
            )
          ) : (
            <SkeletonRows />
          )}
        </Card>
      </div>
    </>
  )
}
