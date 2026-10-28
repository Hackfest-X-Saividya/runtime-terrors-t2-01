import { useEffect } from 'react'
import { useLocation, useNavigate, useParams } from 'react-router-dom'
import { useFinding, useFindings, useScan } from '@/api/hooks'
import { CVSSBadge, CorrelationBadge, NovelBadge, SeverityBadge, SourceBadge, SuppressedBadge, Tag } from '@/components/Badges'
import { Button, ButtonLink } from '@/components/Button'
import { Card } from '@/components/Card'
import { CodeViewer } from '@/components/CodeViewer'
import { Icon } from '@/components/Icon'
import { Markdown } from '@/components/Markdown'
import { PageHeader } from '@/components/PageHeader'
import { RiskGauge } from '@/components/RiskScore'
import { ErrorState, Skeleton, SkeletonRows } from '@/components/States'
import { useFindingFilters } from '@/hooks/useFindingFilters'
import { useToast } from '@/hooks/useToast'
import { fmtPct } from '@/lib/format'
import { isNovel, severityMeta, splitOwasp } from '@/lib/labels'
import { sinkIndex } from '@/lib/snippet'
import type { Finding } from '@/types/contract'
import { TriagePanel } from './TriagePanel'
import { CVSSPanel } from './CVSSPanel'
import { FrameworksPanel } from './FrameworksPanel'
import { CorrelationPanel } from './CorrelationPanel'

function DetectedBy({ f }: { f: Finding }) {
  const rule = f.source !== 'ml'
  const ml = f.source !== 'rule'
  return (
    <Card title="Detected by" action={<SourceBadge source={f.source} ruleId={f.rule_id} />}>
      <div className="grid grid-cols-1 gap-space-sm sm:grid-cols-2">
        <div
          className={`rounded-lg p-space-sm ${rule ? 'bg-surface-container' : 'bg-surface-container-lowest opacity-70'}`}
        >
          <p className="font-label-code-sm text-label-code-sm uppercase text-on-surface-variant">Rule engine</p>
          <p className="font-label-code-lg text-label-code-lg text-on-surface">{f.rule_id ?? 'No rule matched'}</p>
          <p className="font-body-sm text-body-sm text-on-surface-variant">
            {rule ? (f.rule_id?.startsWith('B') ? 'Bandit check' : 'Semgrep rule') : 'Pattern rules missed this one'}
          </p>
        </div>
        <div
          className={`rounded-lg p-space-sm ${ml ? 'bg-surface-container' : 'bg-surface-container-lowest opacity-70'}`}
        >
          <p className="font-label-code-sm text-label-code-sm uppercase text-on-surface-variant">ML model</p>
          <p className="font-label-code-lg text-label-code-lg text-primary">
            {typeof f.ml_score === 'number' ? `${fmtPct(f.ml_score)} vulnerable` : 'Not scored'}
          </p>
          <p className="font-body-sm text-body-sm text-on-surface-variant">
            {typeof f.ml_score_before === 'number'
              ? `Was ${fmtPct(f.ml_score_before)} before feedback`
              : typeof f.ml_score === 'number'
                ? 'Function-level risk score'
                : 'Rule-only finding'}
          </p>
        </div>
      </div>
      {isNovel(f) && (
        <p className="mt-space-sm flex items-center gap-space-sm font-body-md text-body-md text-on-surface-variant">
          <NovelBadge /> Only the ML detector flagged this: a zero-day candidate requiring independent validation.
        </p>
      )}
      {f.source === 'both' && (
        <p className="mt-space-sm font-body-sm text-body-sm text-on-surface-variant">
          Corroborated by both static rule checks and ML model scoring; requires manual triage before confirmation.
        </p>
      )}
    </Card>
  )
}

export default function FindingDetailPage() {
  const { findingId } = useParams()
  const { search } = useLocation()
  const navigate = useNavigate()
  const toast = useToast()
  const finding = useFinding(findingId)
  const f = finding.data
  const scan = useScan(f?.scan_id)
  const { query } = useFindingFilters()
  // Same filters/sort as the table the user came from, for previous/next.
  const siblings = useFindings(f?.scan_id, { ...query, include_suppressed: true, limit: 500, offset: 0 })
  const list = siblings.data?.items ?? []
  const idx = list.findIndex((x) => x.id === findingId)
  const prev = idx > 0 ? list[idx - 1] : null
  const next = idx >= 0 && idx < list.length - 1 ? list[idx + 1] : null

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      const target = e.target as HTMLElement
      if (/^(INPUT|TEXTAREA|SELECT)$/.test(target.tagName)) return
      if (e.key === '[' && prev) navigate(`/findings/${prev.id}${search}`)
      if (e.key === ']' && next) navigate(`/findings/${next.id}${search}`)
    }
    document.addEventListener('keydown', onKey)
    return () => document.removeEventListener('keydown', onKey)
  }, [prev, next, navigate, search])

  if (finding.isError) {
    return (
      <>
        <PageHeader title="Finding" crumbs={[{ label: 'Findings', to: '/findings' }, { label: findingId ?? '' }]} />
        <ErrorState error={finding.error} onRetry={() => finding.refetch()} />
      </>
    )
  }
  if (!f) {
    return (
      <div className="pt-space-lg">
        <Skeleton className="mb-space-lg h-10 w-2/3" />
        <SkeletonRows rows={8} />
      </div>
    )
  }

  const owasp = splitOwasp(f.owasp)
  const backTo = `/scans/${f.scan_id}/findings${search}`

  return (
    <>
      <PageHeader
        crumbs={[
          { label: scan.data?.name ?? f.scan_id, to: `/scans/${f.scan_id}/findings` },
          { label: 'Findings', to: backTo },
          { label: `${f.title} (${f.cwe_id})` },
        ]}
        title={f.title}
        meta={
          <>
            <SeverityBadge severity={f.severity} score={f.risk_score} />
            <CVSSBadge
              score={f.cvss?.score ?? f.cvss_score}
              severity={f.cvss?.severity ?? f.cvss_severity}
              provenance={f.cvss?.provenance ?? f.cvss_provenance}
            />
            <CorrelationBadge
              type={f.correlation?.correlation_type}
              isPrimary={f.correlation?.is_primary}
            />
            <Tag>{f.cwe_id}</Tag>
            <Tag>
              {owasp.code}:2025 {owasp.name}
            </Tag>
            <SourceBadge source={f.source} ruleId={f.rule_id} />
            {f.suppressed && <SuppressedBadge />}
          </>
        }
        actions={
          <>
            {idx >= 0 && (
              <span className="font-label-code-md text-label-code-md text-on-surface-variant">
                Finding <b className="text-on-surface">{idx + 1}</b> of {list.length}
              </span>
            )}
            <ButtonLink
              to={prev ? `/findings/${prev.id}${search}` : '#'}
              icon="arrow_back"
              className={prev ? '' : 'pointer-events-none opacity-40'}
            >
              Previous <kbd className="text-on-surface-variant">[</kbd>
            </ButtonLink>
            <ButtonLink
              to={next ? `/findings/${next.id}${search}` : '#'}
              icon="arrow_forward"
              className={next ? '' : 'pointer-events-none opacity-40'}
            >
              Next <kbd className="text-on-surface-variant">]</kbd>
            </ButtonLink>
            <ButtonLink to={backTo} icon="list">
              Back to findings
            </ButtonLink>
          </>
        }
      />

      {typeof f.ml_score_before === 'number' && typeof f.ml_score === 'number' && (
        <div
          role="status"
          className="mb-space-lg flex flex-wrap items-center gap-space-sm rounded-xl bg-surface-container-low p-space-md shadow-sm"
        >
          <Icon name="info" className="text-secondary" />
          <span className="font-label-code-md text-label-code-md text-on-surface">
            Score lowered by feedback:{' '}
            <b className="text-primary">
              {f.ml_score_before.toFixed(2)} → {f.ml_score.toFixed(2)}
            </b>
            {f.feedback && ` · model ${f.feedback.model_version}`}
          </span>
          <span className="ml-auto rounded bg-secondary/15 px-2 py-0.5 font-label-code-sm text-label-code-sm text-secondary">
            Feedback active
          </span>
        </div>
      )}

      <div className="grid grid-cols-1 gap-space-lg xl:grid-cols-12">
        <div className="flex flex-col gap-space-lg xl:col-span-7">
          <section aria-label="Code" className="overflow-hidden rounded-xl bg-surface-container-low shadow-sm">
            <header className="flex flex-wrap items-center gap-space-sm px-space-md py-space-sm">
              <Icon name="terminal" className="text-primary" />
              <span className="font-label-code-lg text-label-code-lg text-on-surface">{f.file_path}</span>
              <Tag>
                Lines {f.start_line}–{f.end_line}
              </Tag>
              <Button
                variant="ghost"
                icon="content_copy"
                className="ml-auto"
                onClick={() =>
                  navigator.clipboard
                    .writeText(f.snippet)
                    .then(() => toast('success', 'Snippet copied.'))
                    .catch(() => toast('error', 'Copy failed: clipboard not available.'))
                }
              >
                Copy
              </Button>
            </header>
            <CodeViewer
              code={f.snippet}
              startLine={f.start_line}
              highlight={[sinkIndex(f.snippet)]}
              label={`Code for ${f.title}`}
            />
            <p className="flex items-center gap-space-sm bg-surface-container px-space-md py-space-sm font-body-sm text-body-sm text-on-surface-variant">
              <span aria-hidden="true" className="h-3 w-1 rounded bg-error" />
              Highlighted line: the likely sink. The code was read, never run.
            </p>
          </section>
          <DetectedBy f={f} />
          <Card title="Recommended fix" icon="healing">
            <Markdown>{f.mitigation}</Markdown>
          </Card>
        </div>

        <div className="flex flex-col gap-space-lg xl:col-span-5">
          <Card
            title="Risk score"
            action={
              <span className={`font-label-code-sm text-label-code-sm uppercase ${severityMeta[f.severity].text}`}>
                {severityMeta[f.severity].label}
              </span>
            }
          >
            <RiskGauge score={typeof f.risk_score === 'number' ? f.risk_score : 0} label={`${severityMeta[f.severity]?.label ?? 'Unknown'} severity`} />
          </Card>
          <CVSSPanel finding={f} />
          <FrameworksPanel finding={f} />
          <CorrelationPanel finding={f} />
          <TriagePanel finding={f} />
        </div>
      </div>
    </>
  )
}
