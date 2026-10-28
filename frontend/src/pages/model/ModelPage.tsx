import { Link } from 'react-router-dom'
import { useModelInfo } from '@/api/hooks'
import { FindingStatusPill, Tag } from '@/components/Badges'
import { Card } from '@/components/Card'
import { HeldOutChart } from '@/components/charts/HeldOutChart'
import { Icon } from '@/components/Icon'
import { KpiCard } from '@/components/KpiCard'
import { PageHeader } from '@/components/PageHeader'
import { EmptyState, ErrorState, Skeleton, SkeletonRows } from '@/components/States'
import { fmtNumber, fmtPct, fmtRelative } from '@/lib/format'
import { mockTransport } from '@/lib/runtime'
import { VersionTimeline } from './VersionTimeline'

function SampleTag() {
  return mockTransport() ? (
    <span className="rounded bg-tertiary-container/20 px-2 py-0.5 font-label-code-sm text-label-code-sm text-tertiary">
      Sample data
    </span>
  ) : null
}

export default function ModelPage() {
  const info = useModelInfo()

  if (info.isError) {
    return (
      <>
        <PageHeader title="Model card & evaluation" />
        <ErrorState error={info.error} onRetry={() => info.refetch()} />
      </>
    )
  }
  const d = info.data
  if (!d) {
    return (
      <>
        <PageHeader title="Model card & evaluation" />
        <Skeleton className="mb-space-lg h-40 w-full rounded-xl" />
        <SkeletonRows rows={6} />
      </>
    )
  }

  const { model_card: card, eval: ev, learning } = d
  const avgDetection = ev.held_out.length
    ? ev.held_out.reduce((n, r) => n + r.detection_rate, 0) / ev.held_out.length
    : 0
  const avgFpr = ev.held_out.length ? ev.held_out.reduce((n, r) => n + r.fpr, 0) / ev.held_out.length : 0
  const latest = learning.versions[0]

  return (
    <>
      <PageHeader
        crumbs={[{ label: 'Model' }]}
        title="Model card & evaluation"
        description={`${card.architecture}. Scores every function for vulnerability risk; findings only it catches are marked Novel.`}
        meta={
          <>
            <SampleTag />
            <Tag className="text-primary">
              <span aria-hidden="true" className="h-1.5 w-1.5 rounded-full bg-primary" /> Active: {learning.version}
            </Tag>
            {d.status && (
              <Tag className={d.status === 'ready' ? 'text-primary' : 'text-warning'}>
                <span
                  aria-hidden="true"
                  className={`h-1.5 w-1.5 rounded-full ${d.status === 'ready' ? 'bg-primary' : 'bg-warning'}`}
                />{' '}
                Runtime: {d.status}
              </Tag>
            )}
            <Tag>threshold {card.threshold.toFixed(2)}</Tag>
            <Tag>{card.languages.join(', ')}</Tag>
          </>
        }
      />

            {/* Architecture and Zero-Day Disclaimer Banner */}
      <div className="mb-space-lg rounded-xl bg-surface-container-low p-space-md border border-outline/20">
        <div className="flex items-start gap-3">
          <Icon name="info" className="text-primary text-xl mt-0.5 shrink-0" />
          <div className="flex flex-col gap-1 text-sm">
            <p className="font-semibold text-on-surface">
              Inference Architecture & Research Disclaimer
            </p>
            <p className="text-on-surface-variant leading-relaxed">
              <b>Production Pipeline:</b> High-speed sublinear TF-IDF feature extraction combined with a regularized Logistic Regression classifier and online contextual bandit reinforcement learning. CodeBERT is utilized as an offline deep-learning evaluation baseline.
            </p>
            <p className="text-on-surface-variant leading-relaxed">
              <b>Zero-Day Generalization Proxy:</b> Held-out vulnerability types from the VUDENC benchmark evaluate cross-category detection transfer. All novel ML findings are candidates requiring manual triage and dynamic verification prior to vulnerability disclosure.
            </p>
          </div>
        </div>
      </div>

      <Card className="mb-space-lg" title={card.name} subtitle={card.architecture} icon="smart_toy">
        <dl className="grid grid-cols-1 gap-space-sm md:grid-cols-2 xl:grid-cols-4">
          {[
            ['Version', card.version],
            ['Training data', card.training_data],
            ['Languages', card.languages.join(', ')],
            ['Decision threshold', `${card.threshold.toFixed(2)}: ML scores below it are suppressed on rescan`],
          ].map(([k, v]) => (
            <div key={k} className="rounded-lg bg-surface-container p-space-sm">
              <dt className="font-label-code-sm text-label-code-sm uppercase text-on-surface-variant">{k}</dt>
              <dd className="font-body-md text-body-md text-on-surface">{v}</dd>
            </div>
          ))}
        </dl>
      </Card>

      <section
        aria-label="Evaluation metrics"
        className="mb-space-lg grid grid-cols-2 gap-4 md:grid-cols-3 xl:grid-cols-5"
      >
        <KpiCard
          label="Precision"
          icon="target"
          value={fmtPct(ev.precision)}
          footer="Of flagged functions, truly vulnerable"
        />
        <KpiCard label="Recall" icon="radar" value={fmtPct(ev.recall)} footer="Of vulnerable functions, flagged" />
        <KpiCard
          label="F1 score"
          icon="balance"
          value={fmtPct(ev.f1)}
          valueClassName="text-primary"
          footer={`model ${learning.version}`}
        />
        <KpiCard label="ROC-AUC" icon="show_chart" value={ev.roc_auc.toFixed(3)} footer="Ranking quality" />
        <KpiCard
          label="Threshold"
          icon="tune"
          value={card.threshold.toFixed(2)}
          valueClassName="text-tertiary"
          footer="Suppression cut-off"
        />
      </section>

      <Card
        className="mb-space-lg"
        title="Held-out vulnerability types"
        subtitle="Each row is a vulnerability type the model never saw in training: our zero-day proxy (requires independent validation)."
        action={
          <span className="flex flex-wrap items-center gap-space-sm">
            <SampleTag />
            <Tag className="text-primary">Avg detection {fmtPct(avgDetection)}</Tag>
            <Tag>Mean FPR {fmtPct(avgFpr)}</Tag>
          </span>
        }
      >
        {ev.held_out.length ? (
          <div className="grid grid-cols-1 gap-space-lg 2xl:grid-cols-2">
            <div className="overflow-x-auto">
              <table className="w-full min-w-[520px] text-left">
                <caption className="sr-only">Held-out evaluation by vulnerability type</caption>
                <thead className="font-label-code-sm text-label-code-sm uppercase text-on-surface-variant">
                  <tr>
                    <th scope="col" className="py-space-sm pr-space-sm font-semibold">
                      Vulnerability type
                    </th>
                    <th scope="col" className="px-space-sm py-space-sm font-semibold">
                      Detection
                    </th>
                    <th scope="col" className="px-space-sm py-space-sm font-semibold">
                      FPR
                    </th>
                    <th scope="col" className="py-space-sm pl-space-sm text-right font-semibold">
                      Samples
                    </th>
                  </tr>
                </thead>
                <tbody>
                  {ev.held_out.map((r) => (
                    <tr key={r.vuln_type} className="border-t border-surface-container">
                      <td className="py-3 pr-space-sm">
                        <span className="block font-body-md text-body-md text-on-surface">{r.vuln_type}</span>
                        <span className="flex items-center gap-1">
                          <Tag>{r.cwe_id}</Tag>
                          <span className="rounded bg-surface-container-highest px-1.5 py-0.5 font-label-code-sm text-label-code-sm text-secondary">
                            NOVEL TYPE
                          </span>
                        </span>
                      </td>
                      <td className="px-space-sm py-3">
                        <span className="flex items-center gap-space-sm">
                          <span className="font-mono text-label-code-lg text-primary">{fmtPct(r.detection_rate)}</span>
                          <span aria-hidden="true" className="h-1.5 w-16 rounded-full bg-surface-container-highest">
                            <span
                              className="block h-1.5 rounded-full bg-primary"
                              style={{ width: `${r.detection_rate * 100}%` }}
                            />
                          </span>
                        </span>
                      </td>
                      <td className="px-space-sm py-3 font-mono text-label-code-lg text-on-surface">{fmtPct(r.fpr)}</td>
                      <td className="py-3 pl-space-sm text-right font-mono text-label-code-lg text-on-surface-variant">
                        {fmtNumber(r.samples)}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
              <p className="mt-space-sm font-label-code-sm text-label-code-sm text-on-surface-variant">
                {fmtNumber(ev.held_out.reduce((n, r) => n + r.samples, 0))} held-out samples in total.
              </p>
            </div>
            <HeldOutChart rows={ev.held_out} average={avgDetection} />
          </div>
        ) : (
          <EmptyState icon="science" title="No held-out evaluation published" />
        )}
      </Card>

      <section aria-label="Learning from feedback" className="mb-space-lg">
        <header className="mb-space-md flex flex-wrap items-center gap-space-sm">
          <Icon name="model_training" className="text-headline-md text-primary" />
          <h2 className="font-headline-md text-headline-md text-on-surface">Learning from feedback</h2>
          <span className="rounded bg-primary/10 px-2 py-0.5 font-label-code-sm text-label-code-sm text-primary">
            Active learning loop
          </span>
          <SampleTag />
        </header>
        <p className="mb-space-md max-w-3xl font-body-md text-body-md text-on-surface-variant">
          False positives marked with "Use this to improve the model" lower the ML score for that pattern in that file.
          On the next scan, findings that fall below the threshold are suppressed. Rule-only findings never change the
          model.
        </p>
        <div className="grid grid-cols-2 gap-4 md:grid-cols-4">
          <KpiCard label="Feedback received" icon="forum" value={learning.feedback_count} footer="Training events" />
          <KpiCard
            label="False positives suppressed"
            icon="filter_alt_off"
            value={learning.suppressed_count}
            valueClassName="text-secondary"
            footer="Across all scans"
          />
          <KpiCard
            label="Current model"
            icon="deployed_code"
            value={learning.version}
            valueClassName="text-primary"
            footer={`threshold ${learning.threshold.toFixed(2)}`}
          />
          <KpiCard
            label="Last updated"
            icon="update"
            value={latest ? fmtRelative(latest.created_at) : '–'}
            footer={latest?.trigger}
          />
        </div>
      </section>

      <Card
        className="mb-space-lg"
        title="Version timeline"
        subtitle="Newest first. Revert undoes the score changes made by newer feedback."
        padding="none"
        icon="timeline"
      >
        <VersionTimeline versions={learning.versions} />
      </Card>

      <Card title="Recent feedback" subtitle="Triage that reached the model" icon="history_edu" padding="none">
        {learning.recent_feedback.length ? (
          <ul>
            {learning.recent_feedback.map((f) => (
              <li
                key={`${f.id}-${f.feedback?.created_at}`}
                className="flex flex-wrap items-center gap-space-md border-t border-surface-container px-space-lg py-3"
              >
                <div className="flex min-w-0 flex-1 flex-col">
                  <Link
                    to={`/findings/${f.id}`}
                    className="truncate font-body-md text-body-md text-on-surface hover:text-primary"
                  >
                    {f.title}
                  </Link>
                  <span className="font-label-code-sm text-label-code-sm text-on-surface-variant">
                    {f.file_path}:{f.start_line}
                  </span>
                </div>
                <FindingStatusPill status={f.status} />
                <span className="w-56 truncate font-body-md text-body-md text-on-surface-variant">
                  {f.feedback?.reason ?? 'No reason given'}
                </span>
                <span className="w-24 font-label-code-sm text-label-code-sm text-on-surface-variant">
                  {f.feedback?.train ? <span className="text-primary">trained</span> : 'not trained'}
                </span>
                <span className="w-16 text-right font-label-code-sm text-label-code-sm text-on-surface-variant">
                  {f.feedback && fmtRelative(f.feedback.created_at)}
                </span>
              </li>
            ))}
          </ul>
        ) : (
          <EmptyState icon="forum" title="No feedback yet">
            Mark findings as false positive, fixed or accepted to start the learning loop.
          </EmptyState>
        )}
      </Card>
    </>
  )
}
