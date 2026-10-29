import { Link } from 'react-router-dom'
import { Card } from '@/components/Card'
import { Icon } from '@/components/Icon'
import { Tag } from '@/components/Badges'
import type { Finding, CorrelationDetail } from '@/types/contract'

export function CorrelationPanel({ finding: f }: { finding: Finding }) {
  const correlation: CorrelationDetail | undefined =
    f.correlation ?? (f.correlation_data as unknown as CorrelationDetail | undefined)

  if (!correlation && f.source !== 'both' && f.source !== 'ml') {
    return null
  }

  const clusterId = correlation?.cluster_id ?? 'unassigned'
  const correlationType = correlation?.correlation_type ?? (f.source === 'both' ? 'corroborated' : f.source === 'ml' ? 'standalone_candidate' : 'unassigned')
  const isPrimary = correlation?.is_primary ?? true
  const primaryId = correlation?.primary_finding_id
  const evidence = correlation?.evidence ?? []
  const rationale = correlation?.rationale
  const limitations = correlation?.limitations

  return (
    <Card
      title="Correlation & Deduplication"
      icon="hub"
      action={
        <div className="flex items-center gap-1.5">
          <Tag className="font-mono text-xs">Cluster #{clusterId.slice(0, 8)}</Tag>
          {correlationType === 'exact_duplicate' && !isPrimary && (
            <span className="rounded bg-warning/15 px-2 py-0.5 font-label-code-sm text-label-code-sm text-warning font-semibold">
              Duplicate
            </span>
          )}
          {correlationType === 'corroborated' && (
            <span className="rounded bg-primary/15 px-2 py-0.5 font-label-code-sm text-label-code-sm text-primary font-semibold">
              Corroborated
            </span>
          )}
          {correlationType === 'standalone_candidate' && (
            <span className="rounded bg-primary-container px-2 py-0.5 font-label-code-sm text-label-code-sm text-on-primary-container font-semibold">
              ML Novel
            </span>
          )}
        </div>
      }
    >
      <div className="flex flex-col gap-space-md">
        {/* Exact Duplicate Warning */}
        {correlationType === 'exact_duplicate' && !isPrimary && (
          <div className="rounded-lg bg-surface-container border border-outline/30 p-space-sm">
            <div className="flex items-start gap-2">
              <Icon name="content_copy" className="text-warning text-lg mt-0.5 shrink-0" />
              <div>
                <p className="font-label-code-md text-label-code-md font-semibold text-on-surface">
                  Exact Duplicate Finding
                </p>
                <p className="font-body-sm text-body-sm text-on-surface-variant mt-0.5">
                  This finding shares the identical vulnerability signature, file, and code location as another detector result.
                  It has been correlated to prevent double-counting or inflating the scan&apos;s overall risk score.
                </p>
                {primaryId && (
                  <Link
                    to={`/findings/${primaryId}`}
                    className="inline-flex items-center gap-1 mt-2 text-primary font-label-code-sm text-label-code-sm font-semibold hover:underline"
                  >
                    <Icon name="arrow_forward" />
                    Jump to Primary Finding ({primaryId.slice(0, 8)}...)
                  </Link>
                )}
              </div>
            </div>
          </div>
        )}

        {/* Standalone Candidate Warning */}
        {correlationType === 'standalone_candidate' && (
          <div className="rounded-lg bg-primary/5 border border-primary/20 p-space-sm">
            <div className="flex items-start gap-2">
              <Icon name="auto_awesome" className="text-primary text-lg mt-0.5 shrink-0" />
              <div>
                <p className="font-label-code-md text-label-code-md font-semibold text-primary">
                  Unverified ML Candidate (Zero-Day Hypothesis)
                </p>
                <p className="font-body-sm text-body-sm text-on-surface-variant mt-0.5">
                  This finding was detected solely by machine learning inference without corroboration from standard static rules.
                  Per responsible disclosure principles, candidate zero-days require independent verification and manual triage before confirming exploitability.
                </p>
              </div>
            </div>
          </div>
        )}

        {/* Corroborated Notice */}
        {correlationType === 'corroborated' && (
          <div className="rounded-lg bg-surface-container p-space-sm border border-outline/10">
            <div className="flex items-start gap-2">
              <Icon name="verified" className="text-primary text-lg mt-0.5 shrink-0" />
              <div>
                <p className="font-label-code-md text-label-code-md font-semibold text-on-surface">
                  Dual-Engine Corroboration
                </p>
                <p className="font-body-sm text-body-sm text-on-surface-variant mt-0.5">
                  Both pattern-matching static rules and deep learning embeddings independently flagged this weakness,
                  substantially reducing the probability of a false positive.
                </p>
              </div>
            </div>
          </div>
        )}

        {/* Rationale */}
        {rationale && (
          <div>
            <span className="block font-label-code-sm text-label-code-sm uppercase text-on-surface-variant mb-1">
              Correlation Rationale
            </span>
            <p className="font-body-sm text-body-sm text-on-surface-variant bg-surface-container p-space-sm rounded-lg">
              {rationale}
            </p>
          </div>
        )}

        {/* Evidence Items */}
        {evidence.length > 0 && (
          <div>
            <span className="block font-label-code-sm text-label-code-sm uppercase text-on-surface-variant mb-1.5">
              Corroborating Evidence ({evidence.length})
            </span>
            <div className="flex flex-col gap-1.5">
              {evidence.map((item, idx) => (
                <div key={idx} className="rounded bg-surface-container p-2 text-xs flex flex-col gap-0.5">
                  <div className="flex items-center justify-between font-mono text-on-surface">
                    <span className="font-semibold uppercase text-primary">{item.source} engine</span>
                    <Tag className="text-[10px]">{item.evidence_type}</Tag>
                  </div>
                  <p className="text-on-surface-variant">{item.detail}</p>
                </div>
              ))}
            </div>
          </div>
        )}

        {/* Limitations */}
        {limitations && (
          <p className="font-body-xs text-xs text-on-surface-variant/70 border-t border-surface-container pt-2">
            <b>Disclaimer:</b> {limitations}
          </p>
        )}
      </div>
    </Card>
  )
}
