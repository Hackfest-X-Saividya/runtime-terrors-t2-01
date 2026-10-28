import { Card } from '@/components/Card'
import { Icon } from '@/components/Icon'
import { Tag } from '@/components/Badges'
import { cweUrl, owaspUrl } from '@/lib/labels'
import type { Finding, NISTCSFMapping, OWASPMapping } from '@/types/contract'

const FUNCTION_COLORS: Record<string, string> = {
  GV: 'bg-purple-500/10 text-purple-400 border-purple-500/20',
  ID: 'bg-blue-500/10 text-blue-400 border-blue-500/20',
  PR: 'bg-emerald-500/10 text-emerald-400 border-emerald-500/20',
  DE: 'bg-amber-500/10 text-amber-400 border-amber-500/20',
  RS: 'bg-rose-500/10 text-rose-400 border-rose-500/20',
  RC: 'bg-cyan-500/10 text-cyan-400 border-cyan-500/20',
}

export function FrameworksPanel({ finding: f }: { finding: Finding }) {
  const owaspList: OWASPMapping[] =
    f.owasp_mappings ??
    (f.security_frameworks?.owasp_2025 as OWASPMapping[] | undefined) ??
    []

  const nistList: NISTCSFMapping[] =
    f.nist_csf_mappings ??
    (f.security_frameworks?.nist_csf_20 as NISTCSFMapping[] | undefined) ??
    []

  const primaryOwasp = owaspList.find((m) => m.primary) ?? owaspList[0]
  const secondaryOwasp = owaspList.filter((m) => m !== primaryOwasp)

  return (
    <Card title="Security Framework Mappings" icon="category">
      <div className="flex flex-col gap-space-md">
        {/* CWE Section */}
        <div>
          <span className="block font-label-code-sm text-label-code-sm uppercase text-on-surface-variant mb-1">
            Common Weakness Enumeration
          </span>
          <a
            href={cweUrl(f.cwe_id)}
            target="_blank"
            rel="noreferrer"
            className="flex items-center justify-between rounded-lg bg-surface-container p-space-sm hover:bg-surface-container-high transition-colors"
          >
            <div>
              <span className="font-label-code-lg text-label-code-lg text-on-surface font-semibold">
                {f.cwe_id}
              </span>
              <span className="block font-body-sm text-body-sm text-on-surface-variant">
                MITRE CWE Knowledge Base
              </span>
            </div>
            <Icon name="open_in_new" className="text-on-surface-variant" />
            <span className="sr-only">(opens in a new tab)</span>
          </a>
        </div>

        {/* OWASP Top 10:2025 Section */}
        <div>
          <div className="flex items-center justify-between mb-1">
            <span className="font-label-code-sm text-label-code-sm uppercase text-on-surface-variant">
              OWASP Top 10:2025
            </span>
            <Tag>Official 2025 Taxonomy</Tag>
          </div>

          <div className="rounded-lg bg-surface-container p-space-sm">
            <div className="flex items-center justify-between mb-1">
              <a
                href={owaspUrl()}
                target="_blank"
                rel="noreferrer"
                className="font-label-code-lg text-label-code-lg text-primary hover:underline font-semibold"
              >
                {primaryOwasp ? `${primaryOwasp.category_id} ${primaryOwasp.category_name}` : f.owasp}
              </a>
              {primaryOwasp && (
                <span className="rounded bg-primary-container/40 px-2 py-0.5 font-label-code-sm text-label-code-sm uppercase text-primary font-medium">
                  {primaryOwasp.confidence} confidence
                </span>
              )}
            </div>

            {primaryOwasp?.rationale ? (
              <p className="font-body-sm text-body-sm text-on-surface-variant mt-1.5 leading-relaxed">
                {primaryOwasp.rationale}
              </p>
            ) : (
              <p className="font-body-sm text-body-sm text-on-surface-variant mt-1">
                Mapped to OWASP Top 10:2025 vulnerability standard.
              </p>
            )}

            {secondaryOwasp.length > 0 && (
              <div className="mt-3 border-t border-surface-container-highest pt-2">
                <span className="block font-label-code-sm text-xs uppercase text-on-surface-variant mb-1">
                  Secondary Mappings
                </span>
                <div className="flex flex-col gap-1.5">
                  {secondaryOwasp.map((sec) => (
                    <div key={sec.category_id} className="rounded bg-surface-container-low p-2 text-xs">
                      <div className="flex items-center justify-between font-medium text-on-surface">
                        <span>{sec.category_id} {sec.category_name}</span>
                        <Tag className="text-[10px]">{sec.confidence}</Tag>
                      </div>
                      <p className="text-on-surface-variant mt-0.5">{sec.rationale}</p>
                    </div>
                  ))}
                </div>
              </div>
            )}
          </div>
        </div>

        {/* NIST CSF 2.0 Section */}
        <div>
          <div className="flex items-center justify-between mb-1">
            <span className="font-label-code-sm text-label-code-sm uppercase text-on-surface-variant">
              NIST CSF 2.0 Technical Profile
            </span>
            <Tag>CSF 2.0</Tag>
          </div>

          {nistList.length > 0 ? (
            <div className="flex flex-col gap-2">
              {nistList.map((n) => {
                const badgeColor = FUNCTION_COLORS[n.function_code] ?? 'bg-surface-container text-on-surface'
                return (
                  <div key={n.subcategory_id} className="rounded-lg bg-surface-container p-space-sm border border-outline/10">
                    <div className="flex flex-wrap items-center gap-1.5 mb-1.5">
                      <span className={`rounded px-1.5 py-0.5 text-xs font-semibold uppercase border ${badgeColor}`}>
                        {n.function_code} · {n.function_name}
                      </span>
                      <span className="font-mono text-xs font-semibold text-on-surface">
                        {n.subcategory_id}
                      </span>
                    </div>

                    <p className="font-label-code-md text-label-code-md font-semibold text-on-surface">
                      {n.subcategory_title}
                    </p>

                    <p className="font-body-sm text-body-sm text-on-surface-variant mt-1 leading-relaxed">
                      {n.rationale}
                    </p>

                    {n.reference && (
                      <div className="mt-2 text-xs font-mono text-on-surface-variant/80 border-t border-surface-container-highest/60 pt-1.5">
                        <span className="text-primary font-semibold">Reference:</span> {n.reference}
                      </div>
                    )}
                  </div>
                )
              })}
            </div>
          ) : (
            <div className="rounded-lg bg-surface-container p-space-sm text-on-surface-variant text-xs">
              <span className="font-semibold text-on-surface block mb-1">PR.PS-01 (Platform Security)</span>
              Automated configuration and software security defect remediation under NIST Cybersecurity Framework 2.0 Protect function.
            </div>
          )}
        </div>
      </div>
    </Card>
  )
}
