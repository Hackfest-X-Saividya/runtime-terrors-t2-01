import { useState } from 'react'
import { Card } from '@/components/Card'
import { Icon } from '@/components/Icon'
import { Tag } from '@/components/Badges'
import { Button } from '@/components/Button'
import { useToast } from '@/hooks/useToast'
import type { Finding } from '@/types/contract'

const METRIC_NAMES: Record<string, { name: string; values: Record<string, string> }> = {
  AV: {
    name: 'Attack Vector',
    values: { N: 'Network', A: 'Adjacent', L: 'Local', P: 'Physical' },
  },
  AC: {
    name: 'Attack Complexity',
    values: { L: 'Low', H: 'High' },
  },
  PR: {
    name: 'Privileges Required',
    values: { N: 'None', L: 'Low', H: 'High' },
  },
  UI: {
    name: 'User Interaction',
    values: { N: 'None', R: 'Required' },
  },
  S: {
    name: 'Scope',
    values: { U: 'Unchanged', C: 'Changed' },
  },
  C: {
    name: 'Confidentiality',
    values: { N: 'None', L: 'Low', H: 'High' },
  },
  I: {
    name: 'Integrity',
    values: { N: 'None', L: 'Low', H: 'High' },
  },
  A: {
    name: 'Availability',
    values: { N: 'None', L: 'Low', H: 'High' },
  },
}

function parseCvssVector(vector: string | null | undefined): Record<string, string> {
  if (!vector || !vector.startsWith('CVSS:3.1/')) return {}
  const parts = vector.slice('CVSS:3.1/'.length).split('/')
  const out: Record<string, string> = {}
  for (const part of parts) {
    const [k, v] = part.split(':')
    if (k && v) out[k] = v
  }
  return out
}

export function CVSSPanel({ finding: f }: { finding: Finding }) {
  const toast = useToast()
  const [copied, setCopied] = useState(false)

  const cvssObj = f.cvss
  const score = cvssObj?.score ?? f.cvss_score ?? null
  const vector = cvssObj?.vector ?? f.cvss_vector ?? null
  const severity = cvssObj?.severity ?? f.cvss_severity ?? (score ? (score >= 9.0 ? 'Critical' : score >= 7.0 ? 'High' : score >= 4.0 ? 'Medium' : 'Low') : null)
  const provenance = cvssObj?.provenance ?? f.cvss_provenance ?? 'unassessed'

  const isAssessed = typeof score === 'number' && provenance !== 'unassessed'
  const metrics = cvssObj?.metrics ?? parseCvssVector(vector)

  const sevLower = (severity || 'none').toLowerCase()
  const sevBadgeColor =
    sevLower === 'critical'
      ? 'bg-error-container text-on-error-container'
      : sevLower === 'high'
        ? 'bg-tertiary-container text-on-tertiary-container'
        : sevLower === 'medium'
          ? 'bg-surface-container-highest text-secondary'
          : 'bg-surface-container text-on-surface-variant'

  const provLabel =
    provenance === 'analyst_assessed'
      ? 'Analyst Assessed'
      : provenance === 'rule_estimated'
        ? 'Rule Estimated'
        : 'Unassessed (Automated Scan)'

  const copyVector = () => {
    if (!vector) return
    navigator.clipboard
      .writeText(vector)
      .then(() => {
        setCopied(true)
        toast('success', 'CVSS v3.1 vector copied to clipboard.')
        setTimeout(() => setCopied(false), 2000)
      })
      .catch(() => toast('error', 'Clipboard not available.'))
  }

  return (
    <Card
      title="CVSS v3.1 Base Score"
      icon="security"
      action={
        <span className="flex items-center gap-1.5">
          <Tag className={provenance === 'analyst_assessed' ? 'text-primary' : 'text-on-surface-variant'}>
            {provLabel}
          </Tag>
          {isAssessed && (
            <span className={`rounded px-2 py-0.5 font-label-code-sm text-label-code-sm uppercase font-semibold ${sevBadgeColor}`}>
              {severity}
            </span>
          )}
        </span>
      }
    >
      <div className="flex flex-col gap-space-md">
        {isAssessed ? (
          <>
            <div className="flex items-baseline justify-between rounded-lg bg-surface-container p-space-md">
              <div>
                <span className="block font-label-code-sm text-label-code-sm uppercase text-on-surface-variant">
                  CVSS 3.1 Base Score
                </span>
                <span className="font-headline-lg text-headline-lg font-bold text-on-surface">
                  {score.toFixed(1)}
                  <span className="font-label-code-lg text-label-code-lg text-on-surface-variant"> / 10.0</span>
                </span>
              </div>
              <div className="text-right">
                <span className="block font-label-code-sm text-label-code-sm uppercase text-on-surface-variant">
                  Specification
                </span>
                <span className="font-label-code-md text-label-code-md text-primary font-mono">
                  FIRST CVSS v3.1
                </span>
              </div>
            </div>

            {vector && (
              <div className="rounded-lg bg-surface-container-low p-space-sm border border-outline/20">
                <div className="flex items-center justify-between mb-1">
                  <span className="font-label-code-sm text-label-code-sm uppercase text-on-surface-variant">
                    Vector String
                  </span>
                  <Button
                    variant="ghost"
                    icon={copied ? 'check' : 'content_copy'}
                    className="h-7 px-2 text-xs"
                    onClick={copyVector}
                  >
                    {copied ? 'Copied' : 'Copy'}
                  </Button>
                </div>
                <code className="block font-mono text-label-code-sm text-on-surface break-all select-all">
                  {vector}
                </code>
              </div>
            )}

            {Object.keys(metrics).length > 0 && (
              <div>
                <span className="block font-label-code-sm text-label-code-sm uppercase text-on-surface-variant mb-2">
                  Base Metrics Breakdown
                </span>
                <div className="grid grid-cols-2 gap-2 sm:grid-cols-4">
                  {Object.entries(metrics).map(([k, val]) => {
                    const meta = METRIC_NAMES[k]
                    const valName = meta?.values[val] ?? val
                    return (
                      <div key={k} className="rounded bg-surface-container p-2 text-xs">
                        <span className="block font-label-code-sm text-on-surface-variant truncate">
                          {meta?.name ?? k} ({k})
                        </span>
                        <span className="font-semibold text-on-surface font-mono">
                          {valName} ({val})
                        </span>
                      </div>
                    )
                  })}
                </div>
              </div>
            )}
          </>
        ) : (
          <div className="rounded-lg bg-surface-container p-space-md text-center">
            <Icon name="verified_user" className="text-on-surface-variant/40 text-3xl mx-auto mb-2" />
            <p className="font-label-code-md text-label-code-md font-semibold text-on-surface">
              CVSS Base Score Unassessed
            </p>
            <p className="font-body-sm text-body-sm text-on-surface-variant mt-1 max-w-sm mx-auto">
              Automated scanners calculate ZeroSentinel Risk Scores. Official CVSS v3.1 scores require confirmed
              environmental and attack complexity assessment.
            </p>
          </div>
        )}

        <p className="font-body-xs text-xs text-on-surface-variant/80 border-t border-surface-container pt-2">
          <b>Note:</b> CVSS 3.1 Base Score evaluates static technical severity per the FIRST specification. It is evaluated independently from ZeroSentinel&apos;s proprietary contextual Risk Score (0–10).
        </p>
      </div>
    </Card>
  )
}
