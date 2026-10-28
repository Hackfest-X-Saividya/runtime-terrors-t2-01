import { useState } from 'react'
import { useUpdateFinding } from '@/api/hooks'
import { FindingStatusPill } from '@/components/Badges'
import { Card } from '@/components/Card'
import { FeedbackForm } from '@/components/FeedbackForm'
import { Icon } from '@/components/Icon'
import { Popover } from '@/components/Popover'
import { useToast } from '@/hooks/useToast'
import { fmtRelative } from '@/lib/format'
import { findingStatusMeta, findingStatusOrder } from '@/lib/labels'
import type { Finding, FindingStatus } from '@/types/contract'

export function TriagePanel({ finding }: { finding: Finding }) {
  const [open, setOpen] = useState<FindingStatus | null>(null)
  const update = useUpdateFinding()
  const toast = useToast()
  const fb = finding.feedback

  return (
    <>
      <Card title="Triage & status" icon="tune">
        <div
          role="group"
          aria-label="Set status"
          className="grid grid-cols-2 gap-1 rounded-lg bg-surface-container-lowest p-1 2xl:grid-cols-4"
        >
          {findingStatusOrder.map((s) => {
            const current = finding.status === s
            return (
              <Popover
                key={s}
                open={open === s}
                onClose={() => setOpen(null)}
                label={`Mark as ${findingStatusMeta[s].label}`}
                align={s === 'accepted' || s === 'false_positive' ? 'right' : 'left'}
                anchor={
                  <button
                    type="button"
                    aria-pressed={current}
                    aria-expanded={open === s}
                    onClick={() => setOpen(open === s ? null : s)}
                    className={`flex w-full items-center justify-center gap-1.5 rounded-lg px-space-sm py-2 font-label-code-md text-label-code-md transition-colors ${
                      current
                        ? 'bg-surface-container-highest text-primary'
                        : 'text-on-surface-variant hover:bg-surface-container hover:text-on-surface'
                    }`}
                  >
                    {current && <span aria-hidden="true" className="h-1.5 w-1.5 rounded-full bg-primary" />}
                    {findingStatusMeta[s].label}
                  </button>
                }
              >
                <FeedbackForm
                  status={s}
                  trainable={finding.source !== 'rule'}
                  pending={update.isPending}
                  onCancel={() => setOpen(null)}
                  onSubmit={(input) =>
                    update.mutate(
                      { id: finding.id, ...input },
                      {
                        onSuccess: (f) => {
                          setOpen(null)
                          const learned = typeof f.ml_score_before === 'number' && input.train
                          const scoreStr = typeof f.ml_score === 'number' ? f.ml_score.toFixed(2) : '-'
                          toast(
                            'success',
                            `Marked ${findingStatusMeta[s].label.toLowerCase()}.` +
                              (learned
                                ? ` Model ${f.feedback?.model_version ?? ''} lowered the ML score to ${scoreStr}.`
                                : ''),
                          )
                        },
                        onError: (e) => toast('error', e.message),
                      },
                    )
                  }
                />
              </Popover>
            )
          })}
        </div>
        <p className="mt-space-sm font-body-sm text-body-sm text-on-surface-variant">
          Current status: <FindingStatusPill status={finding.status} />
        </p>
      </Card>

      <Card title="Feedback" icon="forum">
        {fb ? (
          <div className="flex flex-col gap-space-sm">
            <div className="flex flex-wrap items-center gap-space-sm">
              <FindingStatusPill status={finding.status} />
              {fb.reason && <span className="font-label-code-md text-label-code-md text-on-surface">{fb.reason}</span>}
            </div>
            {fb.note && (
              <p className="rounded-lg bg-surface-container-lowest p-space-sm font-label-code-md text-label-code-md text-on-surface-variant">
                {fb.note}
              </p>
            )}
            <p className="flex flex-wrap items-center gap-space-sm font-label-code-sm text-label-code-sm text-on-surface-variant">
              <span>{fmtRelative(fb.created_at)}</span>
              <span>·</span>
              {fb.train ? (
                <span className="flex items-center gap-1 text-primary">
                  <Icon name="model_training" /> Used to train model {fb.model_version}
                </span>
              ) : (
                <span>Not used for training (model {fb.model_version})</span>
              )}
            </p>
          </div>
        ) : (
          <p className="font-body-md text-body-md text-on-surface-variant">
            No feedback yet. Marking a false positive with a reason can teach the model to stop flagging this pattern.
          </p>
        )}
      </Card>
    </>
  )
}
