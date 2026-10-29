import { useState } from 'react'
import { useBulkUpdateFindings } from '@/api/hooks'
import { Button } from '@/components/Button'
import { FeedbackForm } from '@/components/FeedbackForm'
import { Popover } from '@/components/Popover'
import { useToast } from '@/hooks/useToast'
import { findingStatusMeta } from '@/lib/labels'
import type { Finding, FindingStatus } from '@/types/contract'

const actions: { status: FindingStatus; label: string; icon: string }[] = [
  { status: 'fixed', label: 'Mark fixed', icon: 'check_circle' },
  { status: 'false_positive', label: 'Mark false positive', icon: 'flag' },
  { status: 'accepted', label: 'Mark accepted', icon: 'verified' },
  { status: 'open', label: 'Reopen', icon: 'undo' },
]

export function BulkBar({ selected, onDone }: { selected: Finding[]; onDone: () => void }) {
  const [open, setOpen] = useState<FindingStatus | null>(null)
  const bulk = useBulkUpdateFindings()
  const toast = useToast()
  const trainable = selected.some((f) => f.source !== 'rule')

  return (
    <div
      role="region"
      aria-label="Bulk actions"
      className="mb-space-md flex flex-wrap items-center gap-space-md rounded-xl bg-surface-container-high p-space-md shadow-sm"
    >
      <span className="flex items-center gap-space-sm font-headline-sm text-headline-sm text-on-surface">
        <span aria-hidden="true" className="h-2.5 w-2.5 rounded-full bg-primary" />
        {selected.length} finding{selected.length === 1 ? '' : 's'} selected
      </span>
      <div className="flex flex-wrap gap-space-sm">
        {actions.map((a) => (
          <Popover
            key={a.status}
            open={open === a.status}
            onClose={() => setOpen(null)}
            label={a.label}
            anchor={
              <Button
                icon={a.icon}
                onClick={() => setOpen(open === a.status ? null : a.status)}
                aria-expanded={open === a.status}
              >
                {a.label}
              </Button>
            }
          >
            <FeedbackForm
              status={a.status}
              trainable={trainable}
              count={selected.length}
              pending={bulk.isPending}
              onCancel={() => setOpen(null)}
              onSubmit={(input) =>
                bulk.mutate(
                  { ids: selected.map((f) => f.id), ...input },
                  {
                    onSuccess: (res) => {
                      const versions = new Set(res.map((f) => f.feedback?.model_version))
                      toast(
                        'success',
                        `${res.length} finding${res.length === 1 ? '' : 's'} marked ${findingStatusMeta[a.status].label.toLowerCase()}.` +
                          (input.train && trainable ? ` Model updated to ${[...versions].pop()}.` : ''),
                      )
                      setOpen(null)
                      onDone()
                    },
                    onError: (e) => toast('error', e.message),
                  },
                )
              }
            />
          </Popover>
        ))}
      </div>
      <button
        type="button"
        onClick={onDone}
        className="ml-auto rounded font-label-code-md text-label-code-md text-on-surface-variant underline hover:text-on-surface"
      >
        Deselect all
      </button>
    </div>
  )
}
