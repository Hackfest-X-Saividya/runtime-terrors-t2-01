import { useId, useState, type FormEvent } from 'react'
import { falsePositiveReasons, findingStatusMeta } from '@/lib/labels'
import type { FindingStatus, UpdateFindingInput } from '@/types/contract'
import { Button } from './Button'
import { Icon } from './Icon'

interface FeedbackFormProps {
  status: FindingStatus
  /** At least one target has ML evidence, so training can change the model. */
  trainable: boolean
  count?: number
  pending?: boolean
  onSubmit: (input: UpdateFindingInput) => void
  onCancel: () => void
}

/** Status change + feedback. A reason is required for false positives. */
export function FeedbackForm({ status, trainable, count = 1, pending, onSubmit, onCancel }: FeedbackFormProps) {
  const id = useId()
  const isFp = status === 'false_positive'
  const [reason, setReason] = useState('')
  const [other, setOther] = useState('')
  const [note, setNote] = useState('')
  const [train, setTrain] = useState(trainable)
  const [touched, setTouched] = useState(false)

  const finalReason = reason === 'Other' ? other.trim() : reason
  const missingReason = isFp && !finalReason

  const submit = (e: FormEvent) => {
    e.preventDefault()
    setTouched(true)
    if (missingReason) return
    onSubmit({
      status,
      ...(finalReason ? { reason: finalReason } : {}),
      ...(note.trim() ? { note: note.trim() } : {}),
      ...(isFp ? { train: train && trainable } : {}),
    })
  }

  const field =
    'w-full rounded-lg bg-surface-container px-space-sm py-1.5 font-body-md text-body-md text-on-surface placeholder:text-outline'

  return (
    <form onSubmit={submit} className="flex flex-col gap-space-sm" noValidate>
      <div className="flex items-center gap-space-sm">
        <Icon name={isFp ? 'flag' : 'edit_note'} className="text-primary" />
        <h3 className="font-headline-sm text-headline-sm text-on-surface">
          Mark {count > 1 ? `${count} findings` : 'finding'} as {findingStatusMeta[status].label.toLowerCase()}
        </h3>
      </div>

      <label
        htmlFor={`${id}-reason`}
        className="font-label-code-sm text-label-code-sm uppercase text-on-surface-variant"
      >
        Reason {isFp ? <span className="text-error">(required)</span> : '(optional)'}
      </label>
      <select
        id={`${id}-reason`}
        value={reason}
        onChange={(e) => setReason(e.target.value)}
        aria-invalid={touched && missingReason}
        aria-describedby={touched && missingReason ? `${id}-err` : undefined}
        className={field}
      >
        <option value="">Choose a reason…</option>
        {falsePositiveReasons.map((r) => (
          <option key={r}>{r}</option>
        ))}
      </select>
      {reason === 'Other' && (
        <input
          aria-label="Other reason"
          value={other}
          onChange={(e) => setOther(e.target.value)}
          placeholder="Describe the reason"
          className={field}
        />
      )}
      {touched && missingReason && (
        <p id={`${id}-err`} className="font-body-sm text-body-sm text-error">
          Pick a reason so the team (and the model) know why.
        </p>
      )}

      <label htmlFor={`${id}-note`} className="font-label-code-sm text-label-code-sm uppercase text-on-surface-variant">
        Note (optional)
      </label>
      <textarea
        id={`${id}-note`}
        rows={3}
        value={note}
        onChange={(e) => setNote(e.target.value)}
        placeholder="e.g. Sanitised by middleware in app/security.py"
        className={`${field} resize-none font-mono`}
      />

      {isFp && (
        <label className={`flex items-start gap-space-sm ${trainable ? 'cursor-pointer' : 'opacity-60'}`}>
          <input
            type="checkbox"
            checked={train && trainable}
            disabled={!trainable}
            onChange={(e) => setTrain(e.target.checked)}
            className="mt-1 h-4 w-4 accent-primary"
          />
          <span className="font-body-md text-body-md text-on-surface">
            Use this to improve the model
            <span className="block font-body-sm text-body-sm text-on-surface-variant">
              {trainable
                ? 'Lowers the ML score for this pattern in this file; the next rescan hides it below threshold.'
                : 'Rule-only findings never train the ML model.'}
            </span>
          </span>
        </label>
      )}

      <div className="mt-space-xs flex justify-end gap-space-sm">
        <Button variant="ghost" onClick={onCancel}>
          Cancel
        </Button>
        <Button type="submit" variant="primary" icon="check" disabled={pending}>
          {pending ? 'Saving…' : 'Confirm'}
        </Button>
      </div>
    </form>
  )
}
