import { Button } from '@/components/Button'
import { Icon } from '@/components/Icon'
import { fmtDateTime, fmtPct, fmtRelative } from '@/lib/format'
import type { ModelVersion } from '@/types/contract'

export function VersionTimeline({ versions }: { versions: ModelVersion[] }) {

  return (
    <div className="overflow-x-auto">
      <table className="w-full min-w-[720px] text-left">
        <caption className="sr-only">Model versions, newest first</caption>
        <thead className="bg-surface-container-lowest font-label-code-sm text-label-code-sm uppercase text-on-surface-variant">
          <tr>
            <th scope="col" className="px-space-lg py-space-sm font-semibold">
              Version
            </th>
            <th scope="col" className="px-space-sm py-space-sm font-semibold">
              Created
            </th>
            <th scope="col" className="px-space-sm py-space-sm font-semibold">
              Trigger
            </th>
            <th scope="col" className="px-space-sm py-space-sm font-semibold">
              Validation F1
            </th>
            <th scope="col" className="px-space-sm py-space-sm font-semibold">
              FPR
            </th>
            <th scope="col" className="px-space-lg py-space-sm text-right font-semibold">
              Actions
            </th>
          </tr>
        </thead>
        <tbody>
          {versions.map((v, i) => (
            <tr
              key={v.version}
              className={`border-t border-surface-container ${i === 0 ? 'bg-surface-container' : ''}`}
            >
              <td className="px-space-lg py-3">
                <span
                  className={`font-label-code-lg text-label-code-lg ${i === 0 ? 'text-primary' : 'text-on-surface'}`}
                >
                  {v.version}
                </span>
                {i === 0 && (
                  <span className="ml-space-sm inline-flex items-center gap-1 rounded bg-primary/10 px-1.5 py-0.5 font-label-code-sm text-label-code-sm text-primary">
                    <span aria-hidden="true" className="h-1.5 w-1.5 rounded-full bg-primary" /> Current
                  </span>
                )}
              </td>
              <td
                className="px-space-sm py-3 font-body-md text-body-md text-on-surface-variant"
                title={fmtDateTime(v.created_at)}
              >
                {fmtRelative(v.created_at)}
              </td>
              <td className="px-space-sm py-3 font-body-md text-body-md text-on-surface">{v.trigger}</td>
              <td
                className={`px-space-sm py-3 font-mono text-label-code-lg ${i === 0 ? 'text-primary' : 'text-on-surface'}`}
              >
                {fmtPct(v.f1)}
              </td>
              <td className="px-space-sm py-3 font-mono text-label-code-lg text-on-surface">{fmtPct(v.fpr)}</td>
              <td className="px-space-lg py-3 text-right">
                {i === 0 ? (
                  <span className="inline-flex items-center gap-1 font-label-code-sm text-label-code-sm text-primary">
                    <Icon name="check_circle" /> Active
                  </span>
                ) : (
                  <Button
                    variant="ghost"
                    icon="history"
                    disabled
                    title="Model checkpoint rollback is not supported by the backend runtime"
                    aria-label={`Revert to ${v.version} (unsupported)`}
                  >
                    Revert (Unsupported)
                  </Button>
                )}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}
