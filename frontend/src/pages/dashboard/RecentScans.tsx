import { Link } from 'react-router-dom'
import { ScanStatusPill } from '@/components/Badges'
import { Icon } from '@/components/Icon'
import { RiskScore } from '@/components/RiskScore'
import { fmtDateTime, fmtNumber } from '@/lib/format'
import type { Scan } from '@/types/contract'

const typeIcon = { zip: 'folder_zip', git: 'commit', paste: 'content_paste' }

export function RecentScans({ scans }: { scans: Scan[] }) {
  return (
    <div className="overflow-x-auto">
      <table className="w-full min-w-[640px] text-left">
        <caption className="sr-only">Recent scans</caption>
        <thead>
          <tr className="font-label-code-sm text-label-code-sm uppercase text-on-surface-variant">
            <th scope="col" className="px-space-lg py-space-sm font-semibold">
              Name
            </th>
            <th scope="col" className="px-space-sm py-space-sm font-semibold">
              Started
            </th>
            <th scope="col" className="px-space-sm py-space-sm font-semibold">
              Files
            </th>
            <th scope="col" className="px-space-sm py-space-sm font-semibold">
              Findings
            </th>
            <th scope="col" className="px-space-sm py-space-sm font-semibold">
              Risk
            </th>
            <th scope="col" className="px-space-lg py-space-sm font-semibold">
              Status
            </th>
          </tr>
        </thead>
        <tbody>
          {scans.map((scan) => {
            const c = scan.counts_by_severity
            return (
              <tr key={scan.id} className="border-t border-surface-container hover:bg-surface-container">
                <td className="px-space-lg py-3">
                  <Link
                    to={`/scans/${scan.id}/findings`}
                    className="flex items-center gap-space-sm rounded hover:text-primary"
                  >
                    <Icon name={typeIcon[scan.source_type]} className="text-on-surface-variant" />
                    <span className="flex min-w-0 flex-col">
                      <span className="truncate font-body-md text-body-md text-on-surface">{scan.name}</span>
                      <span className="font-label-code-sm text-label-code-sm text-on-surface-variant">
                        {scan.id}
                        {scan.rescan_of && ` · rescan of ${scan.rescan_of}`}
                      </span>
                    </span>
                  </Link>
                </td>
                <td className="px-space-sm py-3 font-body-md text-body-md text-on-surface-variant">
                  {fmtDateTime(scan.started_at)}
                </td>
                <td className="px-space-sm py-3 font-mono text-label-code-lg text-on-surface-variant">
                  {fmtNumber(scan.files_scanned)}
                </td>
                <td className="px-space-sm py-3 font-body-md text-body-md">
                  <span className={c.critical ? 'text-error' : 'text-on-surface-variant'}>{c.critical} Crit</span>
                  <span className="text-on-surface-variant"> · </span>
                  <span className={c.high ? 'text-tertiary-container' : 'text-on-surface-variant'}>{c.high} High</span>
                </td>
                <td className="px-space-sm py-3">
                  <RiskScore score={scan.risk_score} />
                </td>
                <td className="px-space-lg py-3">
                  <ScanStatusPill status={scan.status} />
                </td>
              </tr>
            )
          })}
        </tbody>
      </table>
    </div>
  )
}
