import { Cell, Pie, PieChart, ResponsiveContainer, Tooltip } from 'recharts'
import { fmtNumber } from '@/lib/format'
import { severityMeta, severityOrder } from '@/lib/labels'
import { colors, px } from '@/lib/tokens'
import type { SeverityCounts } from '@/types/contract'
import { SeverityLabel } from '../Badges'

export function SeverityDonut({ counts }: { counts: SeverityCounts }) {
  const total = severityOrder.reduce((n, s) => n + counts[s], 0)
  const data = severityOrder.map((s) => ({ name: severityMeta[s].label, value: counts[s], fill: severityMeta[s].hex }))
  const pct = (n: number) => (total ? `${((n / total) * 100).toFixed(1)}%` : '0%')

  return (
    <div className="flex flex-col gap-space-md">
      <div
        className="relative mx-auto h-56 w-56"
        role="img"
        aria-label={`Findings by severity: ${severityOrder.map((s) => `${severityMeta[s].label} ${counts[s]}`).join(', ')}`}
      >
        <ResponsiveContainer width="100%" height="100%">
          <PieChart>
            <Pie
              data={data}
              dataKey="value"
              innerRadius="72%"
              outerRadius="100%"
              paddingAngle={total ? 1 : 0}
              stroke="none"
              isAnimationActive={false}
            >
              {data.map((d) => (
                <Cell key={d.name} fill={d.fill} />
              ))}
            </Pie>
            <Tooltip
              contentStyle={{
                background: colors['surface-container-highest'],
                border: 'none',
                borderRadius: 8,
                fontSize: px.bodyMd,
              }}
              itemStyle={{ color: colors['on-surface'] }}
            />
          </PieChart>
        </ResponsiveContainer>
        <div className="pointer-events-none absolute inset-0 flex flex-col items-center justify-center">
          <span className="font-mono text-headline-lg font-bold text-on-surface">{fmtNumber(total)}</span>
          <span className="font-label-code-lg text-label-code-lg uppercase text-on-surface-variant">Total</span>
        </div>
      </div>
      <ul className="grid grid-cols-2 gap-space-sm">
        {severityOrder.map((s) => (
          <li key={s} className="flex items-center justify-between gap-space-sm rounded bg-surface-container p-2">
            <SeverityLabel severity={s} large className="text-on-surface" />
            <span className="font-mono text-label-code-lg text-on-surface">
              {counts[s]} <span className="text-on-surface-variant">({pct(counts[s])})</span>
            </span>
          </li>
        ))}
      </ul>
    </div>
  )
}
