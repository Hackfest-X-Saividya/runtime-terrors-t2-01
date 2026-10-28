import { Bar, BarChart, CartesianGrid, Cell, ReferenceLine, ResponsiveContainer, Tooltip, XAxis, YAxis } from 'recharts'
import { colors, px } from '@/lib/tokens'
import type { HeldOutType } from '@/types/contract'

/** Detection rate per vulnerability type the model never saw in training. */
export function HeldOutChart({ rows, average }: { rows: HeldOutType[]; average?: number }) {
  const data = rows.map((r) => ({ name: r.vuln_type, rate: Math.round(r.detection_rate * 1000) / 10 }))
  const tick = { fill: colors['on-surface-variant'], fontSize: px.bodyMd }
  return (
    <div
      className="h-72 w-full"
      role="img"
      aria-label={`Detection rate on held-out types: ${data.map((d) => `${d.name} ${d.rate}%`).join(', ')}`}
    >
      <ResponsiveContainer width="100%" height="100%">
        <BarChart data={data} layout="vertical" margin={{ top: 4, right: 48, bottom: 4, left: 8 }}>
          <CartesianGrid horizontal={false} stroke={colors['outline-variant']} />
          <XAxis
            type="number"
            domain={[0, 100]}
            tick={tick}
            tickFormatter={(v: number) => `${v}%`}
            stroke={colors['outline-variant']}
          />
          <YAxis type="category" dataKey="name" width={210} tick={tick} stroke={colors['outline-variant']} />
          <Tooltip
            cursor={{ fill: colors['surface-container-high'] }}
            formatter={(v: number) => [`${v}%`, 'Detection rate']}
            contentStyle={{
              background: colors['surface-container-highest'],
              border: 'none',
              borderRadius: 8,
              fontSize: px.bodyMd,
            }}
            labelStyle={{ color: colors['on-surface'] }}
            itemStyle={{ color: colors.primary }}
          />
          {average !== undefined && (
            <ReferenceLine
              x={average * 100}
              stroke={colors.tertiary}
              strokeDasharray="4 4"
              label={{
                value: `avg ${Math.round(average * 100)}%`,
                fill: colors.tertiary,
                fontSize: px.bodyMd,
                position: 'top',
              }}
            />
          )}
          <Bar
            dataKey="rate"
            radius={[0, 4, 4, 0]}
            isAnimationActive={false}
            label={{
              position: 'right',
              fill: colors['on-surface'],
              fontSize: px.bodyMd,
              formatter: (v: number) => `${v}%`,
            }}
          >
            {data.map((d) => (
              <Cell
                key={d.name}
                fill={average !== undefined && d.rate < average * 100 ? colors['tertiary-container'] : colors.primary}
              />
            ))}
          </Bar>
        </BarChart>
      </ResponsiveContainer>
    </div>
  )
}
