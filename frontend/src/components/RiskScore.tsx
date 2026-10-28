import { riskTextClass } from '@/lib/labels'

interface RiskScoreProps {
  score?: number | null
  size?: 'sm' | 'lg'
}

/** "8.4 / 10", coloured by risk band. */
export function RiskScore({ score, size = 'sm' }: RiskScoreProps) {
  const big = size === 'lg'
  const valid = typeof score === 'number' && !isNaN(score)
  const display = valid ? score.toFixed(1) : '-'
  return (
    <span className="inline-flex items-baseline gap-1 font-mono" aria-label={`Risk ${display} out of 10`}>
      <span
        className={`${big ? 'text-headline-xl font-bold' : 'text-label-code-lg font-semibold'} ${valid ? riskTextClass(score) : 'text-on-surface-variant'}`}
      >
        {display}
      </span>
      <span className={`${big ? 'text-body-lg' : 'text-label-code-sm'} text-on-surface-variant`}>/ 10</span>
    </span>
  )
}

/** Semicircle gauge (finding detail). */
export function RiskGauge({ score, label }: { score?: number | null; label: string }) {
  const valid = typeof score === 'number' && !isNaN(score)
  const safeScore = valid ? Math.min(10, Math.max(0, score)) : 0
  const display = valid ? score.toFixed(1) : '-'
  const r = 70
  const len = Math.PI * r
  const filled = (safeScore / 10) * len
  return (
    <div className="relative mx-auto w-48" role="img" aria-label={`Risk score ${display} of 10, ${label}`}>
      <svg viewBox="0 0 180 100" className="w-full">
        <path
          d="M 20 90 A 70 70 0 0 1 160 90"
          fill="none"
          strokeWidth="14"
          strokeLinecap="round"
          className="stroke-surface-container-highest"
        />
        <path
          d="M 20 90 A 70 70 0 0 1 160 90"
          fill="none"
          strokeWidth="14"
          strokeLinecap="round"
          strokeDasharray={`${filled} ${len}`}
          className={`${riskTextClass(safeScore)} stroke-current`}
        />
      </svg>
      <div className="absolute inset-x-0 bottom-0 flex flex-col items-center">
        <span className="font-mono text-headline-xl font-bold text-on-surface">{display}</span>
        <span className={`font-label-code-sm text-label-code-sm uppercase ${riskTextClass(safeScore)}`}>{label}</span>
      </div>
    </div>
  )
}
