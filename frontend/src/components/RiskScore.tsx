import { riskTextClass } from '@/lib/labels'

interface RiskScoreProps {
  score: number
  size?: 'sm' | 'lg'
}

/** "8.4 / 10", coloured by risk band. */
export function RiskScore({ score, size = 'sm' }: RiskScoreProps) {
  const big = size === 'lg'
  return (
    <span className="inline-flex items-baseline gap-1 font-mono" aria-label={`Risk ${score.toFixed(1)} out of 10`}>
      <span
        className={`${big ? 'text-headline-xl font-bold' : 'text-label-code-lg font-semibold'} ${riskTextClass(score)}`}
      >
        {score.toFixed(1)}
      </span>
      <span className={`${big ? 'text-body-lg' : 'text-label-code-sm'} text-on-surface-variant`}>/ 10</span>
    </span>
  )
}

/** Semicircle gauge (finding detail). */
export function RiskGauge({ score, label }: { score: number; label: string }) {
  const r = 70
  const len = Math.PI * r
  const filled = (Math.min(10, Math.max(0, score)) / 10) * len
  return (
    <div className="relative mx-auto w-48" role="img" aria-label={`Risk score ${score.toFixed(1)} of 10, ${label}`}>
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
          className={`${riskTextClass(score)} stroke-current`}
        />
      </svg>
      <div className="absolute inset-x-0 bottom-0 flex flex-col items-center">
        <span className="font-mono text-headline-xl font-bold text-on-surface">{score.toFixed(1)}</span>
        <span className={`font-label-code-sm text-label-code-sm uppercase ${riskTextClass(score)}`}>{label}</span>
      </div>
    </div>
  )
}
