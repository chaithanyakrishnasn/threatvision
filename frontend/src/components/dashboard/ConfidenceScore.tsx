interface Props {
  score: number  // 0.0 – 1.0
  showLabel?: boolean
}

export function ConfidenceScore({ score, showLabel = true }: Props) {
  const pct = Math.round(score * 100)
  const color =
    pct >= 85 ? 'text-red-400' :
    pct >= 70 ? 'text-orange-400' :
    pct >= 50 ? 'text-yellow-400' : 'text-slate-400'

  const barColor =
    pct >= 85 ? 'bg-red-500' :
    pct >= 70 ? 'bg-orange-500' :
    pct >= 50 ? 'bg-yellow-500' : 'bg-slate-500'

  return (
    <div className="flex items-center gap-2">
      <div className="flex-1 h-1.5 bg-slate-700 rounded-full overflow-hidden w-16">
        <div
          className={`h-full rounded-full transition-all duration-500 ${barColor}`}
          style={{ width: `${pct}%` }}
        />
      </div>
      {showLabel && (
        <span className={`font-mono text-xs font-semibold ${color}`}>{pct}%</span>
      )}
    </div>
  )
}
