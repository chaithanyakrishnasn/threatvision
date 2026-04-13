'use client'

type Severity = 'critical' | 'high' | 'medium' | 'low'

const SEV_STYLES: Record<Severity, { bg: string; color: string; border: string; dot: string }> = {
  critical: { bg: 'rgba(255,59,107,0.15)', color: '#ff3b6b', border: 'rgba(255,59,107,0.4)', dot: '#ff3b6b' },
  high:     { bg: 'rgba(255,107,53,0.15)', color: '#ff6b35', border: 'rgba(255,107,53,0.4)', dot: '#ff6b35' },
  medium:   { bg: 'rgba(255,184,0,0.12)',  color: '#ffb800', border: 'rgba(255,184,0,0.4)',  dot: '#ffb800' },
  low:      { bg: 'rgba(0,255,157,0.10)', color: '#00ff9d', border: 'rgba(0,255,157,0.3)',  dot: '#00ff9d' },
}

interface Props {
  severity: Severity | string
  pulse?: boolean
  size?: 'sm' | 'md'
}

export function SeverityBadge({ severity, pulse = false, size = 'sm' }: Props) {
  const key = (severity || 'low').toLowerCase() as Severity
  const styles = SEV_STYLES[key] || SEV_STYLES.low
  const textSize = size === 'sm' ? 'text-[10px]' : 'text-xs'

  return (
    <span
      className={`inline-flex items-center gap-1.5 font-mono font-bold uppercase tracking-wider px-2 py-0.5 rounded ${textSize}`}
      style={{ background: styles.bg, color: styles.color, border: `1px solid ${styles.border}` }}
    >
      <span
        className={`w-1.5 h-1.5 rounded-full flex-shrink-0 ${pulse && key === 'critical' ? 'live-dot' : ''}`}
        style={{ background: styles.dot }}
      />
      {key}
    </span>
  )
}
