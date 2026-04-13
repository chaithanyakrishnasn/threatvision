'use client'

interface Props {
  technique: string
  size?: 'sm' | 'xs'
}

export function MitreBadge({ technique, size = 'xs' }: Props) {
  const cls = size === 'xs'
    ? 'text-[10px] px-1.5 py-0.5'
    : 'text-xs px-2 py-1'

  return (
    <span
      className={`font-mono font-medium rounded ${cls} inline-block`}
      style={{ color: '#00d4ff', background: 'rgba(0,212,255,0.1)', border: '1px solid rgba(0,212,255,0.2)' }}
    >
      {technique}
    </span>
  )
}
