'use client'

import { useEffect, useState } from 'react'

interface SLATimerProps {
  deadline: string
  breached: boolean
  size?: 'sm' | 'md' | 'lg'
}

export default function SLATimer({ deadline, breached, size = 'md' }: SLATimerProps) {
  const [remaining, setRemaining] = useState<number>(0)

  useEffect(() => {
    const update = () => {
      setRemaining(new Date(deadline).getTime() - Date.now())
    }
    update()
    const id = setInterval(update, 1000)
    return () => clearInterval(id)
  }, [deadline])

  const fontSizes = { sm: '10px', md: '12px', lg: '15px' }
  const fontSize = fontSizes[size]

  if (breached || remaining <= 0) {
    return (
      <span
        style={{
          color: '#ff3b6b',
          fontWeight: 700,
          fontSize,
          fontFamily: 'monospace',
          animation: 'sentinelPulse 1s ease-in-out infinite',
        }}
      >
        SLA BREACHED
      </span>
    )
  }

  const totalSec = Math.floor(remaining / 1000)
  const hours = Math.floor(totalSec / 3600)
  const minutes = Math.floor((totalSec % 3600) / 60)
  const seconds = totalSec % 60

  const isRed = remaining < 30 * 60 * 1000
  const isYellow = remaining < 2 * 60 * 60 * 1000

  const color = isRed ? '#ff3b6b' : isYellow ? '#ffb800' : '#00ff9d'

  const display =
    hours > 0
      ? `${hours}h ${minutes}m`
      : minutes > 0
      ? `${minutes}m ${seconds}s`
      : `${seconds}s`

  return (
    <span
      style={{
        color,
        fontSize,
        fontWeight: 600,
        fontFamily: 'monospace',
        ...(isRed ? { animation: 'sentinelPulse 1s ease-in-out infinite' } : {}),
      }}
    >
      {display}
    </span>
  )
}
