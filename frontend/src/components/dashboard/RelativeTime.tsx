'use client'

import { useState, useEffect } from 'react'
import { formatDistanceToNow } from 'date-fns'

interface Props {
  timestamp: string | undefined
  className?: string
  style?: React.CSSProperties
}

export function RelativeTime({ timestamp, className, style }: Props) {
  const [relativeTime, setRelativeTime] = useState('')

  useEffect(() => {
    const update = () => {
      setRelativeTime(
        timestamp
          ? formatDistanceToNow(new Date(timestamp), { addSuffix: true })
          : 'just now'
      )
    }
    update()
    const interval = setInterval(update, 30000)
    return () => clearInterval(interval)
  }, [timestamp])

  return (
    <span className={className} style={style}>
      {relativeTime || 'just now'}
    </span>
  )
}
