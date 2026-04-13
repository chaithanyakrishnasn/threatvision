'use client'

import { useEffect, useState, useRef } from 'react'
import {
  AreaChart, Area, XAxis, YAxis, CartesianGrid, Tooltip,
  ResponsiveContainer
} from 'recharts'

interface TimePoint {
  time: string
  brute_force: number
  c2_beacon: number
  lateral_movement: number
  benign: number
}

function generatePoint(prev?: TimePoint): TimePoint {
  const now = new Date()
  const label = now.toLocaleTimeString('en-US', { hour: '2-digit', minute: '2-digit', second: '2-digit', hour12: false })
  const rand = (base: number, variance: number) => Math.max(0, Math.round(base + (Math.random() - 0.5) * variance))
  return {
    time: label,
    brute_force:       rand(3, 6),
    c2_beacon:         rand(2, 4),
    lateral_movement:  rand(1, 3),
    benign:            rand(8, 10),
  }
}

const INITIAL_DATA: TimePoint[] = Array.from({ length: 30 }, (_, i) => {
  const d = new Date(Date.now() - (29 - i) * 2000)
  return {
    time: d.toLocaleTimeString('en-US', { hour: '2-digit', minute: '2-digit', second: '2-digit', hour12: false }),
    brute_force:      Math.max(0, Math.round(2 + Math.random() * 5)),
    c2_beacon:        Math.max(0, Math.round(1 + Math.random() * 4)),
    lateral_movement: Math.max(0, Math.round(Math.random() * 3)),
    benign:           Math.max(0, Math.round(6 + Math.random() * 10)),
  }
})

const CustomTooltip = ({ active, payload, label }: any) => {
  if (!active || !payload?.length) return null
  return (
    <div
      className="text-xs rounded-lg p-3 space-y-1"
      style={{ background: '#0f1629', border: '1px solid #1e2d4a' }}
    >
      <p className="font-mono text-xs mb-2" style={{ color: '#6b7a99' }}>{label}</p>
      {payload.map((entry: any) => (
        <div key={entry.name} className="flex items-center gap-2">
          <span className="w-2 h-2 rounded-full" style={{ background: entry.color }} />
          <span style={{ color: '#e8eaf0' }}>{entry.name.replace('_', ' ')}:</span>
          <span className="font-mono font-bold" style={{ color: entry.color }}>{entry.value}</span>
        </div>
      ))}
    </div>
  )
}

export function ThreatTimeline() {
  const [data, setData] = useState<TimePoint[]>(INITIAL_DATA)
  const intervalRef = useRef<NodeJS.Timeout | null>(null)

  useEffect(() => {
    intervalRef.current = setInterval(() => {
      setData((prev) => {
        const next = [...prev.slice(-59), generatePoint(prev[prev.length - 1])]
        return next
      })
    }, 2000)
    return () => { if (intervalRef.current) clearInterval(intervalRef.current) }
  }, [])

  return (
    <ResponsiveContainer width="100%" height={200}>
      <AreaChart data={data} margin={{ top: 4, right: 8, left: -24, bottom: 0 }}>
        <defs>
          <linearGradient id="bf-grad" x1="0" y1="0" x2="0" y2="1">
            <stop offset="5%"  stopColor="#ff3b6b" stopOpacity={0.5} />
            <stop offset="95%" stopColor="#ff3b6b" stopOpacity={0.0} />
          </linearGradient>
          <linearGradient id="c2-grad" x1="0" y1="0" x2="0" y2="1">
            <stop offset="5%"  stopColor="#00d4ff" stopOpacity={0.4} />
            <stop offset="95%" stopColor="#00d4ff" stopOpacity={0.0} />
          </linearGradient>
          <linearGradient id="lm-grad" x1="0" y1="0" x2="0" y2="1">
            <stop offset="5%"  stopColor="#ffb800" stopOpacity={0.4} />
            <stop offset="95%" stopColor="#ffb800" stopOpacity={0.0} />
          </linearGradient>
          <linearGradient id="bg-grad" x1="0" y1="0" x2="0" y2="1">
            <stop offset="5%"  stopColor="#00ff9d" stopOpacity={0.12} />
            <stop offset="95%" stopColor="#00ff9d" stopOpacity={0.0} />
          </linearGradient>
        </defs>

        <CartesianGrid strokeDasharray="3 3" stroke="#1e2d4a" vertical={false} />
        <XAxis
          dataKey="time"
          tick={{ fill: '#6b7a99', fontSize: 9 }}
          tickLine={false}
          axisLine={false}
          interval="preserveStartEnd"
        />
        <YAxis
          tick={{ fill: '#6b7a99', fontSize: 9 }}
          tickLine={false}
          axisLine={false}
        />
        <Tooltip content={<CustomTooltip />} />

        <Area type="monotone" dataKey="benign"           stroke="#00ff9d" strokeWidth={1} fill="url(#bg-grad)" strokeOpacity={0.4} dot={false} isAnimationActive={false} />
        <Area type="monotone" dataKey="lateral_movement" stroke="#ffb800" strokeWidth={1.5} fill="url(#lm-grad)" dot={false} isAnimationActive={false} />
        <Area type="monotone" dataKey="c2_beacon"        stroke="#00d4ff" strokeWidth={1.5} fill="url(#c2-grad)" dot={false} isAnimationActive={false} />
        <Area type="monotone" dataKey="brute_force"      stroke="#ff3b6b" strokeWidth={2}   fill="url(#bf-grad)" dot={false} isAnimationActive={false} />
      </AreaChart>
    </ResponsiveContainer>
  )
}
