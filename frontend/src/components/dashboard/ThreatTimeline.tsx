'use client'

import { useEffect, useState } from 'react'
import {
  AreaChart, Area, XAxis, YAxis, CartesianGrid, Tooltip,
  ResponsiveContainer
} from 'recharts'
import { dashboardExtApi } from '@/lib/api'

interface TimePoint {
  timestamp: string
  minute: number
  brute_force: number
  c2_beacon: number
  lateral_movement: number
  data_exfiltration: number
  false_positive: number
  benign: number
  total: number
}

const SKELETON: TimePoint[] = Array.from({ length: 60 }, (_, i) => ({
  timestamp: '', minute: i,
  brute_force: 0, c2_beacon: 0, lateral_movement: 0, data_exfiltration: 0,
  false_positive: 0, benign: 0, total: 0,
}))

const formatXAxis = (minute: number, total: number) => {
  const ago = total - minute
  if (ago === total) return `${total}m ago`
  if (ago === Math.floor(total * 0.75)) return `${Math.floor(total * 0.75)}m`
  if (ago === Math.floor(total / 2)) return `${Math.floor(total / 2)}m`
  if (ago === Math.floor(total * 0.25)) return `${Math.floor(total * 0.25)}m`
  if (ago === 0) return 'Now'
  return ''
}

const CustomTooltip = ({ active, payload, label }: any) => {
  if (!active || !payload?.length) return null
  return (
    <div style={{
      background: '#0f1629', border: '1px solid #1e2d4a',
      borderRadius: 6, padding: '8px 10px', fontSize: 11,
    }}>
      <p style={{ color: '#6b7a99', fontFamily: 'monospace', marginBottom: 4 }}>
        {label === 0 ? 'Now' : `${label}m ago`}
      </p>
      {payload.map((entry: any) =>
        entry.value > 0 ? (
          <div key={entry.name} style={{ display: 'flex', alignItems: 'center', gap: 6, marginBottom: 2 }}>
            <span style={{ width: 6, height: 6, borderRadius: '50%', background: entry.color, display: 'inline-block' }} />
            <span style={{ color: '#e8eaf0' }}>{entry.name}:</span>
            <span style={{ color: entry.color, fontFamily: 'monospace', fontWeight: 700 }}>{entry.value}</span>
          </div>
        ) : null
      )}
    </div>
  )
}

export function ThreatTimeline() {
  const [data, setData] = useState<TimePoint[]>(SKELETON)
  const [hasActivity, setHasActivity] = useState(true)

  useEffect(() => {
    const fetchTimeline = async () => {
      try {
        const points = await dashboardExtApi.getThreatTimeline(60)
        if (points && points.length > 0) {
          setData(points.slice(-60))
          setHasActivity(points.some((p: TimePoint) => p.total > 0))
        }
      } catch {}
    }
    fetchTimeline()
    const interval = setInterval(fetchTimeline, 10_000)
    return () => clearInterval(interval)
  }, [])

  const total = data.length

  return (
    <div style={{
      height: '100%',
      display: 'flex',
      flexDirection: 'column',
      overflow: 'hidden',
    }}>
      {/* Header */}
      <div style={{
        flexShrink: 0,
        padding: '7px 12px',
        borderBottom: '1px solid #1e2d4a',
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'space-between',
      }}>
        <span style={{
          color: '#6b7a99', fontSize: '11px', fontWeight: 600,
          textTransform: 'uppercase', letterSpacing: '0.07em',
        }}>
          Threat Activity — Live
        </span>
        <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
          {[
            { color: '#ff3b6b', label: 'Brute Force' },
            { color: '#00d4ff', label: 'C2 Beacon' },
            { color: '#ffb800', label: 'Lateral Move' },
            { color: '#ff003c', label: 'Data Exfil' },
          ].map((l) => (
            <div key={l.label} style={{ display: 'flex', alignItems: 'center', gap: 3 }}>
              <span style={{ width: 10, height: 2, borderRadius: 1, background: l.color, display: 'inline-block' }} />
              <span style={{ fontSize: 9, color: '#6b7a99' }}>{l.label}</span>
            </div>
          ))}
        </div>
      </div>

      {/* Chart */}
      <div style={{ flex: 1, minHeight: 0 }}>
        {!hasActivity ? (
          <div style={{
            height: '100%', display: 'flex', alignItems: 'center', justifyContent: 'center',
            color: '#6b7a99', fontSize: 12,
          }}>
            No activity in this window
          </div>
        ) : (
          <ResponsiveContainer width="100%" height="100%">
            <AreaChart data={data} margin={{ top: 4, right: 8, left: -24, bottom: 0 }}>
              <defs>
                <linearGradient id="bf-grad" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="5%"  stopColor="#ff3b6b" stopOpacity={0.5} />
                  <stop offset="95%" stopColor="#ff3b6b" stopOpacity={0} />
                </linearGradient>
                <linearGradient id="exfil-grad" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="5%"  stopColor="#ff003c" stopOpacity={0.5} />
                  <stop offset="95%" stopColor="#ff003c" stopOpacity={0} />
                </linearGradient>
                <linearGradient id="c2-grad" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="5%"  stopColor="#00d4ff" stopOpacity={0.4} />
                  <stop offset="95%" stopColor="#00d4ff" stopOpacity={0} />
                </linearGradient>
                <linearGradient id="lm-grad" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="5%"  stopColor="#ffb800" stopOpacity={0.4} />
                  <stop offset="95%" stopColor="#ffb800" stopOpacity={0} />
                </linearGradient>
                <linearGradient id="fp-grad" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="5%"  stopColor="#6b7a99" stopOpacity={0.2} />
                  <stop offset="95%" stopColor="#6b7a99" stopOpacity={0} />
                </linearGradient>
                <linearGradient id="bg-grad" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="5%"  stopColor="#00ff9d" stopOpacity={0.12} />
                  <stop offset="95%" stopColor="#00ff9d" stopOpacity={0} />
                </linearGradient>
              </defs>
              <CartesianGrid strokeDasharray="3 3" stroke="#1e2d4a" vertical={false} />
              <XAxis
                dataKey="minute"
                tick={{ fill: '#6b7a99', fontSize: 9 }}
                tickLine={false} axisLine={false}
                tickFormatter={(m) => formatXAxis(m, total - 1)}
              />
              <YAxis
                tick={{ fill: '#6b7a99', fontSize: 9 }}
                tickLine={false} axisLine={false}
              />
              <Tooltip content={<CustomTooltip />} />
              <Area type="monotone" dataKey="benign"           stroke="#00ff9d" strokeWidth={1}   fill="url(#bg-grad)" strokeOpacity={0.4} dot={false} isAnimationActive={false} name="Benign" />
              <Area type="monotone" dataKey="false_positive"   stroke="#6b7a99" strokeWidth={1}   fill="url(#fp-grad)" fillOpacity={0.1}   dot={false} isAnimationActive={false} name="False Positive" />
              <Area type="monotone" dataKey="lateral_movement" stroke="#ffb800" strokeWidth={1.5} fill="url(#lm-grad)"                     dot={false} isAnimationActive={false} name="Lateral Move" />
              <Area type="monotone" dataKey="c2_beacon"        stroke="#00d4ff" strokeWidth={1.5} fill="url(#c2-grad)"                     dot={false} isAnimationActive={false} name="C2 Beacon" />
              <Area type="monotone" dataKey="data_exfiltration" stroke="#ff003c" strokeWidth={2}   fill="url(#exfil-grad)"                   dot={false} isAnimationActive={false} name="Data Exfil" />
              <Area type="monotone" dataKey="brute_force"      stroke="#ff3b6b" strokeWidth={2}   fill="url(#bf-grad)"                     dot={false} isAnimationActive={false} name="Brute Force" />
            </AreaChart>
          </ResponsiveContainer>
        )}
      </div>
    </div>
  )
}
