'use client'

import { useState, useEffect } from 'react'
import { motion, AnimatePresence } from 'framer-motion'
import type { Incident } from '@/types'

// Approximate SVG coordinate positions (800x400 canvas)
const IP_LOCATIONS: Record<string, { x: number; y: number; label: string }> = {
  '185.220.101': { x: 555, y: 155, label: 'Russia' },
  '185.220.102': { x: 565, y: 148, label: 'Russia' },
  '91.108.4':    { x: 505, y: 148, label: 'Netherlands' },
  '91.108.56':   { x: 510, y: 152, label: 'Netherlands' },
  '45.95.147':   { x: 500, y: 160, label: 'Europe' },
  '194.165':     { x: 545, y: 175, label: 'Iran' },
  '77.83':       { x: 520, y: 158, label: 'E. Europe' },
  '23.':         { x: 160, y: 175, label: 'USA' },
  '52.':         { x: 175, y: 165, label: 'USA' },
  '10.':         { x: 400, y: 200, label: 'Internal' },
  '192.168.':    { x: 400, y: 200, label: 'Internal' },
}

const TARGET = { x: 400, y: 205 }

const CONTINENTS = `
  M 50,80 L 120,75 L 130,90 L 140,110 L 135,140 L 120,160 L 100,165 L 80,155 L 65,130 L 55,110 Z
  M 150,70 L 240,65 L 260,80 L 280,85 L 285,110 L 270,130 L 255,145 L 230,145 L 200,130 L 175,110 L 160,90 Z
  M 120,175 L 170,170 L 200,185 L 220,210 L 215,245 L 195,270 L 165,275 L 145,260 L 125,235 L 115,205 Z
  M 450,80 L 530,75 L 590,85 L 640,95 L 660,115 L 650,140 L 620,155 L 580,160 L 540,155 L 500,140 L 470,120 L 455,100 Z
  M 480,170 L 530,165 L 570,175 L 600,195 L 605,220 L 590,240 L 560,250 L 525,245 L 495,225 L 475,200 Z
  M 610,90 L 680,85 L 730,95 L 755,115 L 745,140 L 715,160 L 680,165 L 645,155 L 625,135 L 615,112 Z
  M 660,175 L 710,168 L 750,180 L 770,205 L 760,235 L 730,255 L 695,255 L 665,240 L 648,215 L 650,190 Z
`

function getLocation(ip: string) {
  for (const [prefix, loc] of Object.entries(IP_LOCATIONS)) {
    if (ip.startsWith(prefix)) return loc
  }
  return { x: 300 + Math.random() * 200, y: 130 + Math.random() * 80, label: 'Unknown' }
}

function formatBytes(bytes: number = 0) {
  if (!bytes) return '0 B'
  const k = 1024
  const sizes = ['B', 'KB', 'MB', 'GB', 'TB']
  const i = Math.floor(Math.log(bytes) / Math.log(k))
  return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i]
}

interface AttackSource {
  id: string
  ip: string
  x: number
  y: number
  label: string
  severity: string
  threat_type: string
  bytes_sent?: number
  timestamp: number
}

interface Props {
  incidents: Partial<Incident>[]
}

export function AttackMap({ incidents }: Props) {
  const [sources, setSources] = useState<AttackSource[]>([])
  const [hovered, setHovered] = useState<string | null>(null)

  useEffect(() => {
    const unique = new Map<string, AttackSource>()
    incidents.slice(0, 15).forEach((inc) => {
      const ip = inc.source_ip || ''
      if (!ip || ip.startsWith('10.') || ip.startsWith('192.168.')) return
      if (!unique.has(ip)) {
        const loc = getLocation(ip)
        unique.set(ip, {
          id: inc.id || ip,
          ip,
          x: loc.x + (Math.random() - 0.5) * 20,
          y: loc.y + (Math.random() - 0.5) * 20,
          label: loc.label,
          severity: inc.severity || 'medium',
          threat_type: (inc as any).threat_type || 'unknown',
          bytes_sent: (inc as any).bytes_sent,
          timestamp: new Date(inc.created_at || Date.now()).getTime(),
        })
      }
    })
    setSources(Array.from(unique.values()))
  }, [incidents])

  const getColor = (sev: string, threatType?: string) => {
    if (threatType === 'data_exfiltration') return '#ff003c' // Brighter red for exfil
    if (sev === 'critical') return '#ff3b6b'
    if (sev === 'high')     return '#ff6b35'
    if (sev === 'medium')   return '#ffb800'
    return '#00d4ff'
  }

  return (
    <div style={{
      height: '100%',
      display: 'flex',
      flexDirection: 'column',
      overflow: 'hidden',
      background: '#0f1629',
      border: '1px solid #1e2d4a',
      borderRadius: '8px',
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
          Live Attack Map
        </span>
        <div style={{ display: 'flex', alignItems: 'center', gap: 5 }}>
          <span style={{
            width: 7, height: 7, borderRadius: '50%',
            background: '#ff3b6b', display: 'inline-block',
          }} />
          <span style={{ fontSize: 10, fontFamily: 'monospace', color: '#ff3b6b' }}>
            {sources.length} active
          </span>
        </div>
      </div>

      {/* Map area */}
      <div style={{ flex: 1, minHeight: 0, position: 'relative', background: '#0a0e1a' }}>
        {/* Scanline overlay */}
        <div style={{
          position: 'absolute', inset: 0, pointerEvents: 'none',
          backgroundImage: 'repeating-linear-gradient(0deg, transparent, transparent 3px, rgba(0,212,255,0.015) 3px, rgba(0,212,255,0.015) 4px)',
        }} />

        <svg width="100%" height="100%" viewBox="0 0 800 400" preserveAspectRatio="xMidYMid meet">
          {/* Grid */}
          {Array.from({ length: 17 }, (_, i) => (
            <line key={`v${i}`} x1={i * 50} y1={0} x2={i * 50} y2={400} stroke="#1e2d4a" strokeWidth={0.5} />
          ))}
          {Array.from({ length: 9 }, (_, i) => (
            <line key={`h${i}`} x1={0} y1={i * 50} x2={800} y2={i * 50} stroke="#1e2d4a" strokeWidth={0.5} />
          ))}

          {/* Continent outlines */}
          <g opacity={0.15}>
            {CONTINENTS.trim().split('\n').map((path, i) => (
              <path key={i} d={path.trim()} fill="#00d4ff" stroke="#00d4ff" strokeWidth={0.5} />
            ))}
          </g>

          {/* Attack arcs and dots */}
          {sources.map((src, i) => {
            const isExfil = src.threat_type === 'data_exfiltration'
            const color = getColor(src.severity, src.threat_type)
            const dur = isExfil ? '1.2s' : `${1.8 + (i % 4) * 0.5}s`
            const midX = (src.x + TARGET.x) / 2
            const midY = Math.min(src.y, TARGET.y) - 40 - i * 5
            const pathD = `M${src.x},${src.y} Q${midX},${midY} ${TARGET.x},${TARGET.y}`

            return (
              <g key={src.id} 
                 onMouseEnter={() => setHovered(src.id)}
                 onMouseLeave={() => setHovered(null)}
                 style={{ cursor: 'pointer' }}>
                <path 
                  d={pathD} 
                  fill="none" 
                  stroke={color} 
                  strokeWidth={isExfil ? 2.5 : 0.8} 
                  strokeOpacity={isExfil ? 0.7 : 0.25} 
                  strokeDasharray={isExfil ? "none" : "6 4"} 
                >
                  {isExfil && (
                    <animate attributeName="stroke-opacity" values="0.7;0.2;0.7" dur="1s" repeatCount="indefinite" />
                  )}
                </path>
                <circle r={isExfil ? 3.5 : 2.5} fill={color} opacity={0.9}>
                  <animateMotion dur={dur} repeatCount="indefinite" path={pathD} />
                  <animate attributeName="opacity" values="0;1;1;0" dur={dur} repeatCount="indefinite" />
                </circle>
                <circle cx={src.x} cy={src.y} r={isExfil ? 10 : 6} fill={color} opacity={0.15}>
                  <animate attributeName="r" values={isExfil ? "8;18;8" : "5;12;5"} dur={isExfil ? "1.5s" : "2.5s"} repeatCount="indefinite" />
                  <animate attributeName="opacity" values="0.15;0;0.15" dur={isExfil ? "1.5s" : "2.5s"} repeatCount="indefinite" />
                </circle>
                <circle cx={src.x} cy={src.y} r={isExfil ? 5 : 4} fill={color} opacity={0.9} />
                
                {/* Tooltip on hover */}
                {hovered === src.id && (
                  <foreignObject x={src.x + 10} y={src.y - 40} width="160" height="60">
                    <div style={{
                      background: 'rgba(10, 14, 26, 0.95)',
                      border: `1px solid ${color}`,
                      borderRadius: '4px',
                      padding: '6px 10px',
                      boxShadow: '0 4px 12px rgba(0,0,0,0.5)',
                      pointerEvents: 'none',
                    }}>
                      <div style={{ color: color, fontSize: '10px', fontWeight: 700, textTransform: 'uppercase', marginBottom: 2 }}>
                        {isExfil ? '⚠️ DATA EXFILTRATION' : src.threat_type.replace(/_/g, ' ')}
                      </div>
                      <div style={{ color: '#e8eaf0', fontSize: '11px', fontFamily: 'monospace' }}>
                        {src.ip}
                      </div>
                      {isExfil && src.bytes_sent && (
                        <div style={{ color: '#ff3b6b', fontSize: '11px', fontWeight: 700, marginTop: 2 }}>
                          {formatBytes(src.bytes_sent)} transferred
                        </div>
                      )}
                    </div>
                  </foreignObject>
                )}

                {!hovered && (
                  <text x={src.x + 7} y={src.y + 4} fill={color} fontSize={8} opacity={0.85} fontFamily="JetBrains Mono, monospace">
                    {src.label}
                  </text>
                )}
              </g>
            )
          })}

          {/* Target */}
          <circle cx={TARGET.x} cy={TARGET.y} r={16} fill="none" stroke="#00d4ff" strokeWidth={1} opacity={0.3}>
            <animate attributeName="r" values="14;22;14" dur="2s" repeatCount="indefinite" />
            <animate attributeName="opacity" values="0.3;0.05;0.3" dur="2s" repeatCount="indefinite" />
          </circle>
          <circle cx={TARGET.x} cy={TARGET.y} r={8} fill="none" stroke="#00d4ff" strokeWidth={1.5} opacity={0.6} />
          <circle cx={TARGET.x} cy={TARGET.y} r={3} fill="#00d4ff" />
          <text x={TARGET.x + 12} y={TARGET.y + 4} fill="#00d4ff" fontSize={9} fontWeight="bold" fontFamily="Inter, sans-serif">
            YOUR NETWORK
          </text>
        </svg>

        {/* Legend */}
        <div style={{ position: 'absolute', bottom: 6, left: 10, display: 'flex', gap: 10 }}>
          {[
            { color: '#ff3b6b', label: 'Critical' },
            { color: '#ff6b35', label: 'High' },
            { color: '#ffb800', label: 'Medium' },
          ].map((l) => (
            <div key={l.label} style={{ display: 'flex', alignItems: 'center', gap: 4 }}>
              <span style={{ width: 7, height: 7, borderRadius: '50%', background: l.color, display: 'inline-block' }} />
              <span style={{ fontSize: 9, color: '#6b7a99' }}>{l.label}</span>
            </div>
          ))}
        </div>
      </div>
    </div>
  )
}
