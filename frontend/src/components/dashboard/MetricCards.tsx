'use client'

import { useState } from 'react'
import { Activity, ShieldAlert, AlertOctagon, Filter, TrendingUp, Brain } from 'lucide-react'
import type { DashboardMetrics } from '@/types'
import { MetricDetailModal } from './MetricDetailModal'

interface Props {
  metrics: DashboardMetrics | null
  wsConnected?: boolean
}

type MetricType = 'events' | 'threats' | 'critical' | 'false_positive' | 'detection_rate' | 'confidence'

interface CardDef {
  label: string
  metricType: MetricType
  getValue: (m: DashboardMetrics) => number | string
  subValue?: (m: DashboardMetrics) => string
  icon: React.ComponentType<{ className?: string; style?: React.CSSProperties }>
  accentColor: string
  glowColor: string
  format?: 'number' | 'percent'
  pulseIfPositive?: boolean
}

const CARDS: CardDef[] = [
  {
    label: 'Total Events',
    metricType: 'events',
    getValue: (m) => m.total_events ?? m.summary?.total_events ?? 0,
    subValue: (m) => `${(m.summary?.events_24h ?? 0).toLocaleString()} / 24h`,
    icon: Activity,
    accentColor: '#00d4ff',
    glowColor: 'rgba(0,212,255,0.15)',
  },
  {
    label: 'Active Threats',
    metricType: 'threats',
    getValue: (m) => m.active_threats ?? m.summary?.active_incidents ?? 0,
    icon: ShieldAlert,
    accentColor: '#ff3b6b',
    glowColor: 'rgba(255,59,107,0.15)',
    pulseIfPositive: true,
  },
  {
    label: 'Critical Alerts',
    metricType: 'critical',
    getValue: (m) => m.critical_alerts ?? m.incidents_by_severity?.critical ?? 0,
    icon: AlertOctagon,
    accentColor: '#ff3b6b',
    glowColor: 'rgba(255,59,107,0.12)',
    pulseIfPositive: true,
  },
  {
    label: 'False Positives',
    metricType: 'false_positive',
    getValue: (m) => m.false_positives ?? 0,
    subValue: (m) => {
      const total = m.total_events ?? m.summary?.total_events ?? 0
      const fp = m.false_positives ?? 0
      if (!total) return '0%'
      return `${((fp / total) * 100).toFixed(1)}%`
    },
    icon: Filter,
    accentColor: '#ffb800',
    glowColor: 'rgba(255,184,0,0.12)',
  },
  {
    label: 'Detection Rate',
    metricType: 'detection_rate',
    getValue: (m) => {
      const rate = m.detection_rate
      if (rate != null && rate > 0) return Math.round(rate)
      // fallback from simulations
      const sims = m.recent_simulations || []
      if (sims.length) {
        const avg = sims.reduce((a: number, s: any) => a + (s.detection_rate || 0), 0) / sims.length
        return Math.round(avg * 100)
      }
      return 0
    },
    subValue: () => 'last 24h',
    icon: TrendingUp,
    accentColor: '#00ff9d',
    glowColor: 'rgba(0,255,157,0.12)',
    format: 'percent',
  },
  {
    label: 'Avg Confidence',
    metricType: 'confidence',
    getValue: (m) => {
      const conf = m.avg_confidence
      if (conf != null && conf > 0) return Math.round(conf * 100)
      return 0
    },
    icon: Brain,
    accentColor: '#00d4ff',
    glowColor: 'rgba(0,212,255,0.10)',
    format: 'percent',
  },
]

export function MetricCards({ metrics, wsConnected }: Props) {
  const [selectedMetric, setSelectedMetric] = useState<MetricType | null>(null)
  const [modalOpen, setModalOpen] = useState(false)

  const handleCardClick = (metricType: MetricType) => {
    setSelectedMetric(metricType)
    setModalOpen(true)
  }

  return (
    <>
      <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-6 gap-3">
        {CARDS.map((card) => {
          const Icon = card.icon
          const rawValue = metrics ? card.getValue(metrics) : 0
          const numValue = typeof rawValue === 'number' ? rawValue : parseInt(String(rawValue))
          const isPositive = numValue > 0
          const displayValue = card.format === 'percent' ? `${numValue}%` : numValue.toLocaleString()
          const subText = metrics && card.subValue ? card.subValue(metrics) : null

          return (
            <div
              key={card.label}
              className="relative overflow-hidden rounded-xl p-4 cursor-pointer"
              onClick={() => handleCardClick(card.metricType)}
              style={{
                background: '#141d35',
                border: `1px solid ${isPositive && card.pulseIfPositive ? card.accentColor + '50' : '#1e2d4a'}`,
              }}
            >
              {/* Icon */}
              <div
                className="w-8 h-8 rounded-lg flex items-center justify-center mb-3"
                style={{ background: card.glowColor }}
              >
                <Icon className="w-4 h-4" style={{ color: card.accentColor }} />
              </div>

              {/* Value */}
              <div className="space-y-0.5">
                <p
                  className="text-2xl font-bold font-mono leading-none"
                  style={{ color: isPositive && card.pulseIfPositive ? card.accentColor : '#e8eaf0' }}
                >
                  {metrics ? displayValue : '—'}
                </p>
                <p className="text-xs font-medium" style={{ color: '#6b7a99' }}>{card.label}</p>
                {subText && (
                  <p className="text-[10px]" style={{ color: '#6b7a99' }}>{subText}</p>
                )}
              </div>

              {/* Pulse indicator for active threats */}
              {card.pulseIfPositive && isPositive && (
                <div className="absolute top-3 right-3">
                  <span
                    className="w-2 h-2 rounded-full block"
                    style={{ background: card.accentColor }}
                  />
                </div>
              )}
            </div>
          )
        })}
      </div>
      <MetricDetailModal
        isOpen={modalOpen}
        onClose={() => setModalOpen(false)}
        metricType={selectedMetric}
      />
    </>
  )
}
