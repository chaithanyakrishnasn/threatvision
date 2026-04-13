'use client'

import { motion, AnimatePresence } from 'framer-motion'
import { Shield, ArrowRight, Link2 } from 'lucide-react'
import { SeverityBadge } from './SeverityBadge'
import { MitreBadge } from './MitreBadge'
import { RelativeTime } from './RelativeTime'
import type { Incident } from '@/types'

const SEVERITY_BORDER: Record<string, string> = {
  critical: '#ff3b6b',
  high:     '#ff6b35',
  medium:   '#ffb800',
  low:      '#00ff9d',
}

interface Props {
  incidents: Partial<Incident>[]
  onSelect?: (id: string) => void
  selectedId?: string | null
}

export function IncidentFeed({ incidents, onSelect, selectedId }: Props) {
  if (incidents.length === 0) {
    return (
      <div className="flex flex-col items-center justify-center h-40" style={{ color: '#6b7a99' }}>
        <Shield className="w-8 h-8 mb-2 opacity-40" />
        <p className="text-sm">No incidents detected</p>
      </div>
    )
  }

  return (
    <div className="space-y-2 overflow-y-auto max-h-[480px] pr-1">
      <AnimatePresence initial={false}>
        {incidents.slice(0, 50).map((incident, idx) => {
          const sev = (incident.severity || 'low').toLowerCase()
          const borderColor = SEVERITY_BORDER[sev] || '#1e2d4a'
          const isSelected = selectedId === incident.id
          const isCritical = sev === 'critical'

          return (
            <motion.div
              key={incident.id || idx}
              layout
              initial={{ opacity: 0, y: -12, scale: 0.98 }}
              animate={{ opacity: 1, y: 0, scale: 1 }}
              exit={{ opacity: 0, scale: 0.95, height: 0 }}
              transition={{ duration: 0.2 }}
              onClick={() => incident.id && onSelect?.(incident.id)}
              className={`cursor-pointer rounded-lg p-3 transition-all duration-200 ${isCritical ? 'glow-critical' : ''}`}
              style={{
                background: isSelected ? 'rgba(0,212,255,0.08)' : '#141d35',
                borderLeft: `3px solid ${borderColor}`,
                border: isSelected
                  ? `1px solid rgba(0,212,255,0.4)`
                  : `1px solid #1e2d4a`,
                borderLeftColor: borderColor,
                borderLeftWidth: '3px',
              }}
            >
              {/* Header row */}
              <div className="flex items-start justify-between gap-2 mb-2">
                <SeverityBadge severity={sev} pulse={isCritical} />
                <div className="flex items-center gap-1 flex-shrink-0">
                  {(incident as any).cross_layer_correlated && (
                    <span title="Cross-layer correlated">
                      <Link2 className="w-3 h-3" style={{ color: '#00d4ff' }} />
                    </span>
                  )}
                  {(incident as any).false_positive && (
                    <span
                      className="text-[9px] font-bold px-1.5 py-0.5 rounded"
                      style={{ background: 'rgba(107,122,153,0.2)', color: '#6b7a99', border: '1px solid #1e2d4a' }}
                    >
                      FP
                    </span>
                  )}
                </div>
              </div>

              {/* Title */}
              <p className="text-sm font-semibold leading-snug line-clamp-2 mb-2" style={{ color: '#e8eaf0' }}>
                {incident.title || 'Untitled Incident'}
              </p>

              {/* IP row */}
              {(incident.source_ip || incident.dest_ip) && (
                <div className="flex items-center gap-1.5 mb-2">
                  <span className="font-mono text-[10px]" style={{ color: '#6b7a99' }}>
                    {incident.source_ip || '—'}
                  </span>
                  <ArrowRight className="w-3 h-3 flex-shrink-0" style={{ color: '#1e2d4a' }} />
                  <span className="font-mono text-[10px]" style={{ color: '#6b7a99' }}>
                    {incident.dest_ip || '—'}
                  </span>
                </div>
              )}

              {/* MITRE techniques */}
              {(incident.mitre_techniques?.length ?? 0) > 0 && (
                <div className="flex flex-wrap gap-1 mb-2">
                  {incident.mitre_techniques!.slice(0, 4).map((t) => (
                    <MitreBadge key={t} technique={t} />
                  ))}
                </div>
              )}

              {/* Confidence bar + timestamp */}
              <div className="flex items-center justify-between mt-1">
                <div className="flex items-center gap-2 flex-1 max-w-[140px]">
                  <div className="flex-1 h-1 rounded-full" style={{ background: '#1e2d4a' }}>
                    <div
                      className="h-full rounded-full transition-all duration-500"
                      style={{
                        width: `${Math.round((incident.confidence || 0) * 100)}%`,
                        background: (incident.confidence || 0) > 0.8 ? '#ff3b6b' : '#00d4ff',
                      }}
                    />
                  </div>
                  <span className="font-mono text-[10px]" style={{ color: '#6b7a99' }}>
                    {Math.round((incident.confidence || 0) * 100)}%
                  </span>
                </div>
                <RelativeTime
                  timestamp={incident.created_at}
                  className="text-[10px]"
                  style={{ color: '#6b7a99' }}
                />
              </div>
            </motion.div>
          )
        })}
      </AnimatePresence>
    </div>
  )
}
