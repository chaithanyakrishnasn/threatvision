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
  onSelect?: (incident: Partial<Incident>) => void
}

export function IncidentFeed({ incidents, onSelect }: Props) {
  return (
    <div style={{
      background: '#0f1629',
      border: '1px solid #1e2d4a',
      borderRadius: '8px',
      height: '100%',
      display: 'flex',
      flexDirection: 'column',
      overflow: 'hidden',
    }}>
      {/* Header */}
      <div style={{
        flexShrink: 0,
        padding: '10px 14px',
        borderBottom: '1px solid #1e2d4a',
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'space-between',
      }}>
        <span style={{
          color: '#6b7a99',
          fontSize: '12px',
          fontWeight: 600,
          textTransform: 'uppercase',
          letterSpacing: '0.08em',
        }}>
          Live Feed
        </span>
        <span style={{
          color: '#ff3b6b',
          fontSize: '11px',
          fontFamily: 'monospace',
          background: 'rgba(255,59,107,0.1)',
          padding: '2px 8px',
          borderRadius: '4px',
        }}>
          {incidents.filter((i) => !(i as any).is_false_positive).length} active
        </span>
      </div>

      {/* Scrollable list */}
      <div style={{
        flex: 1,
        overflowY: 'auto',
        minHeight: 0,
        padding: '8px',
      }}>
        {incidents.length === 0 ? (
          <div style={{
            display: 'flex',
            flexDirection: 'column',
            alignItems: 'center',
            justifyContent: 'center',
            height: '120px',
            color: '#6b7a99',
          }}>
            <Shield style={{ width: 28, height: 28, marginBottom: 8, opacity: 0.3 }} />
            <p style={{ fontSize: '13px' }}>No incidents detected</p>
          </div>
        ) : (
          <AnimatePresence initial={false}>
            {incidents.slice(0, 50).map((incident, idx) => {
              const sev = (incident.severity || 'low').toLowerCase()
              const borderColor = SEVERITY_BORDER[sev] || '#1e2d4a'
              const isCritical = sev === 'critical'

              return (
                <motion.div
                  key={incident.id || idx}
                  layout
                  initial={{ opacity: 0, y: -12, scale: 0.98 }}
                  animate={{ opacity: 1, y: 0, scale: 1 }}
                  exit={{ opacity: 0, scale: 0.95, height: 0 }}
                  transition={{ duration: 0.2 }}
                  onClick={() => onSelect?.(incident)}
                  style={{
                    cursor: 'pointer',
                    borderRadius: '8px',
                    padding: '10px 12px',
                    marginBottom: '6px',
                    background: '#141d35',
                    borderLeft: `3px solid ${borderColor}`,
                    border: `1px solid #1e2d4a`,
                    borderLeftColor: borderColor,
                    borderLeftWidth: '3px',
                    transition: 'background 0.15s, border-color 0.15s',
                  }}
                  whileHover={{ background: 'rgba(0,212,255,0.06)' } as any}
                  className={isCritical ? 'glow-critical' : ''}
                >
                  {/* Header row */}
                  <div style={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between', gap: 8, marginBottom: 6 }}>
                    <SeverityBadge severity={sev} pulse={isCritical} />
                    <div style={{ display: 'flex', alignItems: 'center', gap: 4, flexShrink: 0 }}>
                      {(incident as any).cross_layer_correlated && (
                        <span title="Cross-layer correlated">
                          <Link2 style={{ width: 12, height: 12, color: '#00d4ff' }} />
                        </span>
                      )}
                      {(incident as any).false_positive && (
                        <span style={{
                          fontSize: '9px',
                          fontWeight: 700,
                          padding: '2px 6px',
                          borderRadius: '4px',
                          background: 'rgba(107,122,153,0.2)',
                          color: '#6b7a99',
                          border: '1px solid #1e2d4a',
                        }}>
                          FP
                        </span>
                      )}
                    </div>
                  </div>

                  {/* Title */}
                  <p style={{
                    fontSize: '13px',
                    fontWeight: 600,
                    color: '#e8eaf0',
                    marginBottom: 6,
                    lineHeight: 1.35,
                    display: '-webkit-box',
                    WebkitLineClamp: 2,
                    WebkitBoxOrient: 'vertical',
                    overflow: 'hidden',
                  }}>
                    {incident.title || 'Untitled Incident'}
                  </p>

                  {/* IP row */}
                  {(incident.source_ip || incident.dest_ip) && (
                    <div style={{ display: 'flex', alignItems: 'center', gap: 6, marginBottom: 6 }}>
                      <span style={{ fontFamily: 'monospace', fontSize: '10px', color: '#6b7a99' }}>
                        {incident.source_ip || '—'}
                      </span>
                      <ArrowRight style={{ width: 11, height: 11, color: '#1e2d4a', flexShrink: 0 }} />
                      <span style={{ fontFamily: 'monospace', fontSize: '10px', color: '#6b7a99' }}>
                        {incident.dest_ip || '—'}
                      </span>
                    </div>
                  )}

                  {/* MITRE techniques */}
                  {(incident.mitre_techniques?.length ?? 0) > 0 && (
                    <div style={{ display: 'flex', flexWrap: 'wrap', gap: 4, marginBottom: 6 }}>
                      {incident.mitre_techniques!.slice(0, 4).map((t) => (
                        <MitreBadge key={t} technique={t} />
                      ))}
                    </div>
                  )}

                  {/* Confidence bar + timestamp */}
                  <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginTop: 2 }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: 6, flex: 1, maxWidth: 140 }}>
                      <div style={{ flex: 1, height: 3, borderRadius: 999, background: '#1e2d4a', overflow: 'hidden' }}>
                        <div style={{
                          height: '100%',
                          borderRadius: 999,
                          width: `${Math.round((incident.confidence || 0) * 100)}%`,
                          background: (incident.confidence || 0) > 0.8 ? '#ff3b6b' : '#00d4ff',
                          transition: 'width 0.5s',
                        }} />
                      </div>
                      <span style={{ fontFamily: 'monospace', fontSize: '10px', color: '#6b7a99' }}>
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
        )}
      </div>
    </div>
  )
}
