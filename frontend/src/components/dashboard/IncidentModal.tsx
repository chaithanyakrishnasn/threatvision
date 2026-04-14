'use client'

import { useEffect, useState } from 'react'
import { playbooksApi } from '@/lib/api'
import type { Incident, IncidentWithClassification } from '@/types'

// Fields beyond base Incident arrive at runtime from the enriched backend response.
// We accept the base Partial<Incident> type at the boundary and cast internally.
type ModalIncident = Partial<IncidentWithClassification>

interface Props {
  incident: Partial<Incident>   // accepts what the page stores
  onClose: () => void
}

const SEV_COLOR = (s = '') => {
  const u = s.toUpperCase()
  if (u === 'CRITICAL') return '#ff3b6b'
  if (u === 'HIGH')     return '#ff8c00'
  if (u === 'MEDIUM')   return '#ffb800'
  return '#00ff9d'
}

// ── IncidentModal ─────────────────────────────────────────────────────────────

export function IncidentModal({ incident: _incident, onClose }: Props) {
  // Cast to extended type — runtime data includes all classification fields
  const incident = _incident as ModalIncident

  // Close on Escape
  useEffect(() => {
    const h = (e: KeyboardEvent) => { if (e.key === 'Escape') onClose() }
    window.addEventListener('keydown', h)
    return () => window.removeEventListener('keydown', h)
  }, [onClose])

  const sevColor = SEV_COLOR(incident.severity)
  const sev = (incident.severity || 'LOW').toUpperCase()
  const threatLabel = (incident.threat_type || incident.title || 'Unknown Threat')
    .replace(/_/g, ' ').toUpperCase()
  const isFP = incident.is_false_positive ?? false

  return (
    <div
      onClick={onClose}
      style={{
        position: 'fixed', inset: 0,
        background: 'rgba(0,0,0,0.85)',
        zIndex: 1000,
        display: 'flex', alignItems: 'center', justifyContent: 'center',
        padding: '20px',
      }}
    >
      <div
        onClick={(e) => e.stopPropagation()}
        style={{
          background: '#0f1629',
          border: '1px solid #1e2d4a',
          borderRadius: '12px',
          width: '780px',
          maxWidth: '95vw',
          height: '85vh',
          display: 'flex',
          flexDirection: 'column',
          overflow: 'hidden',
        }}
      >
        {/* ── FIXED HEADER ────────────────────────────────────────────────── */}
        <div style={{
          display: 'flex', alignItems: 'center', justifyContent: 'space-between',
          padding: '13px 20px',
          borderBottom: '1px solid #1e2d4a',
          flexShrink: 0,
          background: '#0a0e1a',
          gap: 12,
        }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 10, minWidth: 0 }}>
            <span style={{
              background: sevColor, color: '#0a0e1a',
              fontSize: 10, fontWeight: 700,
              padding: '3px 8px', borderRadius: 4, flexShrink: 0,
            }}>{sev}</span>
            <span style={{
              color: '#e8eaf0', fontWeight: 600, fontSize: 13,
              whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis',
            }}>
              {threatLabel}
            </span>
            {(incident.source_ip || incident.dest_ip) && (
              <span style={{ color: '#6b7a99', fontSize: 12, fontFamily: 'monospace', flexShrink: 0 }}>
                {incident.source_ip}{incident.dest_ip ? ` → ${incident.dest_ip}` : ''}
              </span>
            )}
          </div>
          <button
            onClick={onClose}
            style={{
              background: 'none', border: '1px solid #1e2d4a',
              color: '#6b7a99', fontSize: 16,
              cursor: 'pointer', padding: '4px 10px',
              borderRadius: 6, flexShrink: 0,
            }}
            onMouseOver={(e) => { e.currentTarget.style.color = '#e8eaf0'; e.currentTarget.style.borderColor = '#6b7a99' }}
            onMouseOut={(e)  => { e.currentTarget.style.color = '#6b7a99'; e.currentTarget.style.borderColor = '#1e2d4a' }}
          >✕</button>
        </div>

        {/* ── SCROLLABLE BODY ──────────────────────────────────────────────── */}
        <div style={{
          flex: 1,
          overflowY: 'auto',
          minHeight: 0,
          padding: '18px 20px',
          display: 'flex',
          flexDirection: 'column',
          gap: 12,
        }}>

          {/* WHY WAS THIS FLAGGED? */}
          <Row>
            <RowHeader>
              <span style={{ color: '#00d4ff', fontSize: 13, fontWeight: 600 }}>
                🧠 WHY WAS THIS FLAGGED?
              </span>
              <Pill bg={isFP ? 'rgba(107,122,153,0.2)' : 'rgba(255,59,107,0.15)'}
                    border={isFP ? '#6b7a99' : '#ff3b6b'}
                    color={isFP ? '#6b7a99' : '#ff3b6b'}>
                {isFP ? 'FALSE POSITIVE' : 'GENUINE THREAT'}
              </Pill>
            </RowHeader>
          </Row>

          {/* Explanation text */}
          {incident.explanation && (
            <Row>
              <p style={{ color: '#e8eaf0', fontSize: 13, lineHeight: 1.7, margin: 0 }}>
                {incident.explanation}
              </p>
            </Row>
          )}

          {/* Rule Engine */}
          <Row>
            <SectionLabel color="#ff3b6b">🛡 RULE ENGINE (70% WEIGHT)</SectionLabel>
            {(incident.rule_matches?.length ?? 0) === 0 ? (
              <Muted>No rules matched — anomaly-driven detection</Muted>
            ) : (
              incident.rule_matches!.map((r) => (
                <div key={r} style={{ fontSize: 13, marginBottom: 4 }}>
                  <span style={{ color: '#6b7a99' }}>›</span>
                  <span style={{ fontFamily: 'monospace', color: '#00d4ff', marginLeft: 6 }}>{r}</span>
                  <span style={{ color: '#00ff9d', marginLeft: 8, fontSize: 11 }}>✓ matched</span>
                </div>
              ))
            )}
          </Row>

          {/* Anomaly Score */}
          <Row>
            <SectionLabel color="#00d4ff">🤖 ANOMALY SCORE (30% WEIGHT)</SectionLabel>
            <AnomalyBar score={incident.anomaly_score ?? 0} />
            <Muted style={{ marginTop: 5 }}>IsolationForest ML model · confidence {Math.round((incident.confidence ?? 0) * 100)}%</Muted>
          </Row>

          {/* MITRE ATT&CK */}
          <Row>
            <SectionLabel color="#a78bfa">🎯 MITRE ATT&amp;CK</SectionLabel>
            <div style={{ display: 'flex', flexWrap: 'wrap', gap: 6 }}>
              {(incident.mitre_tactics ?? []).map((t) => (
                <span key={t} style={{
                  background: 'rgba(167,139,250,0.15)', border: '1px solid rgba(167,139,250,0.35)',
                  color: '#a78bfa', fontSize: 11, padding: '3px 10px', borderRadius: 12,
                }}>{t.split(' - ')[0]}</span>
              ))}
              {(incident.mitre_techniques ?? []).map((t) => (
                <span key={t} style={{
                  background: 'rgba(83,74,183,0.2)', border: '1px solid #534ab7',
                  color: '#afa9ec', fontSize: 11, padding: '3px 10px', borderRadius: 12,
                  fontFamily: 'monospace',
                }}>{t.split(' - ')[0]}</span>
              ))}
              {(incident.mitre_tactics?.length ?? 0) + (incident.mitre_techniques?.length ?? 0) === 0 && (
                <Muted>No MITRE techniques mapped</Muted>
              )}
            </div>
          </Row>

          {/* False Positive Check */}
          <Row>
            <SectionLabel color="#00ff9d">✅ FALSE POSITIVE CHECK</SectionLabel>
            {[
              { label: 'Known asset?',             pass: !isFP },
              { label: 'Internal destination?',    pass: incident.dest_ip?.startsWith('10.') ?? false },
              { label: 'Cross-layer correlated?',  pass: incident.cross_layer_correlated ?? false },
            ].map(({ label, pass }) => (
              <div key={label} style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 4 }}>
                <span style={{ color: pass ? '#00ff9d' : '#ff3b6b', fontSize: 13, width: 14 }}>{pass ? '✓' : '✗'}</span>
                <span style={{ color: '#e8eaf0', fontSize: 12 }}>{label}</span>
                <span style={{ color: pass ? '#00ff9d' : '#ff3b6b', fontFamily: 'monospace', fontSize: 11, marginLeft: 'auto', fontWeight: 700 }}>
                  {pass ? 'YES' : 'NO'}
                </span>
              </div>
            ))}
            <div style={{
              marginTop: 10, paddingTop: 8,
              borderTop: '1px solid #1e2d4a',
              color: isFP ? '#6b7a99' : '#ff3b6b',
              fontWeight: 700, fontSize: 13,
            }}>
              → Verdict: {isFP ? 'FALSE POSITIVE — Suppressed' : 'GENUINE THREAT — Action required'}
            </div>
          </Row>

          {/* Recommended Action */}
          {incident.recommended_action && (
            <Row>
              <SectionLabel color="#ffb800">📋 RECOMMENDED ACTION</SectionLabel>
              <p style={{ color: '#e8eaf0', fontSize: 13, margin: 0, lineHeight: 1.7 }}>
                {incident.recommended_action}
              </p>
            </Row>
          )}

          {/* Quick Response Commands */}
          <QuickResponseSection incident={incident} />

          {/* divider */}
          <div style={{ borderTop: '1px solid #1e2d4a' }} />

          {/* Generate AI Playbook — inline */}
          <GeneratePlaybookSection incident={incident} />

        </div>
      </div>
    </div>
  )
}

// ── Small layout helpers ──────────────────────────────────────────────────────

function Row({ children }: { children: React.ReactNode }) {
  return (
    <div style={{
      background: '#141d35', border: '1px solid #1e2d4a',
      borderRadius: 8, padding: '13px 16px',
    }}>
      {children}
    </div>
  )
}

function RowHeader({ children }: { children: React.ReactNode }) {
  return (
    <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
      {children}
    </div>
  )
}

function SectionLabel({ children, color }: { children: React.ReactNode; color: string }) {
  return (
    <div style={{ color, fontSize: 12, fontWeight: 600, marginBottom: 10 }}>
      {children}
    </div>
  )
}

function Pill({ children, bg, border, color }: { children: React.ReactNode; bg: string; border: string; color: string }) {
  return (
    <span style={{
      background: bg, border: `1px solid ${border}`, color,
      fontSize: 10, fontWeight: 700, padding: '3px 10px',
      borderRadius: 4, letterSpacing: '0.05em',
    }}>{children}</span>
  )
}

function Muted({ children, style }: { children: React.ReactNode; style?: React.CSSProperties }) {
  return <span style={{ color: '#6b7a99', fontSize: 12, ...style }}>{children}</span>
}

function AnomalyBar({ score }: { score: number }) {
  const pct = Math.round(score * 100)
  const label =
    score >= 0.9 ? 'Highly anomalous — top 2%' :
    score >= 0.7 ? 'Moderately anomalous — top 15%' :
    score >= 0.5 ? 'Somewhat anomalous' : 'Within baseline range'

  return (
    <div>
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 6 }}>
        <span style={{ color: score >= 0.7 ? '#ff3b6b' : '#ffb800', fontWeight: 700, fontSize: 18, fontFamily: 'monospace' }}>
          {pct} / 100
        </span>
        <Muted>{label}</Muted>
      </div>
      <div style={{ background: '#0a0e1a', borderRadius: 4, height: 10, overflow: 'hidden' }}>
        <div style={{
          width: `${pct}%`, height: '100%',
          background: 'linear-gradient(90deg, #00d4ff, #ff3b6b)',
          transition: 'width 0.6s ease',
        }} />
      </div>
    </div>
  )
}

// ── Quick Response Commands ───────────────────────────────────────────────────

function QuickResponseSection({ incident }: { incident: ModalIncident }) {
  const [commands, setCommands] = useState<string[]>([])
  const [loading, setLoading] = useState(true)
  const [copied, setCopied] = useState<number | null>(null)

  useEffect(() => {
    if (!incident.threat_type) { setLoading(false); return }
    playbooksApi.getQuickResponse(incident.threat_type)
      .then((d) => setCommands(d.commands || []))
      .catch(() => setCommands([]))
      .finally(() => setLoading(false))
  }, [incident.threat_type])

  const copy = (cmd: string, i: number) => {
    navigator.clipboard.writeText(cmd)
    setCopied(i)
    setTimeout(() => setCopied(null), 1800)
  }

  const resolve = (cmd: string) =>
    cmd
      .replace(/\{source_ip\}/g, incident.source_ip ?? 'SOURCE_IP')
      .replace(/\{dest_ip\}/g, incident.dest_ip ?? 'DEST_IP')
      .replace(/\{username\}/g, 'compromised_user')
      .replace(/\{port\}/g, '443')

  return (
    <Row>
      <SectionLabel color="#00d4ff">⚡ QUICK RESPONSE COMMANDS</SectionLabel>
      {loading ? (
        <Muted>Loading commands...</Muted>
      ) : commands.length === 0 ? (
        <Muted>No commands available for this threat type.</Muted>
      ) : (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
          {commands.map((cmd, i) => {
            const isComment = cmd.startsWith('#')
            return (
              <div key={i} style={{
                background: isComment ? 'transparent' : '#0a0e1a',
                border: isComment ? 'none' : '1px solid #1e2d4a',
                borderRadius: isComment ? 0 : 4,
                padding: isComment ? '1px 2px' : '7px 12px',
                fontFamily: 'monospace', fontSize: 12,
                color: isComment ? '#6b7a99' : '#00ff9d',
                display: 'flex', justifyContent: 'space-between', alignItems: 'center',
              }}>
                <span style={{ flex: 1, wordBreak: 'break-all' }}>{resolve(cmd)}</span>
                {!isComment && (
                  <button
                    onClick={() => copy(cmd, i)}
                    style={{
                      background: 'none', border: '1px solid #1e2d4a',
                      color: copied === i ? '#00ff9d' : '#6b7a99',
                      cursor: 'pointer', fontSize: 10,
                      padding: '2px 7px', borderRadius: 3,
                      flexShrink: 0, marginLeft: 8,
                    }}
                  >{copied === i ? 'copied!' : 'copy'}</button>
                )}
              </div>
            )
          })}
        </div>
      )}
    </Row>
  )
}

// ── Generate AI Playbook — inline, no separate card ───────────────────────────

const PHASE_COLORS: Record<string, string> = {
  Containment:      '#ff3b6b',
  Eradication:      '#ffb800',
  Recovery:         '#00d4ff',
  'Lessons Learned': '#00ff9d',
}

function GeneratePlaybookSection({ incident }: { incident: ModalIncident }) {
  const [playbook, setPlaybook] = useState<any>(null)
  const [generating, setGenerating] = useState(false)
  const [error, setError] = useState('')

  const generate = async () => {
    if (!incident.threat_type) return
    setGenerating(true)
    setError('')
    try {
      const result = await playbooksApi.generateForThreat(
        incident.threat_type,
        incident.severity ?? 'high',
        [incident.source_ip, incident.dest_ip].filter(Boolean) as string[],
      )
      setPlaybook(result)
    } catch {
      setError('Failed to generate playbook — try again.')
    } finally {
      setGenerating(false)
    }
  }

  return (
    <Row>
      {/* Section header + button */}
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: playbook ? 16 : 0 }}>
        <SectionLabel color="#00d4ff" >📖 AI RESPONSE PLAYBOOK</SectionLabel>
        {!playbook && (
          <button
            onClick={generate}
            disabled={generating}
            style={{
              background: generating ? 'rgba(0,212,255,0.08)' : 'rgba(0,212,255,0.15)',
              border: '1px solid rgba(0,212,255,0.4)',
              color: generating ? '#6b7a99' : '#00d4ff',
              fontSize: 12, fontWeight: 600,
              padding: '7px 16px', borderRadius: 6,
              cursor: generating ? 'not-allowed' : 'pointer',
              display: 'flex', alignItems: 'center', gap: 7,
              transition: 'all 0.15s',
            }}
          >
            {generating ? (
              <>
                <span style={{
                  width: 10, height: 10,
                  border: '2px solid #1e2d4a',
                  borderTopColor: '#00d4ff',
                  borderRadius: '50%', display: 'inline-block',
                  animation: 'modal-spin 0.8s linear infinite',
                }} />
                Generating...
              </>
            ) : (
              <>⚡ Generate AI Playbook</>
            )}
          </button>
        )}
        {playbook && (
          <button
            onClick={() => setPlaybook(null)}
            style={{
              background: 'none', border: '1px solid #1e2d4a',
              color: '#6b7a99', fontSize: 11,
              padding: '4px 10px', borderRadius: 4, cursor: 'pointer',
            }}
          >regenerate</button>
        )}
      </div>

      {error && (
        <div style={{ color: '#ff3b6b', fontSize: 12, marginTop: 6 }}>{error}</div>
      )}

      {/* Playbook renders inline */}
      {playbook && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
          {/* Meta row */}
          <div style={{
            display: 'flex', gap: 16, flexWrap: 'wrap',
            background: '#0a0e1a', borderRadius: 6, padding: '8px 12px',
          }}>
            {playbook.estimated_time_minutes && (
              <span style={{ color: '#6b7a99', fontSize: 12 }}>
                Est. time: <span style={{ color: '#e8eaf0' }}>{playbook.estimated_time_minutes} min</span>
              </span>
            )}
            {(playbook.required_tools?.length ?? 0) > 0 && (
              <span style={{ color: '#6b7a99', fontSize: 12 }}>
                Tools: <span style={{ color: '#e8eaf0' }}>{playbook.required_tools.join(', ')}</span>
              </span>
            )}
          </div>

          {/* Phases */}
          {(playbook.phases ?? []).map((phase: any, pi: number) => {
            const phaseName: string = phase.phase_name ?? phase.name ?? `Phase ${pi + 1}`
            const phaseColor = PHASE_COLORS[phaseName] ?? '#00d4ff'
            return (
              <div key={pi} style={{
                borderLeft: `3px solid ${phaseColor}`,
                border: `1px solid ${phaseColor}30`,
                borderRadius: 6, overflow: 'hidden',
              }}>
                <div style={{
                  background: `${phaseColor}12`,
                  padding: '8px 14px',
                  display: 'flex', alignItems: 'center', gap: 8,
                }}>
                  <span style={{ color: phaseColor, fontWeight: 700, fontSize: 12 }}>
                    {pi + 1}. {phaseName.toUpperCase()}
                  </span>
                  <span style={{ color: '#6b7a99', fontSize: 11 }}>
                    {(phase.steps ?? []).length} steps
                  </span>
                </div>

                <div style={{ padding: '10px 14px', display: 'flex', flexDirection: 'column', gap: 10 }}>
                  {(phase.steps ?? []).map((step: any, si: number) => (
                    <div key={si}>
                      <div style={{ color: '#e8eaf0', fontSize: 13, fontWeight: 500, marginBottom: 3 }}>
                        {si + 1}. {step.title ?? step.action}
                      </div>
                      {(step.description ?? step.notes) && (
                        <div style={{ color: '#6b7a99', fontSize: 12, lineHeight: 1.5, marginBottom: 5 }}>
                          {step.description ?? step.notes}
                        </div>
                      )}
                      {(step.commands ?? (step.command ? [step.command] : [])).filter(Boolean).map((cmd: string, ci: number) => (
                        <CmdLine key={ci} cmd={cmd} />
                      ))}
                    </div>
                  ))}
                </div>
              </div>
            )
          })}

          {/* Success criteria */}
          {(playbook.success_criteria?.length ?? 0) > 0 && (
            <div style={{
              background: 'rgba(0,255,157,0.05)',
              border: '1px solid rgba(0,255,157,0.2)',
              borderRadius: 6, padding: '12px 14px',
            }}>
              <div style={{ color: '#00ff9d', fontSize: 12, fontWeight: 600, marginBottom: 8 }}>
                ✅ SUCCESS CRITERIA
              </div>
              {(playbook.success_criteria as string[]).map((c, i) => (
                <div key={i} style={{ color: '#e8eaf0', fontSize: 12, marginBottom: 4 }}>› {c}</div>
              ))}
            </div>
          )}

          {/* IOCs */}
          {(playbook.iocs_to_hunt?.length ?? 0) > 0 && (
            <div style={{
              background: 'rgba(255,184,0,0.05)',
              border: '1px solid rgba(255,184,0,0.2)',
              borderRadius: 6, padding: '12px 14px',
            }}>
              <div style={{ color: '#ffb800', fontSize: 12, fontWeight: 600, marginBottom: 8 }}>
                🔍 IOCs TO HUNT
              </div>
              <div style={{ display: 'flex', flexWrap: 'wrap', gap: 6 }}>
                {(playbook.iocs_to_hunt as string[]).filter(Boolean).map((ioc, i) => (
                  <span key={i} style={{
                    fontFamily: 'monospace', fontSize: 11,
                    padding: '2px 8px', borderRadius: 4,
                    color: '#ffb800', background: 'rgba(255,184,0,0.1)',
                    border: '1px solid rgba(255,184,0,0.2)',
                  }}>{ioc}</span>
                ))}
              </div>
            </div>
          )}
        </div>
      )}

      {/* Spinner keyframe */}
      <style>{`@keyframes modal-spin { to { transform: rotate(360deg); } }`}</style>
    </Row>
  )
}

// ── Command line with copy button ─────────────────────────────────────────────

function CmdLine({ cmd }: { cmd: string }) {
  const [copied, setCopied] = useState(false)
  const isComment = cmd.startsWith('#')

  return (
    <div style={{
      background: isComment ? 'transparent' : '#0a0e1a',
      border: isComment ? 'none' : '1px solid #1e2d4a',
      borderRadius: isComment ? 0 : 4,
      padding: isComment ? '1px 2px' : '6px 10px',
      fontFamily: 'monospace', fontSize: 11,
      color: isComment ? '#6b7a99' : '#00ff9d',
      display: 'flex', justifyContent: 'space-between', alignItems: 'center',
      marginBottom: 3,
    }}>
      <span style={{ flex: 1, wordBreak: 'break-all' }}>{cmd}</span>
      {!isComment && (
        <button
          onClick={() => { navigator.clipboard.writeText(cmd); setCopied(true); setTimeout(() => setCopied(false), 1800) }}
          style={{
            background: 'none', border: 'none',
            color: copied ? '#00ff9d' : '#6b7a99',
            cursor: 'pointer', fontSize: 10,
            flexShrink: 0, marginLeft: 6,
          }}
        >{copied ? 'copied!' : 'copy'}</button>
      )}
    </div>
  )
}
