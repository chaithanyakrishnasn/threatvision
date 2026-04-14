'use client'

import { useState } from 'react'
import { motion, AnimatePresence } from 'framer-motion'
import { ChevronDown, CheckCircle2, Clock, Circle, Terminal, Copy, Check, Zap, BookOpen, Loader2, RefreshCw } from 'lucide-react'
import { SeverityBadge } from './SeverityBadge'
import { playbooksApi } from '@/lib/api'
import type { Playbook, Incident } from '@/types'

interface Props {
  playbook?: Playbook | null
  incident?: Partial<Incident> | null
  onGeneratePlaybook?: (pb: Playbook) => void
}

function CopyButton({ text }: { text: string }) {
  const [copied, setCopied] = useState(false)
  const copy = async () => {
    await navigator.clipboard.writeText(text)
    setCopied(true)
    setTimeout(() => setCopied(false), 2000)
  }
  return (
    <button
      onClick={copy}
      className="p-1 rounded transition-colors"
      style={{ color: copied ? '#00ff9d' : '#6b7a99' }}
      title="Copy command"
    >
      {copied ? <Check className="w-3 h-3" /> : <Copy className="w-3 h-3" />}
    </button>
  )
}

export function PlaybookViewer({ playbook, incident, onGeneratePlaybook }: Props) {
  const [expandedPhase, setExpandedPhase] = useState<number | null>(0)
  const [generating, setGenerating] = useState(false)
  const [quickResponse, setQuickResponse] = useState<string[]>([])
  const [showQuickModal, setShowQuickModal] = useState(false)
  const [loadingQuick, setLoadingQuick] = useState(false)

  const handleGenerate = async () => {
    if (!incident?.id) return
    setGenerating(true)
    try {
      const pb = await playbooksApi.generate(incident.id)
      onGeneratePlaybook?.(pb)
    } catch {
      // fallback — show demo playbook
    } finally {
      setGenerating(false)
    }
  }

  if (!playbook) {
    return (
      <div className="flex flex-col items-center justify-center h-full min-h-[200px] text-center px-4" style={{ color: '#6b7a99' }}>
        <BookOpen className="w-10 h-10 mb-3 opacity-30" />
        <p className="text-sm font-medium mb-1" style={{ color: '#e8eaf0' }}>No Incident Selected</p>
        <p className="text-xs">Click an incident to view its response playbook</p>
        {incident && (
          <button
            onClick={handleGenerate}
            disabled={generating}
            className="mt-4 flex items-center gap-2 text-xs px-4 py-2 rounded-lg font-semibold transition-all"
            style={{ background: 'rgba(0,212,255,0.15)', color: '#00d4ff', border: '1px solid rgba(0,212,255,0.3)' }}
          >
            {generating ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <Zap className="w-3.5 h-3.5" />}
            Generate Playbook
          </button>
        )}
      </div>
    )
  }

  return (
    <div className="flex flex-col h-full">
      {/* Header */}
      <div
        className="p-3 rounded-t-lg border-b flex items-start justify-between gap-2"
        style={{ background: '#0f1629', borderColor: '#1e2d4a' }}
      >
        <div className="flex-1 min-w-0">
          <p className="text-xs font-bold uppercase tracking-wider mb-1" style={{ color: '#6b7a99' }}>Response Playbook</p>
          <p className="text-sm font-semibold leading-tight" style={{ color: '#e8eaf0' }}>{playbook.name}</p>
          {(playbook as any).estimated_time_minutes && (
            <p className="text-[10px] mt-1" style={{ color: '#6b7a99' }}>
              Est. {(playbook as any).estimated_time_minutes} min
            </p>
          )}
        </div>
        <SeverityBadge severity={playbook.priority || 'high'} />
      </div>

      {/* Action buttons */}
      <div className="flex gap-2 p-3" style={{ borderBottom: '1px solid #1e2d4a' }}>
        {incident && (
          <button
            onClick={handleGenerate}
            disabled={generating}
            className="flex-1 flex items-center justify-center gap-1.5 text-xs py-1.5 rounded-lg font-semibold transition-all"
            style={{ background: 'rgba(0,212,255,0.12)', color: '#00d4ff', border: '1px solid rgba(0,212,255,0.25)' }}
          >
            {generating ? <Loader2 className="w-3 h-3 animate-spin" /> : <Zap className="w-3 h-3" />}
            Regenerate
          </button>
        )}
        <button
          onClick={async () => {
            setShowQuickModal(true)
            if (quickResponse.length === 0) {
              setLoadingQuick(true)
              try {
                const threatType = (incident as any)?.threat_type || playbook?.name?.toLowerCase().replace(/\s+/g, '_') || 'general'
                const result = await playbooksApi.getQuickResponse(threatType)
                setQuickResponse(result.commands || [])
              } catch {
                // keep empty — modal shows "no commands" message
              } finally {
                setLoadingQuick(false)
              }
            }
          }}
          className="flex-1 flex items-center justify-center gap-1.5 text-xs py-1.5 rounded-lg font-semibold transition-all"
          style={{ background: 'rgba(255,184,0,0.12)', color: '#ffb800', border: '1px solid rgba(255,184,0,0.25)' }}
        >
          <Zap className="w-3 h-3" />
          Quick Response
        </button>
      </div>

      {/* Phases accordion */}
      <div className="flex-1 overflow-y-auto divide-y" style={{ borderColor: '#1e2d4a' }}>
        {playbook.phases.map((phase, phaseIdx) => (
          <div key={phaseIdx}>
            <button
              onClick={() => setExpandedPhase(expandedPhase === phaseIdx ? null : phaseIdx)}
              className="w-full flex items-center justify-between px-3 py-2.5 transition-colors"
              style={{ color: '#e8eaf0' }}
              onMouseOver={(e) => (e.currentTarget.style.background = '#1a2540')}
              onMouseOut={(e) => (e.currentTarget.style.background = 'transparent')}
            >
              <span className="text-xs font-semibold uppercase tracking-wider">
                {phase.name || (phase as any).phase_name}
              </span>
              <div className="flex items-center gap-2">
                <span className="text-[10px]" style={{ color: '#6b7a99' }}>
                  {phase.steps.length} steps
                </span>
                <ChevronDown
                  className="w-3.5 h-3.5 transition-transform"
                  style={{
                    color: '#6b7a99',
                    transform: expandedPhase === phaseIdx ? 'rotate(180deg)' : 'rotate(0deg)',
                  }}
                />
              </div>
            </button>

            <AnimatePresence>
              {expandedPhase === phaseIdx && (
                <motion.div
                  initial={{ height: 0, opacity: 0 }}
                  animate={{ height: 'auto', opacity: 1 }}
                  exit={{ height: 0, opacity: 0 }}
                  transition={{ duration: 0.2 }}
                  className="overflow-hidden"
                >
                  <div className="px-3 pb-3 space-y-3">
                    {phase.steps.map((step: any, stepIdx: number) => (
                      <div
                        key={stepIdx}
                        className="flex items-start gap-2.5 text-xs"
                      >
                        <div className="flex-shrink-0 mt-0.5">
                          {step.status === 'executed' || step.status === 'done'
                            ? <CheckCircle2 className="w-3.5 h-3.5" style={{ color: '#00ff9d' }} />
                            : step.status === 'awaiting_approval' || step.status === 'pending'
                            ? <Clock className="w-3.5 h-3.5" style={{ color: '#ffb800' }} />
                            : <Circle className="w-3.5 h-3.5" style={{ color: '#1e2d4a' }} />
                          }
                        </div>
                        <div className="flex-1 min-w-0">
                          <p className="font-semibold mb-0.5" style={{ color: '#e8eaf0' }}>
                            {step.title || step.action}
                          </p>
                          {(step.description || step.notes) && (
                            <p className="text-[10px] mb-1" style={{ color: '#6b7a99' }}>
                              {step.description || step.notes}
                            </p>
                          )}
                          {/* Commands */}
                          {(step.commands || (step.command ? [step.command] : [])).filter(Boolean).map((cmd: string, ci: number) => (
                            <div
                              key={ci}
                              className="flex items-center gap-2 mt-1.5 px-2 py-1.5 rounded"
                              style={{ background: '#050810', border: '1px solid #1e2d4a' }}
                            >
                              <Terminal className="w-3 h-3 flex-shrink-0" style={{ color: '#00d4ff' }} />
                              <code
                                className="flex-1 text-[10px] break-all"
                                style={{ fontFamily: 'JetBrains Mono, monospace', color: '#00ff9d' }}
                              >
                                {cmd}
                              </code>
                              <CopyButton text={cmd} />
                            </div>
                          ))}
                        </div>
                      </div>
                    ))}
                  </div>
                </motion.div>
              )}
            </AnimatePresence>
          </div>
        ))}
      </div>

      {/* IOCs */}
      {playbook.iocs_to_hunt?.length > 0 && (
        <div className="p-3" style={{ borderTop: '1px solid #1e2d4a' }}>
          <p className="text-[10px] uppercase tracking-wider mb-1.5 font-semibold" style={{ color: '#6b7a99' }}>IOCs to Hunt</p>
          <div className="flex flex-wrap gap-1">
            {playbook.iocs_to_hunt.filter(Boolean).map((ioc, i) => (
              <span
                key={i}
                className="font-mono text-[10px] px-1.5 py-0.5 rounded"
                style={{ color: '#ffb800', background: 'rgba(255,184,0,0.1)', border: '1px solid rgba(255,184,0,0.2)' }}
              >
                {ioc}
              </span>
            ))}
          </div>
        </div>
      )}

      {/* Quick Response Modal */}
      <AnimatePresence>
        {showQuickModal && (
          <motion.div
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            exit={{ opacity: 0 }}
            className="fixed inset-0 z-50 flex items-center justify-center"
            style={{ background: 'rgba(0,0,0,0.7)' }}
            onClick={() => setShowQuickModal(false)}
          >
            <motion.div
              initial={{ scale: 0.9, y: 20 }}
              animate={{ scale: 1, y: 0 }}
              exit={{ scale: 0.9, y: 20 }}
              className="rounded-xl p-6 max-w-md w-full mx-4"
              style={{ background: '#141d35', border: '1px solid #1e2d4a' }}
              onClick={(e) => e.stopPropagation()}
            >
              <h3 className="text-sm font-bold mb-3" style={{ color: '#ffb800' }}>
                ⚡ Quick Response Commands
              </h3>
              {loadingQuick ? (
                <div className="flex items-center justify-center py-6" style={{ color: '#6b7a99' }}>
                  <RefreshCw className="w-4 h-4 animate-spin mr-2" />
                  <span className="text-xs">Loading commands…</span>
                </div>
              ) : quickResponse.length === 0 ? (
                <p className="text-xs text-center py-4" style={{ color: '#6b7a99' }}>
                  No commands available for this threat type.
                </p>
              ) : (
                <div className="space-y-2">
                  {quickResponse.map((cmd, i) => (
                    <div
                      key={i}
                      className="flex items-center gap-2 px-3 py-2 rounded"
                      style={{ background: '#050810', border: '1px solid #1e2d4a' }}
                    >
                      <Terminal className="w-3 h-3 flex-shrink-0" style={{ color: '#00d4ff' }} />
                      <code className="flex-1 text-[10px]" style={{ fontFamily: 'JetBrains Mono, monospace', color: '#00ff9d' }}>
                        {cmd}
                      </code>
                      <CopyButton text={cmd} />
                    </div>
                  ))}
                </div>
              )}
              <button
                onClick={() => setShowQuickModal(false)}
                className="mt-4 w-full text-xs py-2 rounded-lg font-semibold"
                style={{ background: '#1e2d4a', color: '#6b7a99' }}
              >
                Close
              </button>
            </motion.div>
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  )
}
