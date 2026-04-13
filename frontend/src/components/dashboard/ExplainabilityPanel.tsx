'use client'

import { useState } from 'react'
import { motion, AnimatePresence } from 'framer-motion'
import { Brain, Shield, AlertTriangle, ChevronRight, Loader2, CheckCircle2, XCircle, Sparkles } from 'lucide-react'
import { playbooksApi } from '@/lib/api'

interface Incident {
  id: string
  threat_type?: string | null
  severity?: string
  source_ip?: string | null
  dest_ip?: string | null
  confidence?: number
  explanation?: string | null
  mitre_techniques?: string[]
  mitre_tactics?: string[]
  rule_matches?: string[]
  is_false_positive?: boolean
  anomaly_score?: number
  cross_layer_correlated?: boolean
  recommended_action?: string | null
  [key: string]: unknown
}

interface AiAnalysis {
  what_happened: string
  why_suspicious: string
  false_positive_likelihood: string
  false_positive_reason: string | null
  recommended_action: string
  confidence_explanation: string
}

interface Props {
  incident: Partial<Incident> | null
}

function AnomalyBar({ score }: { score: number }) {
  const pct = Math.round(score * 100)
  const label =
    score >= 0.9 ? 'Highly anomalous — top 2%' :
    score >= 0.7 ? 'Significantly anomalous — top 15%' :
    score >= 0.5 ? 'Moderately anomalous' :
    'Within baseline range'

  return (
    <div className="space-y-1.5">
      <div className="flex items-center justify-between">
        <span className="font-mono text-xs font-bold" style={{ color: score >= 0.7 ? '#ff3b6b' : '#ffb800' }}>
          {pct} / 100
        </span>
        <span className="text-[10px]" style={{ color: '#6b7a99' }}>{label}</span>
      </div>
      <div className="h-2 rounded-full overflow-hidden" style={{ background: '#0f1629' }}>
        <motion.div
          initial={{ width: 0 }}
          animate={{ width: `${pct}%` }}
          transition={{ duration: 0.8, ease: 'easeOut' }}
          className="h-full rounded-full"
          style={{
            background: `linear-gradient(90deg, #00d4ff ${100 - pct}%, #ff3b6b)`,
          }}
        />
      </div>
    </div>
  )
}

function Section({
  icon, title, accentColor, children,
}: {
  icon: React.ReactNode
  title: string
  accentColor: string
  children: React.ReactNode
}) {
  return (
    <div
      className="rounded-lg p-3 space-y-2"
      style={{ background: '#0f1629', border: '1px solid #1e2d4a' }}
    >
      <div className="flex items-center gap-2">
        <span style={{ color: accentColor }}>{icon}</span>
        <span className="text-xs font-bold uppercase tracking-wider" style={{ color: accentColor }}>
          {title}
        </span>
      </div>
      {children}
    </div>
  )
}

export function ExplainabilityPanel({ incident }: Props) {
  const [aiAnalysis, setAiAnalysis] = useState<AiAnalysis | null>(null)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)

  if (!incident) {
    return (
      <div
        className="rounded-xl p-6 flex flex-col items-center justify-center text-center"
        style={{ background: '#141d35', border: '1px solid #1e2d4a', minHeight: 200 }}
      >
        <Shield className="w-8 h-8 mb-2 opacity-30" style={{ color: '#00d4ff' }} />
        <p className="text-sm" style={{ color: '#6b7a99' }}>
          Select an incident to see the AI explainability panel
        </p>
      </div>
    )
  }

  const ruleMatches = (incident.rule_matches as string[]) || []
  const techniques = (incident.mitre_techniques as string[]) || []
  const tactics = (incident.mitre_tactics as string[]) || []
  const isFP = incident.is_false_positive ?? false
  const anomaly = incident.anomaly_score ?? 0
  const confidence = incident.confidence ?? 0

  const handleGetAnalysis = async () => {
    setLoading(true)
    setError(null)
    try {
      const event: Record<string, unknown> = {
        source_ip: incident.source_ip,
        dest_ip: incident.dest_ip,
        threat_type: incident.threat_type,
        severity: incident.severity,
        flags: incident.rule_matches || [],
      }
      const classification: Record<string, unknown> = {
        threat_type: incident.threat_type,
        severity: incident.severity,
        confidence,
        mitre_techniques: techniques,
        mitre_tactics: tactics,
        rule_matches: ruleMatches,
        anomaly_score: anomaly,
        is_false_positive: isFP,
        explanation: incident.explanation,
        recommended_action: incident.recommended_action,
        cross_layer_correlated: incident.cross_layer_correlated,
      }
      const result = await playbooksApi.explain(event, classification)
      setAiAnalysis(result)
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : 'Failed to get AI analysis'
      setError(msg)
    } finally {
      setLoading(false)
    }
  }

  return (
    <motion.div
      initial={{ opacity: 0, y: 8 }}
      animate={{ opacity: 1, y: 0 }}
      className="rounded-xl overflow-hidden"
      style={{ background: '#141d35', border: '1px solid #1e2d4a' }}
    >
      {/* Header */}
      <div
        className="px-4 py-3 flex items-center justify-between"
        style={{ borderBottom: '1px solid #1e2d4a', background: '#0f1629' }}
      >
        <div className="flex items-center gap-2">
          <Brain className="w-4 h-4" style={{ color: '#00d4ff' }} />
          <span className="text-xs font-bold uppercase tracking-wider" style={{ color: '#00d4ff' }}>
            Why Was This Flagged?
          </span>
        </div>
        <span
          className="text-[10px] font-mono px-2 py-0.5 rounded"
          style={{
            color: isFP ? '#6b7a99' : '#ff3b6b',
            background: isFP ? 'rgba(107,122,153,0.1)' : 'rgba(255,59,107,0.1)',
          }}
        >
          {isFP ? 'FALSE POSITIVE' : 'GENUINE THREAT'}
        </span>
      </div>

      <div className="p-3 space-y-3">

        {/* Explanation */}
        {incident.explanation && (
          <div
            className="text-xs leading-relaxed p-3 rounded-lg"
            style={{ background: '#0f1629', color: '#b0bcd4', border: '1px solid #1e2d4a' }}
          >
            {incident.explanation}
          </div>
        )}

        {/* Rule Engine */}
        <Section icon={<Shield className="w-3.5 h-3.5" />} title="Rule Engine (70% weight)" accentColor="#ff3b6b">
          {ruleMatches.length > 0 ? (
            <div className="space-y-1">
              {ruleMatches.map((rule) => (
                <div key={rule} className="flex items-center gap-2">
                  <ChevronRight className="w-3 h-3" style={{ color: '#ff3b6b' }} />
                  <span className="font-mono text-[11px]" style={{ color: '#00d4ff' }}>{rule}</span>
                  <span className="text-[10px]" style={{ color: '#00ff9d' }}>✓ matched</span>
                </div>
              ))}
            </div>
          ) : (
            <span className="text-[11px]" style={{ color: '#6b7a99' }}>No rules fired — anomaly-driven detection</span>
          )}
        </Section>

        {/* Anomaly Score */}
        <Section icon={<Brain className="w-3.5 h-3.5" />} title="Anomaly Score (30% weight)" accentColor="#00d4ff">
          <AnomalyBar score={anomaly} />
          <div className="flex items-center justify-between text-[10px]" style={{ color: '#6b7a99' }}>
            <span>IsolationForest ML model</span>
            <span className="font-mono font-bold" style={{ color: '#e8eaf0' }}>
              confidence {Math.round(confidence * 100)}%
            </span>
          </div>
        </Section>

        {/* MITRE ATT&CK */}
        {(techniques.length > 0 || tactics.length > 0) && (
          <Section icon={<AlertTriangle className="w-3.5 h-3.5" />} title="MITRE ATT&CK" accentColor="#a78bfa">
            <div className="flex flex-wrap gap-1">
              {tactics.map((t) => (
                <span
                  key={t}
                  className="text-[10px] px-2 py-0.5 rounded-full font-semibold"
                  style={{ background: 'rgba(167,139,250,0.15)', color: '#a78bfa', border: '1px solid rgba(167,139,250,0.3)' }}
                >
                  {t.split(' - ')[0]}
                </span>
              ))}
              {techniques.map((t) => (
                <span
                  key={t}
                  className="text-[10px] px-2 py-0.5 rounded-full font-mono"
                  style={{ background: 'rgba(167,139,250,0.08)', color: '#c4b5fd', border: '1px solid rgba(167,139,250,0.2)' }}
                >
                  {t.split(' - ')[0]}
                </span>
              ))}
            </div>
          </Section>
        )}

        {/* False Positive Check */}
        <Section icon={<CheckCircle2 className="w-3.5 h-3.5" />} title="False Positive Check" accentColor="#00ff9d">
          <div className="space-y-1.5 text-xs">
            {[
              { label: 'Known asset?',     pass: !isFP },
              { label: 'Internal dest?',   pass: !incident.dest_ip?.startsWith('10.') && !isFP },
              { label: 'Business hours?',  pass: false },
              { label: 'Cross-layer correlated?', pass: incident.cross_layer_correlated ?? false },
            ].map(({ label, pass }) => (
              <div key={label} className="flex items-center gap-2">
                {pass
                  ? <XCircle className="w-3 h-3" style={{ color: '#ff3b6b' }} />
                  : <CheckCircle2 className="w-3 h-3" style={{ color: '#00ff9d' }} />
                }
                <span style={{ color: '#b0bcd4' }}>{label}</span>
                <span
                  className="ml-auto font-mono text-[10px] font-bold"
                  style={{ color: pass ? '#ff3b6b' : '#00ff9d' }}
                >
                  {pass ? 'YES' : 'NO'}
                </span>
              </div>
            ))}
            <div
              className="mt-2 pt-2 flex items-center gap-2 font-bold text-xs"
              style={{ borderTop: '1px solid #1e2d4a' }}
            >
              <span style={{ color: '#6b7a99' }}>→ Verdict:</span>
              <span style={{ color: isFP ? '#6b7a99' : '#ff3b6b' }}>
                {isFP ? 'FALSE POSITIVE' : 'GENUINE THREAT'}
              </span>
            </div>
          </div>
        </Section>

        {/* Claude Analysis */}
        <Section icon={<Sparkles className="w-3.5 h-3.5" />} title="Claude's Analysis" accentColor="#ffb800">
          <AnimatePresence mode="wait">
            {aiAnalysis ? (
              <motion.div
                key="analysis"
                initial={{ opacity: 0 }}
                animate={{ opacity: 1 }}
                className="space-y-2 text-xs"
                style={{ color: '#b0bcd4' }}
              >
                <div>
                  <span className="font-bold" style={{ color: '#ffb800' }}>What happened: </span>
                  {aiAnalysis.what_happened}
                </div>
                <div>
                  <span className="font-bold" style={{ color: '#ff3b6b' }}>Why suspicious: </span>
                  {aiAnalysis.why_suspicious}
                </div>
                <div>
                  <span className="font-bold" style={{ color: '#00d4ff' }}>Confidence: </span>
                  {aiAnalysis.confidence_explanation}
                </div>
                <div>
                  <span className="font-bold" style={{ color: '#00ff9d' }}>Action: </span>
                  {aiAnalysis.recommended_action}
                </div>
                {aiAnalysis.false_positive_likelihood && (
                  <div
                    className="text-[10px] px-2 py-1.5 rounded"
                    style={{ background: 'rgba(167,139,250,0.1)', color: '#a78bfa', border: '1px solid rgba(167,139,250,0.2)' }}
                  >
                    FP likelihood: {aiAnalysis.false_positive_likelihood}
                  </div>
                )}
              </motion.div>
            ) : error ? (
              <motion.div key="error" initial={{ opacity: 0 }} animate={{ opacity: 1 }}>
                <p className="text-[11px]" style={{ color: '#ff3b6b' }}>{error}</p>
              </motion.div>
            ) : (
              <motion.div key="cta" initial={{ opacity: 0 }} animate={{ opacity: 1 }}>
                <button
                  onClick={handleGetAnalysis}
                  disabled={loading}
                  className="w-full flex items-center justify-center gap-2 py-2 rounded-lg text-xs font-semibold transition-all"
                  style={{
                    background: loading ? 'rgba(255,184,0,0.05)' : 'rgba(255,184,0,0.12)',
                    color: '#ffb800',
                    border: '1px solid rgba(255,184,0,0.25)',
                    opacity: loading ? 0.7 : 1,
                  }}
                >
                  {loading
                    ? <><Loader2 className="w-3.5 h-3.5 animate-spin" />Claude is analysing…</>
                    : <><Sparkles className="w-3.5 h-3.5" />Get AI Analysis</>
                  }
                </button>
              </motion.div>
            )}
          </AnimatePresence>
        </Section>
      </div>
    </motion.div>
  )
}
