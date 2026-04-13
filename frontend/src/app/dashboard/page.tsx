'use client'

import { useEffect, useState, useCallback, useRef } from 'react'
import { motion } from 'framer-motion'
import { Shield, AlertOctagon, Activity, Swords } from 'lucide-react'
import {
  MetricCards, IncidentFeed, ThreatTimeline, AttackMap,
  PlaybookViewer, SimulationPanel, ConnectionStatus, ExplainabilityPanel,
} from '@/components/dashboard'
import { useStore } from '@/lib/store'
import { getWsClient, useWebSocket } from '@/lib/websocket'
import { dashboardApi, incidentsApi, alertsApi } from '@/lib/api'
import type { DashboardMetrics, Incident, Alert, WsMessage, Playbook } from '@/types'
import { RadarChart, PolarGrid, PolarAngleAxis, Radar, ResponsiveContainer } from 'recharts'

// ── Demo seed data ────────────────────────────────────────────────────────────

const DEMO_INCIDENTS: Partial<Incident>[] = [
  {
    id: '1', title: 'APT29 TTPs — Lateral Movement via SMB', severity: 'critical',
    status: 'investigating', confidence: 0.94,
    source_ip: '185.220.101.5', dest_ip: '10.0.1.12',
    mitre_techniques: ['T1021.002', 'T1003.001', 'T1078'],
    created_at: new Date(Date.now() - 3 * 60000).toISOString(),
  },
  {
    id: '2', title: 'Ransomware Pre-Deployment Indicators Detected', severity: 'critical',
    status: 'open', confidence: 0.88,
    source_ip: '192.168.1.45', dest_ip: '91.108.56.177',
    mitre_techniques: ['T1486', 'T1562'],
    created_at: new Date(Date.now() - 12 * 60000).toISOString(),
  },
  {
    id: '3', title: 'PowerShell Encoded Command — workstation-dev-12', severity: 'high',
    status: 'open', confidence: 0.76,
    source_ip: '192.168.1.12', dest_ip: '192.168.1.50',
    mitre_techniques: ['T1059.001'],
    created_at: new Date(Date.now() - 28 * 60000).toISOString(),
  },
  {
    id: '4', title: 'Credential Brute Force — Domain Admin Account', severity: 'high',
    status: 'contained', confidence: 0.82,
    source_ip: '45.95.147.236', dest_ip: '10.0.0.5',
    mitre_techniques: ['T1110.001'],
    created_at: new Date(Date.now() - 65 * 60000).toISOString(),
  },
  {
    id: '5', title: 'C2 Beaconing Pattern — Port 443', severity: 'high',
    status: 'investigating', confidence: 0.79,
    source_ip: '192.168.1.45', dest_ip: '185.220.102.8',
    mitre_techniques: ['T1071', 'T1095'],
    created_at: new Date(Date.now() - 95 * 60000).toISOString(),
  },
  {
    id: '6', title: 'LSASS Memory Access — Domain Controller', severity: 'critical',
    status: 'open', confidence: 0.97,
    source_ip: '192.168.1.100', dest_ip: '10.0.0.1',
    mitre_techniques: ['T1003.001'],
    created_at: new Date(Date.now() - 4 * 60000).toISOString(),
  },
  {
    id: '7', title: 'Anomalous Auth from Unusual Geolocation', severity: 'medium',
    status: 'resolved', confidence: 0.61,
    source_ip: '91.108.4.22', dest_ip: '10.0.1.1',
    mitre_techniques: ['T1078'],
    created_at: new Date(Date.now() - 3 * 3600 * 1000).toISOString(),
  },
]

const DEMO_ALERTS: Partial<Alert>[] = [
  { id: 'a1', rule_name: 'LSASS Memory Access',       severity: 'critical', source_ip: '192.168.1.100', dest_ip: '192.168.1.50', mitre_technique: 'T1003.001', created_at: new Date(Date.now() - 90000).toISOString() },
  { id: 'a2', rule_name: 'PowerShell Encoded Command', severity: 'high',     source_ip: '192.168.1.12',                            mitre_technique: 'T1059.001', created_at: new Date(Date.now() - 180000).toISOString() },
  { id: 'a3', rule_name: 'C2 Beaconing Pattern',       severity: 'high',     source_ip: '192.168.1.45',  dest_ip: '185.220.101.5', mitre_technique: 'T1071',     created_at: new Date(Date.now() - 300000).toISOString() },
  { id: 'a4', rule_name: 'Brute Force Authentication',  severity: 'medium',   source_ip: '45.95.147.236',                           mitre_technique: 'T1110.001', created_at: new Date(Date.now() - 600000).toISOString() },
  { id: 'a5', rule_name: 'Defense Evasion — AV Disable', severity: 'high',  source_ip: '192.168.1.22',                             mitre_technique: 'T1562',     created_at: new Date(Date.now() - 720000).toISOString() },
  { id: 'a6', rule_name: 'Data Exfiltration — Large Upload', severity: 'high', source_ip: '192.168.1.50', dest_ip: '91.108.56.177', mitre_technique: 'T1041',   created_at: new Date(Date.now() - 900000).toISOString() },
]

const DEMO_METRICS: DashboardMetrics = {
  // Flat fields for metric cards
  total_events: 12843,
  active_threats: 4,
  critical_alerts: 3,
  false_positives: 9,
  detection_rate: 94,
  avg_confidence: 0.87,
  events_per_second: 0,
  uptime_seconds: 0,
  summary: {
    active_incidents: 4,
    total_alerts: 247,
    alerts_24h: 38,
    total_events: 12843,
    events_24h: 1204,
    anomalies_detected: 17,
    ws_connections: 1,
  },
  incidents_by_severity: { critical: 3, high: 5, medium: 8, low: 3 },
  recent_incidents: DEMO_INCIDENTS,
  recent_alerts: DEMO_ALERTS,
  severity_trend: Array.from({ length: 7 }, (_, i) => ({
    date: new Date(Date.now() - (6 - i) * 86400000).toISOString().slice(0, 10),
    alerts: [12, 19, 8, 34, 22, 41, 38][i],
  })),
  top_mitre_techniques: [
    { technique: 'T1059.001', count: 34 },
    { technique: 'T1003.001', count: 28 },
    { technique: 'T1021.002', count: 22 },
    { technique: 'T1110.001', count: 19 },
    { technique: 'T1041',     count: 15 },
    { technique: 'T1486',     count: 11 },
  ],
  recent_simulations: [],
  generated_at: new Date().toISOString(),
}

const DEMO_PLAYBOOK: Playbook = {
  id: 'pb-demo',
  name: 'APT Lateral Movement Response',
  description: 'Contain and eradicate APT lateral movement via SMB',
  priority: 'critical',
  phases: [
    {
      name: 'Containment',
      steps: [
        { action: 'Block source IP at firewall', tool: 'Palo Alto', command: 'deny ip 185.220.101.5/32 any', notes: 'Immediate block', status: 'executed' },
        { action: 'Isolate compromised endpoint', tool: 'CrowdStrike', command: null, notes: 'Network containment', status: 'awaiting_approval' },
        { action: 'Disable compromised service account', tool: 'Active Directory', command: 'Disable-ADAccount -Identity svc_backup', notes: '', status: 'pending' },
      ],
    },
    {
      name: 'Eradication',
      steps: [
        { action: 'Full endpoint scan', tool: 'EDR', command: null, notes: 'Hunt for persistence mechanisms', status: 'pending' },
        { action: 'Remove scheduled tasks', tool: 'SCCM', command: 'schtasks /delete /tn "Updater" /f', notes: '', status: 'pending' },
        { action: 'Reset all privileged credentials', tool: 'AD / PAM', command: null, notes: 'Rotate service account passwords', status: 'pending' },
      ],
    },
    {
      name: 'Recovery',
      steps: [
        { action: 'Restore from clean backup', tool: 'Veeam', command: null, notes: 'Verify integrity before restore', status: 'pending' },
        { action: 'Re-enable network access', tool: 'Firewall', command: null, notes: 'After confirming clean', status: 'pending' },
      ],
    },
    {
      name: 'Lessons Learned',
      steps: [
        { action: 'Document IOCs', tool: 'ThreatVision', command: null, notes: 'Update threat intel feed', status: 'pending' },
        { action: 'Update detection rules', tool: 'SIEM', command: null, notes: 'Improve coverage for T1021.002', status: 'pending' },
      ],
    },
  ],
  iocs_to_hunt: ['185.220.101.5', '91.108.56.177', 'svc_backup', 'powershell.exe -enc'],
  escalation_criteria: ['Evidence of data exfiltration', 'Domain controller compromise'],
}

const MITRE_RADAR_DATA = [
  { subject: 'Initial Access', A: 42 },
  { subject: 'Execution',      A: 78 },
  { subject: 'Persistence',    A: 35 },
  { subject: 'Priv Esc',       A: 55 },
  { subject: 'Defense Eva',    A: 60 },
  { subject: 'Cred Access',    A: 85 },
  { subject: 'Lateral Mov',    A: 70 },
  { subject: 'Exfiltration',   A: 45 },
]

const LIVE_EVENT_SEEDS = [
  { sev: 'CRITICAL', msg: 'LSASS access — dc-01 — T1003.001' },
  { sev: 'HIGH',     msg: 'PowerShell encoded cmd — workstation-dev-12' },
  { sev: 'HIGH',     msg: 'SMB admin share access — svc_backup' },
  { sev: 'MEDIUM',   msg: 'Auth failure ×7 — jsmith@192.168.1.45' },
  { sev: 'HIGH',     msg: 'C2 beacon — 185.220.101.5:443' },
  { sev: 'LOW',      msg: 'Port scan — 45.95.147.236' },
]

// ── Dashboard Page ────────────────────────────────────────────────────────────

export default function DashboardPage() {
  const {
    incidents, alerts, metrics,
    setIncidents, setAlerts, setMetrics,
    prependIncident, prependAlert,
    selectedIncidentId, setSelectedIncident,
    wsConnected, setWsConnected, setLastEventTime,
  } = useStore()

  const [loading, setLoading] = useState(true)
  const [activeTab, setActiveTab] = useState<'incidents' | 'simulation'>('incidents')
  const [liveEvents, setLiveEvents] = useState<{ sev: string; msg: string; ts: number }[]>([])
  const [selectedPlaybook, setSelectedPlaybook] = useState<Playbook | null>(DEMO_PLAYBOOK)
  const [now, setNow] = useState('')
  const [today, setToday] = useState('')
  const liveRef = useRef(0)

  // Clock
  useEffect(() => {
    const update = () => {
      const d = new Date()
      setNow(d.toLocaleTimeString('en-US', { hour12: false, hour: '2-digit', minute: '2-digit', second: '2-digit' }))
      setToday(d.toLocaleDateString('en-US', { weekday: 'short', month: 'short', day: 'numeric', year: 'numeric' }))
    }
    update()
    const t = setInterval(update, 1000)
    return () => clearInterval(t)
  }, [])

  // Load initial data
  useEffect(() => {
    const load = async () => {
      try {
        const [m, inc, alrt] = await Promise.all([
          dashboardApi.getMetrics().catch(() => DEMO_METRICS),
          incidentsApi.list({ limit: 30 }).catch(() => DEMO_INCIDENTS as Incident[]),
          alertsApi.list({ limit: 20 }).catch(() => DEMO_ALERTS as Alert[]),
        ])
        setMetrics(m)
        setIncidents(inc.length ? inc : DEMO_INCIDENTS as Incident[])
        setAlerts(alrt.length ? alrt : DEMO_ALERTS as Alert[])
      } catch {
        setMetrics(DEMO_METRICS)
        setIncidents(DEMO_INCIDENTS as Incident[])
        setAlerts(DEMO_ALERTS as Alert[])
      } finally {
        setLoading(false)
      }
    }
    load()

    // Metrics polling
    const poll = setInterval(async () => {
      try {
        const m = await dashboardApi.getMetrics()
        setMetrics(m)
      } catch {}
    }, 8000)
    return () => clearInterval(poll)
  }, [])

  // Seed live events then add new ones
  useEffect(() => {
    setLiveEvents(LIVE_EVENT_SEEDS.map((e, i) => ({ ...e, ts: Date.now() - i * 8000 })))
    const interval = setInterval(() => {
      const seed = LIVE_EVENT_SEEDS[liveRef.current % LIVE_EVENT_SEEDS.length]
      liveRef.current++
      setLiveEvents((prev) => [{ ...seed, ts: Date.now() }, ...prev.slice(0, 14)])
    }, 4000)
    return () => clearInterval(interval)
  }, [])

  // Connect WebSocket
  useEffect(() => {
    const client = getWsClient()
    client.connect()
    const unsub = client.on('*', (msg: any) => {
      if (msg?.type !== 'ack') setWsConnected(true)
    })
    // Check connection state after 2s
    const t = setTimeout(() => {
      setWsConnected(client.isConnected)
    }, 2000)
    return () => { unsub(); clearTimeout(t) }
  }, [])

  // WS event handlers
  useWebSocket('new_incident', useCallback((data: unknown) => {
    prependIncident(data as Partial<Incident>)
    setLastEventTime(new Date().toISOString())
  }, []))

  useWebSocket('new_alert', useCallback((data: unknown) => {
    prependAlert(data as Partial<Alert>)
    setLastEventTime(new Date().toISOString())
  }, []))

  useWebSocket('live_event', useCallback((data: unknown) => {
    const d = data as any
    const sev = (d?.classification?.severity || 'medium').toUpperCase()
    const msg = d?.event?.description || 'Threat event detected'
    setLiveEvents((prev) => [{ sev, msg, ts: Date.now() }, ...prev.slice(0, 14)])
    setLastEventTime(new Date().toISOString())
  }, []))

  const displayIncidents = incidents.length > 0 ? incidents : DEMO_INCIDENTS
  const displayAlerts    = alerts.length > 0 ? alerts : DEMO_ALERTS
  const displayMetrics   = metrics || DEMO_METRICS

  const selectedIncident = displayIncidents.find((i) => i.id === selectedIncidentId) ?? null

  const sevColor = (sev: string) => {
    switch (sev) {
      case 'CRITICAL': return '#ff3b6b'
      case 'HIGH':     return '#ff6b35'
      case 'MEDIUM':   return '#ffb800'
      default:         return '#6b7a99'
    }
  }

  return (
    <div className="flex flex-col h-screen overflow-hidden" style={{ background: '#0a0e1a' }}>

      {/* ── HEADER ──────────────────────────────────────────────────────────── */}
      <header
        className="flex-shrink-0 flex items-center justify-between px-5 z-40"
        style={{
          height: 56,
          background: '#0f1629',
          borderBottom: '1px solid #1e2d4a',
          backdropFilter: 'blur(8px)',
        }}
      >
        {/* Brand */}
        <div className="flex items-center gap-3">
          <div
            className="w-8 h-8 rounded-lg flex items-center justify-center"
            style={{ background: 'rgba(0,212,255,0.15)', border: '1px solid rgba(0,212,255,0.3)' }}
          >
            <Shield className="w-4 h-4" style={{ color: '#00d4ff' }} />
          </div>
          <div>
            <span className="font-bold tracking-tight" style={{ color: '#e8eaf0', fontSize: 15 }}>ThreatVision</span>
            <span
              className="ml-2 text-[9px] font-bold uppercase tracking-widest px-1.5 py-0.5 rounded"
              style={{ color: '#00d4ff', background: 'rgba(0,212,255,0.1)', border: '1px solid rgba(0,212,255,0.2)' }}
            >
              SOC
            </span>
          </div>
        </div>

        {/* Center — system time */}
        <div className="hidden md:flex flex-col items-center">
          <span className="font-mono text-lg font-bold" style={{ color: '#00d4ff' }}>{now}</span>
          <span className="text-[9px] uppercase tracking-widest" style={{ color: '#6b7a99' }}>
            {today}
          </span>
        </div>

        {/* Right — status */}
        <div className="flex items-center gap-3">
          <ConnectionStatus connected={wsConnected} />
        </div>
      </header>

      {/* ── METRICS ROW ─────────────────────────────────────────────────────── */}
      <div className="flex-shrink-0 px-4 pt-3 pb-2">
        <MetricCards metrics={displayMetrics} wsConnected={wsConnected} />
      </div>

      {/* ── MAIN CONTENT ────────────────────────────────────────────────────── */}
      <div className="flex-1 flex gap-3 px-4 pb-3 min-h-0">

        {/* ── LEFT: Incident Feed + Simulation ── */}
        <div className="flex flex-col gap-3" style={{ width: 310, flexShrink: 0 }}>

          {/* Tab switcher */}
          <div
            className="flex rounded-lg overflow-hidden"
            style={{ background: '#141d35', border: '1px solid #1e2d4a' }}
          >
            {([
              { id: 'incidents', label: 'Incidents', icon: AlertOctagon },
              { id: 'simulation', label: 'Red Team', icon: Swords },
            ] as const).map((tab) => {
              const Icon = tab.icon
              const active = activeTab === tab.id
              return (
                <button
                  key={tab.id}
                  onClick={() => setActiveTab(tab.id)}
                  className="flex-1 flex items-center justify-center gap-1.5 py-2 text-xs font-semibold transition-all"
                  style={{
                    color: active ? '#00d4ff' : '#6b7a99',
                    background: active ? 'rgba(0,212,255,0.08)' : 'transparent',
                    borderBottom: active ? '2px solid #00d4ff' : '2px solid transparent',
                  }}
                >
                  <Icon className="w-3.5 h-3.5" />
                  {tab.label}
                </button>
              )
            })}
          </div>

          {/* Panel content */}
          <div
            className="flex-1 overflow-y-auto rounded-xl p-3"
            style={{ background: '#141d35', border: '1px solid #1e2d4a' }}
          >
            {activeTab === 'incidents' ? (
              <>
                <div className="flex items-center justify-between mb-2">
                  <span className="text-xs font-bold uppercase tracking-wider" style={{ color: '#6b7a99' }}>
                    Live Feed
                  </span>
                  <span
                    className="text-[10px] font-mono px-1.5 py-0.5 rounded"
                    style={{ color: '#ff3b6b', background: 'rgba(255,59,107,0.1)' }}
                  >
                    {displayIncidents.length} active
                  </span>
                </div>
                <IncidentFeed
                  incidents={displayIncidents}
                  onSelect={setSelectedIncident}
                  selectedId={selectedIncidentId}
                />
              </>
            ) : (
              <SimulationPanel />
            )}
          </div>
        </div>

        {/* ── CENTER: Attack Map + Timeline ── */}
        <div className="flex flex-col gap-3 flex-1 min-w-0">

          {/* Attack Map */}
          <div
            className="rounded-xl p-3"
            style={{ background: '#141d35', border: '1px solid #1e2d4a' }}
          >
            <div className="flex items-center justify-between mb-2">
              <span className="text-xs font-bold uppercase tracking-wider" style={{ color: '#6b7a99' }}>
                Live Attack Map
              </span>
              <span className="text-[9px] font-mono" style={{ color: '#1e2d4a' }}>
                REAL-TIME
              </span>
            </div>
            <AttackMap alerts={displayAlerts} />
          </div>

          {/* Threat Timeline */}
          <div
            className="rounded-xl p-3"
            style={{ background: '#141d35', border: '1px solid #1e2d4a' }}
          >
            <div className="flex items-center justify-between mb-2">
              <span className="text-xs font-bold uppercase tracking-wider" style={{ color: '#6b7a99' }}>
                Threat Activity — Live
              </span>
              <div className="flex items-center gap-3">
                {[
                  { color: '#ff3b6b', label: 'Brute Force' },
                  { color: '#00d4ff', label: 'C2 Beacon' },
                  { color: '#ffb800', label: 'Lateral Move' },
                ].map((l) => (
                  <div key={l.label} className="flex items-center gap-1">
                    <span className="w-2 h-0.5 rounded" style={{ background: l.color }} />
                    <span className="text-[9px]" style={{ color: '#6b7a99' }}>{l.label}</span>
                  </div>
                ))}
              </div>
            </div>
            <ThreatTimeline />
          </div>

          {/* MITRE Radar */}
          <div
            className="rounded-xl p-3 flex-1"
            style={{ background: '#141d35', border: '1px solid #1e2d4a' }}
          >
            <div className="flex items-center justify-between mb-1">
              <span className="text-xs font-bold uppercase tracking-wider" style={{ color: '#6b7a99' }}>
                MITRE ATT&CK Coverage
              </span>
              <Activity className="w-3.5 h-3.5" style={{ color: '#1e2d4a' }} />
            </div>
            <ResponsiveContainer width="100%" height={160}>
              <RadarChart data={MITRE_RADAR_DATA}>
                <PolarGrid stroke="#1e2d4a" />
                <PolarAngleAxis
                  dataKey="subject"
                  tick={{ fill: '#6b7a99', fontSize: 9 }}
                />
                <Radar
                  name="Detections"
                  dataKey="A"
                  stroke="#00d4ff"
                  fill="#00d4ff"
                  fillOpacity={0.2}
                  strokeWidth={2}
                />
              </RadarChart>
            </ResponsiveContainer>
          </div>
        </div>

        {/* ── RIGHT: Explainability / Playbook + Live Events + MITRE top ── */}
        <div className="flex flex-col gap-3" style={{ width: 300, flexShrink: 0 }}>

          {/* Explainability Panel (when incident selected) / Playbook Viewer (default) */}
          <div
            className="flex-1 rounded-xl overflow-hidden overflow-y-auto"
            style={{ background: '#141d35', border: '1px solid #1e2d4a', minHeight: 0 }}
          >
            {selectedIncident ? (
              <ExplainabilityPanel incident={selectedIncident as any} />
            ) : (
              <>
                <div
                  className="px-3 py-2"
                  style={{ borderBottom: '1px solid #1e2d4a' }}
                >
                  <span className="text-xs font-bold uppercase tracking-wider" style={{ color: '#6b7a99' }}>
                    Response Playbook
                  </span>
                </div>
                <div className="overflow-y-auto" style={{ maxHeight: 'calc(100% - 36px)' }}>
                  <PlaybookViewer
                    playbook={selectedPlaybook || DEMO_PLAYBOOK}
                    incident={selectedIncident}
                    onGeneratePlaybook={setSelectedPlaybook}
                  />
                </div>
              </>
            )}
          </div>

          {/* Live Events */}
          <div
            className="rounded-xl p-3"
            style={{ background: '#141d35', border: '1px solid #1e2d4a' }}
          >
            <div className="flex items-center gap-2 mb-2">
              <span className="w-2 h-2 rounded-full live-dot" style={{ background: '#00ff9d' }} />
              <span className="text-xs font-bold uppercase tracking-wider" style={{ color: '#6b7a99' }}>
                Live Events
              </span>
            </div>
            <div className="space-y-0.5 max-h-36 overflow-y-auto">
              {liveEvents.map((e, i) => (
                <motion.div
                  key={`${e.ts}-${i}`}
                  initial={{ opacity: 0, x: 6 }}
                  animate={{ opacity: 1, x: 0 }}
                  className="flex items-start gap-1.5 py-0.5"
                >
                  <span
                    className="text-[9px] font-bold font-mono flex-shrink-0 mt-0.5"
                    style={{ color: sevColor(e.sev) }}
                  >
                    [{e.sev.slice(0, 4)}]
                  </span>
                  <span className="text-[10px] leading-tight" style={{ color: '#6b7a99' }}>
                    {e.msg}
                  </span>
                </motion.div>
              ))}
            </div>
          </div>

          {/* Top MITRE Techniques */}
          <div
            className="rounded-xl p-3"
            style={{ background: '#141d35', border: '1px solid #1e2d4a' }}
          >
            <span className="text-xs font-bold uppercase tracking-wider block mb-2" style={{ color: '#6b7a99' }}>
              Top Techniques
            </span>
            <div className="space-y-2">
              {(displayMetrics.top_mitre_techniques || []).slice(0, 6).map((t) => (
                <div key={t.technique} className="flex items-center gap-2">
                  <span
                    className="font-mono text-[10px] w-20 flex-shrink-0"
                    style={{ color: '#00d4ff' }}
                  >
                    {t.technique}
                  </span>
                  <div className="flex-1 h-1 rounded-full overflow-hidden" style={{ background: '#1e2d4a' }}>
                    <div
                      className="h-full rounded-full transition-all duration-700"
                      style={{
                        width: `${Math.min((t.count / 40) * 100, 100)}%`,
                        background: 'linear-gradient(90deg, #00d4ff, #0ea5e9)',
                      }}
                    />
                  </div>
                  <span className="text-[10px] w-6 text-right" style={{ color: '#6b7a99' }}>{t.count}</span>
                </div>
              ))}
            </div>
          </div>
        </div>
      </div>
    </div>
  )
}
