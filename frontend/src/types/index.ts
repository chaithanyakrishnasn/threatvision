// ── Core domain types ─────────────────────────────────────────────────────────

export type Severity = 'critical' | 'high' | 'medium' | 'low'
export type IncidentStatus = 'open' | 'investigating' | 'contained' | 'resolved'
export type SimulationStatus = 'pending' | 'running' | 'completed' | 'failed'
export type EventType = 'network' | 'endpoint' | 'auth' | 'app'

export interface Incident {
  id: string
  title: string
  description: string | null
  severity: Severity
  status: IncidentStatus
  source_ip: string | null
  dest_ip: string | null
  mitre_tactics: string[]
  mitre_techniques: string[]
  confidence: number
  ai_analysis: string | null
  playbook_id: string | null
  raw_events: unknown[]
  tags: string[]
  alerts: Alert[]
  created_at: string
  updated_at: string
}

export interface Alert {
  id: string
  incident_id: string | null
  rule_name: string
  description: string | null
  severity: Severity
  source: string | null
  source_ip: string | null
  dest_ip: string | null
  protocol: string | null
  port: number | null
  confidence: number
  false_positive: boolean
  raw_data: Record<string, unknown>
  mitre_technique: string | null
  created_at: string
  updated_at: string
}

export interface ThreatEvent {
  id: string
  event_type: EventType
  source: string | null
  source_ip: string | null
  dest_ip: string | null
  hostname: string | null
  username: string | null
  process_name: string | null
  command_line: string | null
  severity: Severity
  category: string | null
  mitre_tactic: string | null
  mitre_technique: string | null
  anomaly_score: number
  is_anomaly: boolean
  raw_log: Record<string, unknown>
  enriched: boolean
  created_at: string
  updated_at: string
}

export interface SimulationRun {
  id: string
  name: string
  scenario: string
  status: SimulationStatus
  red_agent_config: Record<string, unknown>
  blue_agent_config: Record<string, unknown>
  events_generated: number
  alerts_triggered: number
  detection_rate: number
  mean_time_to_detect: number
  red_agent_log: SimLogEntry[]
  blue_agent_log: SimLogEntry[]
  findings: string | null
  recommendations: string[]
  duration_seconds: number
  created_at: string
  updated_at: string
}

export interface SimLogEntry {
  phase?: string
  event_type?: string
  technique?: string
  description?: string
  alert?: string
  severity?: string
  confidence?: number
  timestamp?: string
}

// ── Dashboard types ───────────────────────────────────────────────────────────

export interface DashboardMetrics {
  // Flat fields for dashboard cards
  total_events: number
  active_threats: number
  critical_alerts: number
  false_positives: number
  detection_rate: number
  avg_confidence: number
  events_per_second: number
  uptime_seconds: number
  // Nested summary (legacy / rich detail)
  summary: {
    active_incidents: number
    total_alerts: number
    alerts_24h: number
    total_events: number
    events_24h: number
    anomalies_detected: number
    ws_connections: number
  }
  incidents_by_severity: Record<Severity, number>
  recent_incidents: Partial<Incident>[]
  recent_alerts: Partial<Alert>[]
  severity_trend: { date: string; alerts: number }[]
  top_mitre_techniques: { technique: string; count: number }[]
  recent_simulations?: Partial<SimulationRun>[]
  generated_at: string
}

// Extended incident type with classification fields
export interface IncidentWithClassification extends Incident {
  threat_type: string | null
  is_false_positive: boolean
  explanation: string | null
  recommended_action: string | null
  rule_matches: string[]
  cross_layer_correlated: boolean
  anomaly_score: number
}

// ── WebSocket event types ─────────────────────────────────────────────────────

export type WsEventType =
  | 'new_incident'
  | 'incident_updated'
  | 'new_alert'
  | 'threat_detected'
  | 'live_event'
  | 'simulation_started'
  | 'simulation_complete'
  | 'simulation_failed'
  | 'sim_event'
  | 'sim_alert'
  | 'ack'

export interface WsMessage<T = unknown> {
  type: WsEventType
  data: T
}

// ── Playbook types ────────────────────────────────────────────────────────────

export interface PlaybookStep {
  action: string
  tool: string
  command: string | null
  notes: string
  status?: string
}

export interface PlaybookPhase {
  name: string
  steps: PlaybookStep[]
}

export interface Playbook {
  id: string
  name: string
  description: string
  priority: Severity
  phases: PlaybookPhase[]
  iocs_to_hunt: string[]
  escalation_criteria: string[]
  incident_id?: string
}

// ── API response types ────────────────────────────────────────────────────────

export interface ApiError {
  detail: string
}

export interface PaginatedResponse<T> {
  items: T[]
  total: number
  page: number
  size: number
}
