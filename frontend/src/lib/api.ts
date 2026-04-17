import axios from 'axios'
import type {
  Incident,
  Alert,
  ThreatEvent,
  SimulationRun,
  DashboardMetrics,
  Playbook,
  Analyst,
  Ticket,
  TicketStats,
  LeaderboardEntry,
  AuditLog,
} from '@/types'

const BASE_URL = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:8000'

export const apiClient = axios.create({
  baseURL: `${BASE_URL}/api/v1`,
  headers: { 'Content-Type': 'application/json' },
  timeout: 30_000,
})

// ── Interceptors ──────────────────────────────────────────────────────────────
apiClient.interceptors.response.use(
  (res) => res,
  (err) => {
    const message = err.response?.data?.detail || err.message || 'Unknown error'
    console.error('[API Error]', message)
    return Promise.reject(new Error(message))
  }
)

// ── Dashboard ─────────────────────────────────────────────────────────────────
export const dashboardApi = {
  getMetrics: () =>
    apiClient.get<DashboardMetrics>('/dashboard/metrics').then((r) => r.data),
}

// ── Incidents ─────────────────────────────────────────────────────────────────
export const incidentsApi = {
  list: (params?: { limit?: number; offset?: number; severity?: string; status?: string }) =>
    apiClient.get<Incident[]>('/incidents', { params }).then((r) => r.data),

  get: (id: string) =>
    apiClient.get<Incident>(`/incidents/${id}`).then((r) => r.data),

  create: (data: Partial<Incident>) =>
    apiClient.post<Incident>('/incidents', data).then((r) => r.data),

  update: (id: string, data: Partial<Incident>) =>
    apiClient.patch<Incident>(`/incidents/${id}`, data).then((r) => r.data),

  analyze: (id: string) =>
    apiClient.post<{ incident_id: string; analysis: string }>(`/incidents/${id}/analyze`).then((r) => r.data),
}

// ── Alerts ────────────────────────────────────────────────────────────────────
export const alertsApi = {
  list: (params?: { limit?: number; severity?: string; false_positive?: boolean }) =>
    apiClient.get<Alert[]>('/alerts', { params }).then((r) => r.data),

  get: (id: string) =>
    apiClient.get<Alert>(`/alerts/${id}`).then((r) => r.data),

  update: (id: string, data: Partial<Alert>) =>
    apiClient.patch<Alert>(`/alerts/${id}`, data).then((r) => r.data),
}

// ── Threats ───────────────────────────────────────────────────────────────────
export const threatsApi = {
  list: (params?: { limit?: number; event_type?: string; is_anomaly?: boolean }) =>
    apiClient.get<ThreatEvent[]>('/threats', { params }).then((r) => r.data),

  ingest: (data: Partial<ThreatEvent>) =>
    apiClient.post<ThreatEvent>('/threats', data).then((r) => r.data),
}

// ── Playbooks ─────────────────────────────────────────────────────────────────
export const playbooksApi = {
  list: () =>
    apiClient.get<Playbook[]>('/playbooks').then((r) => r.data),

  get: (id: string) =>
    apiClient.get<Playbook>(`/playbooks/${id}`).then((r) => r.data),

  generate: (incidentId: string) =>
    apiClient.post<Playbook>(`/playbooks/generate/${incidentId}`).then((r) => r.data),

  generateForThreat: (threatType: string, severity: string, affectedIps: string[]) =>
    apiClient.post('/playbooks/generate', {
      threat_type: threatType,
      severity,
      affected_ips: affectedIps,
    }).then((r) => r.data),

  getQuickResponse: (threatType: string) =>
    apiClient.get<{ commands: string[]; threat_type: string }>(`/playbooks/quick/${threatType}`).then((r) => r.data),

  explain: (event: Record<string, unknown>, classification: Record<string, unknown>) =>
    apiClient.post<{
      what_happened: string
      why_suspicious: string
      false_positive_likelihood: string
      false_positive_reason: string | null
      recommended_action: string
      confidence_explanation: string
    }>('/playbooks/explain', { event, classification }).then((r) => r.data),

  execute: (playbookId: string, incidentId: string, autoExecute = true) =>
    apiClient.post(`/playbooks/${playbookId}/execute`, null, {
      params: { incident_id: incidentId, auto_execute: autoExecute },
    }).then((r) => r.data),
}

// ── Ingestion ─────────────────────────────────────────────────────────────────
export const ingestionApi = {
  triggerDemo: () =>
    apiClient.post<{ status: string; message: string }>('/ingestion/demo').then((r) => r.data),

  getStats: () =>
    apiClient.get<{ running: boolean; eps: number; queue_depth: number; total_processed: number }>('/ingestion/stats').then((r) => r.data),
}

// ── Dashboard extras ──────────────────────────────────────────────────────────
export const dashboardExtApi = {
  getThreatTimeline: (minutes = 60) =>
    apiClient.get<Array<{
      timestamp: string
      minute: number
      brute_force: number
      c2_beacon: number
      lateral_movement: number
      data_exfiltration: number
      false_positive: number
      benign: number
      total: number
    }>>(`/dashboard/threat-timeline?minutes=${minutes}`).then((r) => r.data),

  getMetricDetails: (type: string) =>
    apiClient.get(`/dashboard/metric-details?type=${type}`).then((r) => r.data),
}

// ── Recent live events ────────────────────────────────────────────────────────
export const liveEventsApi = {
  getRecent: (limit = 20) =>
    apiClient.get<Array<{
      id: string
      threat_type: string
      severity: string
      source_ip: string | null
      dest_ip: string | null
      raw_log: Record<string, any>
      confidence: number
      created_at: string
    }>>(`/threats/recent?limit=${limit}`).then((r) => r.data),
}

// ── Simulation (extended) ─────────────────────────────────────────────────────
export const simulationApi = {
  list: () =>
    apiClient.get<SimulationRun[]>('/simulation').then((r) => r.data),

  get: (id: string) =>
    apiClient.get<SimulationRun>(`/simulation/${id}`).then((r) => r.data),

  run: (data: { name: string; scenario: string; red_agent_config?: object; blue_agent_config?: object }) =>
    apiClient.post<SimulationRun>('/simulation/run', data).then((r) => r.data),

  quickDemo: () =>
    apiClient.post<{
      simulation_id: string
      total_rounds: number
      final_detection_rate: number
      rounds: { round: number; detection_rate: number; attack_success_rate: number }[]
      findings: string
      events_generated: number
      alerts_triggered: number
    }>('/simulation/quick-demo', {}, { timeout: 120_000 }).then((r) => r.data),

  start: (payload: {
    name?: string
    rounds?: number
    attack_types?: string[]
  }) =>
    apiClient.post<{ simulation_id: string; status: string; message: string }>(
      '/simulation/start', payload
    ).then((r) => r.data),
}

// ── Analysts ──────────────────────────────────────────────────────────────────
export const analystsApi = {
  async list(): Promise<Analyst[]> {
    const res = await fetch(`${BASE_URL}/api/v1/analysts/`)
    if (!res.ok) throw new Error('Failed to fetch analysts')
    return res.json()
  },
  async getAvailable(): Promise<Analyst[]> {
    const res = await fetch(`${BASE_URL}/api/v1/analysts/available`)
    if (!res.ok) throw new Error('Failed to fetch available analysts')
    return res.json()
  },
  async getLeaderboard(): Promise<LeaderboardEntry[]> {
    const res = await fetch(`${BASE_URL}/api/v1/analysts/leaderboard`)
    if (!res.ok) throw new Error('Failed to fetch leaderboard')
    return res.json()
  },
  async getTickets(id: string): Promise<Ticket[]> {
    const res = await fetch(`${BASE_URL}/api/v1/analysts/${id}/tickets`)
    if (!res.ok) throw new Error('Failed to fetch analyst tickets')
    return res.json()
  },
  async updateAvailability(id: string, availability: string): Promise<Analyst> {
    const res = await fetch(`${BASE_URL}/api/v1/analysts/${id}/availability`, {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ availability }),
    })
    if (!res.ok) throw new Error('Failed to update availability')
    return res.json()
  },
}

// ── Tickets ───────────────────────────────────────────────────────────────────
export const ticketsApi = {
  async list(filters?: { status?: string; severity?: string; sla_breached?: boolean }): Promise<Ticket[]> {
    const params = new URLSearchParams()
    if (filters?.status) params.append('status', filters.status)
    if (filters?.severity) params.append('severity', filters.severity)
    if (filters?.sla_breached) params.append('sla_breached', 'true')
    const res = await fetch(`${BASE_URL}/api/v1/tickets/?${params}`)
    if (!res.ok) throw new Error('Failed to fetch tickets')
    return res.json()
  },
  async get(id: string): Promise<Ticket> {
    const res = await fetch(`${BASE_URL}/api/v1/tickets/${id}`)
    if (!res.ok) throw new Error('Failed to fetch ticket')
    return res.json()
  },
  async getStats(): Promise<TicketStats> {
    const res = await fetch(`${BASE_URL}/api/v1/tickets/stats`)
    if (!res.ok) throw new Error('Failed to fetch ticket stats')
    return res.json()
  },
  async getSLABreaches(): Promise<Ticket[]> {
    const res = await fetch(`${BASE_URL}/api/v1/tickets/sla-breaches`)
    if (!res.ok) throw new Error('Failed to fetch SLA breaches')
    return res.json()
  },
  async assign(ticketId: string, analystId: string): Promise<Ticket> {
    const res = await fetch(`${BASE_URL}/api/v1/tickets/${ticketId}/assign`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ analyst_id: analystId }),
    })
    if (!res.ok) throw new Error('Failed to assign ticket')
    return res.json()
  },
  async acknowledge(ticketId: string, analystId: string): Promise<Ticket> {
    const res = await fetch(`${BASE_URL}/api/v1/tickets/${ticketId}/acknowledge`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ analyst_id: analystId }),
    })
    if (!res.ok) throw new Error('Failed to acknowledge ticket')
    return res.json()
  },
  async resolve(ticketId: string, analystId: string, notes: string, type: string): Promise<Ticket> {
    const res = await fetch(`${BASE_URL}/api/v1/tickets/${ticketId}/resolve`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ analyst_id: analystId, resolution_notes: notes, resolution_type: type }),
    })
    if (!res.ok) throw new Error('Failed to resolve ticket')
    return res.json()
  },
  async escalate(ticketId: string, reason: string): Promise<Ticket> {
    const res = await fetch(`${BASE_URL}/api/v1/tickets/${ticketId}/escalate`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ reason }),
    })
    if (!res.ok) throw new Error('Failed to escalate ticket')
    return res.json()
  },
  async comment(ticketId: string, actorName: string, comment: string): Promise<{ success: boolean }> {
    const res = await fetch(`${BASE_URL}/api/v1/tickets/${ticketId}/comment`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ actor_name: actorName, actor_type: 'analyst', comment }),
    })
    if (!res.ok) throw new Error('Failed to add comment')
    return res.json()
  },
}

// ── Audit Logs ────────────────────────────────────────────────────────────────
export const auditLogsApi = {
  list: (params?: {
    actor_type?: string
    action?: string
    result?: string
    actor_id?: string
    target_type?: string
    time_from?: string
    time_to?: string
    limit?: number
    offset?: number
  }) =>
    apiClient.get<{ total: number; logs: AuditLog[] }>('/audit/logs', { params }).then((r) => r.data),

  search: (q: string, limit = 50, offset = 0) =>
    apiClient.get<{ total: number; logs: AuditLog[] }>('/audit/logs/search', { params: { q, limit, offset } }).then((r) => r.data),
  
  verify: () =>
    apiClient.get<{ valid: boolean; checked: number; broken_at: string | null; total_rows: number }>('/audit/verify').then((r) => r.data),
}
