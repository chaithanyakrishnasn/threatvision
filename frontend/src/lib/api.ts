import axios from 'axios'
import type {
  Incident,
  Alert,
  ThreatEvent,
  SimulationRun,
  DashboardMetrics,
  Playbook,
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
