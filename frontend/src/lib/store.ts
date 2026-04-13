import { create } from 'zustand'
import { devtools } from 'zustand/middleware'
import type { Incident, Alert, ThreatEvent, DashboardMetrics, SimulationRun } from '@/types'

interface ThreatVisionState {
  // Data
  incidents: Incident[]
  alerts: Alert[]
  threats: ThreatEvent[]
  metrics: DashboardMetrics | null
  simulations: SimulationRun[]

  // UI state
  selectedIncidentId: string | null
  wsConnected: boolean
  lastEventTime: string | null

  // Actions
  setIncidents: (incidents: Incident[]) => void
  prependIncident: (incident: Partial<Incident>) => void
  updateIncident: (id: string, patch: Partial<Incident>) => void

  setAlerts: (alerts: Alert[]) => void
  prependAlert: (alert: Partial<Alert>) => void

  setThreats: (threats: ThreatEvent[]) => void
  prependThreat: (threat: Partial<ThreatEvent>) => void

  setMetrics: (metrics: DashboardMetrics) => void
  setSimulations: (sims: SimulationRun[]) => void
  upsertSimulation: (sim: Partial<SimulationRun>) => void

  setSelectedIncident: (id: string | null) => void
  setWsConnected: (connected: boolean) => void
  setLastEventTime: (time: string) => void
}

export const useStore = create<ThreatVisionState>()(
  devtools(
    (set, get) => ({
      incidents: [],
      alerts: [],
      threats: [],
      metrics: null,
      simulations: [],
      selectedIncidentId: null,
      wsConnected: false,
      lastEventTime: null,

      setIncidents: (incidents) => set({ incidents }),
      prependIncident: (incident) =>
        set((state) => ({
          incidents: [incident as Incident, ...state.incidents.slice(0, 99)],
        })),
      updateIncident: (id, patch) =>
        set((state) => ({
          incidents: state.incidents.map((i) =>
            i.id === id ? { ...i, ...patch } : i
          ),
        })),

      setAlerts: (alerts) => set({ alerts }),
      prependAlert: (alert) =>
        set((state) => ({
          alerts: [alert as Alert, ...state.alerts.slice(0, 199)],
        })),

      setThreats: (threats) => set({ threats }),
      prependThreat: (threat) =>
        set((state) => ({
          threats: [threat as ThreatEvent, ...state.threats.slice(0, 499)],
        })),

      setMetrics: (metrics) => set({ metrics }),
      setSimulations: (simulations) => set({ simulations }),
      upsertSimulation: (sim) =>
        set((state) => {
          const idx = state.simulations.findIndex((s) => s.id === sim.id)
          if (idx >= 0) {
            const updated = [...state.simulations]
            updated[idx] = { ...updated[idx], ...sim }
            return { simulations: updated }
          }
          return { simulations: [sim as SimulationRun, ...state.simulations] }
        }),

      setSelectedIncident: (id) => set({ selectedIncidentId: id }),
      setWsConnected: (wsConnected) => set({ wsConnected }),
      setLastEventTime: (lastEventTime) => set({ lastEventTime }),
    }),
    { name: 'ThreatVisionStore' }
  )
)
