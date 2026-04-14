'use client'

import { useEffect, useState, useCallback } from 'react'
import { Shield, ArrowLeft, Users, Award, Clock, CheckCircle, Wifi, WifiOff, ChevronDown } from 'lucide-react'
import Link from 'next/link'
import { analystsApi } from '@/lib/api'
import { useWebSocket } from '@/lib/websocket'
import { showToast } from '@/lib/toast'
import SLATimer from '@/components/tickets/SLATimer'
import type { Analyst, Ticket, LeaderboardEntry } from '@/types'

// ── Helpers ───────────────────────────────────────────────────────────────────

function getInitials(name: string) {
  return name.split(' ').map((n) => n[0]).join('').toUpperCase().slice(0, 2)
}

const TIER_COLOR: Record<number, string> = {
  3: '#00d4ff',
  2: '#ffb800',
  1: '#6b7a99',
}

const AVAIL_COLOR: Record<string, string> = {
  online: '#00ff9d',
  busy: '#ffb800',
  offline: '#6b7a99',
}

const SEV_COLOR: Record<string, string> = {
  CRITICAL: '#ff3b6b',
  HIGH: '#ff6b35',
  MEDIUM: '#ffb800',
  LOW: '#00ff9d',
}

function NavBar() {
  return (
    <header
      style={{
        height: 56,
        background: '#0f1629',
        borderBottom: '1px solid #1e2d4a',
        display: 'flex',
        alignItems: 'center',
        padding: '0 20px',
        gap: 20,
        flexShrink: 0,
        zIndex: 40,
      }}
    >
      <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
        <div
          style={{
            width: 32, height: 32, borderRadius: 8,
            display: 'flex', alignItems: 'center', justifyContent: 'center',
            background: 'rgba(0,212,255,0.15)', border: '1px solid rgba(0,212,255,0.3)',
          }}
        >
          <Shield size={16} color="#00d4ff" />
        </div>
        <span style={{ color: '#e8eaf0', fontWeight: 700, fontSize: 15 }}>SentinelAI</span>
      </div>

      <nav style={{ display: 'flex', gap: 4 }}>
        {[
          { href: '/dashboard', label: 'SOC Dashboard' },
          { href: '/analysts', label: 'Analysts' },
          { href: '/tickets', label: 'Tickets' },
        ].map(({ href, label }) => {
          const active = typeof window !== 'undefined' && window.location.pathname === href
          return (
            <Link
              key={href}
              href={href}
              style={{
                color: active ? '#00d4ff' : '#6b7a99',
                fontSize: 13,
                textDecoration: 'none',
                padding: '4px 12px',
                borderRadius: 6,
                background: active ? 'rgba(0,212,255,0.08)' : 'transparent',
                fontWeight: active ? 600 : 400,
                transition: 'all 0.15s',
              }}
            >
              {label}
            </Link>
          )
        })}
      </nav>

      <div style={{ marginLeft: 'auto' }}>
        <Link
          href="/dashboard"
          style={{
            color: '#6b7a99', fontSize: 12, textDecoration: 'none',
            display: 'flex', alignItems: 'center', gap: 4,
          }}
        >
          <ArrowLeft size={14} /> Back to SOC
        </Link>
      </div>
    </header>
  )
}

// ── Analyst Card (left panel list item) ───────────────────────────────────────

function AnalystCard({
  analyst,
  selected,
  onClick,
}: {
  analyst: Analyst
  selected: boolean
  onClick: () => void
}) {
  const tierColor = TIER_COLOR[analyst.tier] || '#6b7a99'
  const availColor = AVAIL_COLOR[analyst.availability] || '#6b7a99'
  const pct = analyst.workload_percentage

  return (
    <button
      onClick={onClick}
      style={{
        width: '100%',
        background: selected ? 'rgba(0,212,255,0.06)' : 'transparent',
        border: `1px solid ${selected ? 'rgba(0,212,255,0.25)' : 'transparent'}`,
        borderRadius: 8,
        padding: '10px 12px',
        cursor: 'pointer',
        textAlign: 'left',
        transition: 'all 0.15s',
        display: 'flex',
        alignItems: 'center',
        gap: 10,
      }}
      onMouseEnter={(e) => {
        if (!selected) (e.currentTarget as HTMLButtonElement).style.background = 'rgba(255,255,255,0.03)'
      }}
      onMouseLeave={(e) => {
        if (!selected) (e.currentTarget as HTMLButtonElement).style.background = 'transparent'
      }}
    >
      {/* Avatar */}
      <div
        style={{
          width: 36, height: 36, borderRadius: '50%', flexShrink: 0,
          background: `${tierColor}22`,
          border: `2px solid ${tierColor}55`,
          display: 'flex', alignItems: 'center', justifyContent: 'center',
          fontSize: 12, fontWeight: 700, color: tierColor,
          position: 'relative',
        }}
      >
        {getInitials(analyst.name)}
        <div
          style={{
            position: 'absolute', bottom: 1, right: 1,
            width: 8, height: 8, borderRadius: '50%',
            background: availColor,
            border: '1.5px solid #141d35',
          }}
        />
      </div>

      {/* Info */}
      <div style={{ flex: 1, minWidth: 0 }}>
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
          <span style={{ color: '#e8eaf0', fontSize: 13, fontWeight: 600 }}>
            {analyst.name}
          </span>
          <span
            style={{
              fontSize: 9, fontWeight: 700, color: tierColor,
              background: `${tierColor}18`, border: `1px solid ${tierColor}44`,
              borderRadius: 3, padding: '1px 5px',
            }}
          >
            T{analyst.tier}
          </span>
        </div>
        <div style={{ display: 'flex', alignItems: 'center', gap: 6, marginTop: 4 }}>
          <div style={{ flex: 1, height: 3, background: '#1e2d4a', borderRadius: 2, overflow: 'hidden' }}>
            <div
              style={{
                height: '100%', borderRadius: 2,
                width: `${Math.min(pct, 100)}%`,
                background: pct > 80 ? '#ff3b6b' : pct > 50 ? '#ffb800' : '#00ff9d',
                transition: 'width 0.5s',
              }}
            />
          </div>
          <span style={{ fontSize: 10, color: '#6b7a99', whiteSpace: 'nowrap' }}>
            {analyst.current_ticket_count}/{analyst.max_tickets}
          </span>
        </div>
      </div>
    </button>
  )
}

// ── Analyst Detail (right panel) ──────────────────────────────────────────────

function AnalystDetail({
  analyst,
  onUpdate,
}: {
  analyst: Analyst
  onUpdate: (updated: Analyst) => void
}) {
  const [tickets, setTickets] = useState<Ticket[]>([])
  const [loadingTickets, setLoadingTickets] = useState(false)
  const [updatingAvail, setUpdatingAvail] = useState(false)

  const tierColor = TIER_COLOR[analyst.tier] || '#6b7a99'
  const pct = analyst.workload_percentage

  useEffect(() => {
    setLoadingTickets(true)
    analystsApi.getTickets(analyst.id)
      .then(setTickets)
      .catch(() => {})
      .finally(() => setLoadingTickets(false))
  }, [analyst.id])

  const handleAvailability = async (val: string) => {
    setUpdatingAvail(true)
    try {
      const updated = await analystsApi.updateAvailability(analyst.id, val)
      onUpdate(updated)
      showToast(`${analyst.name} is now ${val}`, 'info')
    } catch {
      showToast('Failed to update availability', 'error')
    } finally {
      setUpdatingAvail(false)
    }
  }

  return (
    <div style={{ padding: 24, height: '100%', overflowY: 'auto' }}>
      {/* Header */}
      <div style={{ display: 'flex', alignItems: 'flex-start', gap: 16, marginBottom: 24 }}>
        <div
          style={{
            width: 60, height: 60, borderRadius: '50%',
            background: `${tierColor}22`, border: `2px solid ${tierColor}66`,
            display: 'flex', alignItems: 'center', justifyContent: 'center',
            fontSize: 20, fontWeight: 700, color: tierColor, flexShrink: 0,
          }}
        >
          {getInitials(analyst.name)}
        </div>
        <div style={{ flex: 1 }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
            <h2 style={{ color: '#e8eaf0', fontSize: 18, fontWeight: 700, margin: 0 }}>
              {analyst.name}
            </h2>
            <span
              style={{
                fontSize: 10, fontWeight: 700, color: tierColor,
                background: `${tierColor}18`, border: `1px solid ${tierColor}44`,
                borderRadius: 4, padding: '2px 8px',
              }}
            >
              Tier {analyst.tier}
            </span>
          </div>
          <p style={{ color: '#6b7a99', fontSize: 12, margin: '4px 0 0' }}>{analyst.email}</p>
        </div>

        {/* Availability dropdown */}
        <div style={{ position: 'relative' }}>
          <select
            value={analyst.availability}
            disabled={updatingAvail}
            onChange={(e) => handleAvailability(e.target.value)}
            style={{
              background: '#1a2540',
              border: `1px solid ${AVAIL_COLOR[analyst.availability]}55`,
              color: AVAIL_COLOR[analyst.availability],
              borderRadius: 6, padding: '5px 28px 5px 10px',
              fontSize: 12, fontWeight: 600, cursor: 'pointer',
              appearance: 'none', outline: 'none',
              opacity: updatingAvail ? 0.5 : 1,
            }}
          >
            <option value="online">● Online</option>
            <option value="busy">⊙ Busy</option>
            <option value="offline">○ Offline</option>
          </select>
          <ChevronDown size={12} style={{ position: 'absolute', right: 8, top: '50%', transform: 'translateY(-50%)', color: '#6b7a99', pointerEvents: 'none' }} />
        </div>
      </div>

      {/* Skills */}
      <div style={{ marginBottom: 20 }}>
        <p style={{ color: '#6b7a99', fontSize: 10, fontWeight: 700, textTransform: 'uppercase', letterSpacing: '0.1em', marginBottom: 8 }}>Skills</p>
        <div style={{ display: 'flex', flexWrap: 'wrap', gap: 6 }}>
          {analyst.skills.map((skill) => (
            <span
              key={skill}
              style={{
                fontSize: 11, color: '#00d4ff', fontWeight: 600,
                background: 'rgba(0,212,255,0.08)', border: '1px solid rgba(0,212,255,0.2)',
                borderRadius: 20, padding: '3px 10px',
              }}
            >
              {skill}
            </span>
          ))}
        </div>
      </div>

      {/* Stats */}
      <div
        style={{
          display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)',
          gap: 10, marginBottom: 20,
        }}
      >
        {[
          { label: 'Workload', value: `${Math.round(pct)}%`, color: pct > 80 ? '#ff3b6b' : pct > 50 ? '#ffb800' : '#00ff9d' },
          { label: 'Avg Resolve', value: `${analyst.avg_resolution_hours.toFixed(1)}h`, color: '#00d4ff' },
          { label: 'Total Resolved', value: analyst.total_resolved, color: '#00ff9d' },
          { label: 'Success Rate', value: `${Math.round(analyst.success_rate * 100)}%`, color: '#00d4ff' },
        ].map((stat) => (
          <div
            key={stat.label}
            style={{
              background: '#1a2540', border: '1px solid #1e2d4a',
              borderRadius: 8, padding: '10px 12px', textAlign: 'center',
            }}
          >
            <p style={{ color: stat.color as string, fontSize: 18, fontWeight: 700, margin: 0 }}>{stat.value}</p>
            <p style={{ color: '#6b7a99', fontSize: 10, margin: '3px 0 0' }}>{stat.label}</p>
          </div>
        ))}
      </div>

      {/* Workload bar */}
      <div style={{ marginBottom: 24 }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 6 }}>
          <span style={{ color: '#6b7a99', fontSize: 11 }}>Workload</span>
          <span style={{ color: '#e8eaf0', fontSize: 11 }}>{analyst.current_ticket_count} / {analyst.max_tickets} tickets</span>
        </div>
        <div style={{ height: 8, background: '#1e2d4a', borderRadius: 4, overflow: 'hidden' }}>
          <div
            style={{
              height: '100%', borderRadius: 4,
              width: `${Math.min(pct, 100)}%`,
              background: pct > 80 ? 'linear-gradient(90deg,#ff3b6b,#ff6b35)' : pct > 50 ? 'linear-gradient(90deg,#ffb800,#ff6b35)' : 'linear-gradient(90deg,#00ff9d,#00d4ff)',
              transition: 'width 0.5s',
            }}
          />
        </div>
      </div>

      {/* Assigned tickets */}
      <div>
        <p style={{ color: '#6b7a99', fontSize: 10, fontWeight: 700, textTransform: 'uppercase', letterSpacing: '0.1em', marginBottom: 10 }}>
          Assigned Tickets ({tickets.length})
        </p>
        {loadingTickets ? (
          <p style={{ color: '#6b7a99', fontSize: 12 }}>Loading…</p>
        ) : tickets.length === 0 ? (
          <p style={{ color: '#1e2d4a', fontSize: 12 }}>No active tickets</p>
        ) : (
          <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
            {tickets.map((t) => (
              <Link
                key={t.id}
                href={`/tickets?selected=${t.id}`}
                style={{
                  display: 'flex', alignItems: 'center', gap: 10,
                  background: '#1a2540', border: '1px solid #1e2d4a',
                  borderLeft: `3px solid ${SEV_COLOR[t.severity] || '#6b7a99'}`,
                  borderRadius: 6, padding: '8px 12px',
                  textDecoration: 'none', transition: 'background 0.15s',
                }}
              >
                <span style={{ color: '#6b7a99', fontSize: 10, fontFamily: 'monospace', flexShrink: 0 }}>
                  TICK-{String(t.ticket_number).padStart(4, '0')}
                </span>
                <span
                  style={{
                    fontSize: 9, fontWeight: 700, flexShrink: 0,
                    color: SEV_COLOR[t.severity],
                    background: `${SEV_COLOR[t.severity]}18`,
                    border: `1px solid ${SEV_COLOR[t.severity]}44`,
                    borderRadius: 3, padding: '1px 5px',
                  }}
                >
                  {t.severity}
                </span>
                <span style={{ color: '#e8eaf0', fontSize: 12, flex: 1, minWidth: 0, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                  {t.title}
                </span>
                <SLATimer deadline={t.sla_deadline} breached={t.sla_breached} size="sm" />
              </Link>
            ))}
          </div>
        )}
      </div>
    </div>
  )
}

// ── Leaderboard ───────────────────────────────────────────────────────────────

const RANK_COLORS = ['#ffd700', '#c0c0c0', '#cd7f32']
const RANK_LABELS = ['🥇', '🥈', '🥉']

function AnalystLeaderboard({ entries }: { entries: LeaderboardEntry[] }) {
  return (
    <div>
      <p style={{ color: '#6b7a99', fontSize: 10, fontWeight: 700, textTransform: 'uppercase', letterSpacing: '0.1em', marginBottom: 10, margin: '0 0 10px' }}>
        Leaderboard
      </p>
      {entries.length === 0 ? (
        <p style={{ color: '#1e2d4a', fontSize: 11 }}>No data yet</p>
      ) : (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
          {entries.map((entry) => {
            const rankColor = RANK_COLORS[entry.rank - 1] || '#6b7a99'
            const rankLabel = RANK_LABELS[entry.rank - 1] || `#${entry.rank}`
            const analyst = entry.analyst
            return (
              <div
                key={analyst.id}
                style={{
                  display: 'flex', alignItems: 'center', gap: 10,
                  background: entry.rank <= 3 ? `${rankColor}08` : 'transparent',
                  borderRadius: 6, padding: '7px 10px',
                  border: `1px solid ${entry.rank <= 3 ? `${rankColor}25` : 'transparent'}`,
                }}
              >
                <span style={{ fontSize: 14, width: 20, flexShrink: 0 }}>{rankLabel}</span>
                <div
                  style={{
                    width: 26, height: 26, borderRadius: '50%', flexShrink: 0,
                    background: `${TIER_COLOR[analyst.tier] || '#6b7a99'}22`,
                    border: `1.5px solid ${TIER_COLOR[analyst.tier] || '#6b7a99'}55`,
                    display: 'flex', alignItems: 'center', justifyContent: 'center',
                    fontSize: 9, fontWeight: 700, color: TIER_COLOR[analyst.tier] || '#6b7a99',
                  }}
                >
                  {getInitials(analyst.name)}
                </div>
                <span style={{ color: '#e8eaf0', fontSize: 12, fontWeight: 600, flex: 1 }}>
                  {analyst.name.split(' ')[0]}
                </span>
                <div style={{ textAlign: 'right' }}>
                  <p style={{ color: rankColor, fontSize: 12, fontWeight: 700, margin: 0 }}>
                    {Math.round(entry.sla_compliance_rate * 100)}%
                  </p>
                  <p style={{ color: '#6b7a99', fontSize: 9, margin: 0 }}>
                    {entry.tickets_this_week ?? 0} this wk
                  </p>
                </div>
              </div>
            )
          })}
        </div>
      )}
    </div>
  )
}

// ── Page ──────────────────────────────────────────────────────────────────────

export default function AnalystsPage() {
  const [analysts, setAnalysts] = useState<Analyst[]>([])
  const [leaderboard, setLeaderboard] = useState<LeaderboardEntry[]>([])
  const [selectedId, setSelectedId] = useState<string | null>(null)
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    const load = async () => {
      try {
        const [a, l] = await Promise.allSettled([
          analystsApi.list(),
          analystsApi.getLeaderboard(),
        ])
        if (a.status === 'fulfilled') {
          setAnalysts(a.value)
          if (a.value.length > 0) setSelectedId(a.value[0].id)
        }
        if (l.status === 'fulfilled') setLeaderboard(l.value)
      } finally {
        setLoading(false)
      }
    }
    load()
  }, [])

  // WebSocket updates
  useWebSocket('analyst_update', useCallback((data: unknown) => {
    const updated = data as Analyst
    setAnalysts((prev) => prev.map((a) => a.id === updated.id ? updated : a))
  }, []))

  const handleUpdate = useCallback((updated: Analyst) => {
    setAnalysts((prev) => prev.map((a) => a.id === updated.id ? updated : a))
  }, [])

  const selectedAnalyst = analysts.find((a) => a.id === selectedId) ?? null

  return (
    <div style={{ display: 'flex', flexDirection: 'column', height: '100vh', background: '#0a0e1a' }}>
      <NavBar />

      {loading ? (
        <div style={{ flex: 1, display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
          <p style={{ color: '#6b7a99', fontSize: 14 }}>Loading analysts…</p>
        </div>
      ) : (
        <div style={{ flex: 1, display: 'flex', gap: 0, overflow: 'hidden' }}>

          {/* ── LEFT SIDEBAR ── */}
          <div
            style={{
              width: 300, flexShrink: 0, display: 'flex', flexDirection: 'column',
              background: '#0f1629', borderRight: '1px solid #1e2d4a', overflow: 'hidden',
            }}
          >
            {/* Roster header */}
            <div style={{ padding: '16px 16px 10px', borderBottom: '1px solid #1e2d4a', flexShrink: 0 }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                <Users size={14} color="#00d4ff" />
                <span style={{ color: '#6b7a99', fontSize: 10, fontWeight: 700, textTransform: 'uppercase', letterSpacing: '0.1em' }}>
                  Analyst Roster
                </span>
                <span
                  style={{
                    marginLeft: 'auto', fontSize: 10, color: '#00d4ff',
                    background: 'rgba(0,212,255,0.1)', border: '1px solid rgba(0,212,255,0.2)',
                    borderRadius: 3, padding: '1px 6px',
                  }}
                >
                  {analysts.length} analysts
                </span>
              </div>
            </div>

            {/* Analyst cards */}
            <div style={{ flex: 1, overflowY: 'auto', padding: '8px 10px' }}>
              {analysts.map((analyst) => (
                <AnalystCard
                  key={analyst.id}
                  analyst={analyst}
                  selected={analyst.id === selectedId}
                  onClick={() => setSelectedId(analyst.id)}
                />
              ))}
            </div>

            {/* Leaderboard */}
            <div
              style={{
                borderTop: '1px solid #1e2d4a', padding: 14,
                background: '#0a0e1a', flexShrink: 0,
              }}
            >
              <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 10 }}>
                <Award size={13} color="#ffb800" />
                <span style={{ color: '#6b7a99', fontSize: 10, fontWeight: 700, textTransform: 'uppercase', letterSpacing: '0.1em' }}>
                  Leaderboard
                </span>
              </div>
              <AnalystLeaderboard entries={leaderboard} />
            </div>
          </div>

          {/* ── RIGHT DETAIL ── */}
          <div style={{ flex: 1, overflow: 'hidden' }}>
            {selectedAnalyst ? (
              <AnalystDetail analyst={selectedAnalyst} onUpdate={handleUpdate} />
            ) : (
              <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', height: '100%' }}>
                <p style={{ color: '#1e2d4a', fontSize: 14 }}>Select an analyst to view details</p>
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  )
}
