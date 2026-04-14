'use client'

import { useEffect, useState, useCallback, useRef, Suspense } from 'react'
import { Shield, ArrowLeft, AlertTriangle, Clock, CheckCircle, XCircle, Filter, ChevronRight, X, Send, RotateCcw } from 'lucide-react'
import Link from 'next/link'
import { useSearchParams } from 'next/navigation'
import { ticketsApi, analystsApi } from '@/lib/api'
import { useWebSocket } from '@/lib/websocket'
import { showToast } from '@/lib/toast'
import SLATimer from '@/components/tickets/SLATimer'
import type { Ticket, TicketStats, Analyst } from '@/types'

// ── Helpers ───────────────────────────────────────────────────────────────────

const SEV_COLOR: Record<string, string> = {
  CRITICAL: '#ff3b6b',
  HIGH: '#ff6b35',
  MEDIUM: '#ffb800',
  LOW: '#00ff9d',
}

const STATUS_COLOR: Record<string, string> = {
  open: '#6b7a99',
  in_progress: '#00d4ff',
  resolved: '#00ff9d',
  escalated: '#ff6b35',
  closed: '#1e2d4a',
}

function formatRelative(iso: string): string {
  const diff = Date.now() - new Date(iso).getTime()
  const sec = Math.floor(diff / 1000)
  if (sec < 60) return `${sec}s ago`
  const min = Math.floor(sec / 60)
  if (min < 60) return `${min}m ago`
  const hr = Math.floor(min / 60)
  if (hr < 24) return `${hr}h ago`
  return `${Math.floor(hr / 24)}d ago`
}

const ACTIVITY_ICONS: Record<string, string> = {
  created: '●',
  assigned: '→',
  acknowledged: '✓',
  resolved: '✔',
  escalated: '↑',
  comment: '💬',
  sla_breached: '⚠️',
  reassigned: '↔',
}

// ── Nav Bar ───────────────────────────────────────────────────────────────────

function NavBar() {
  return (
    <header
      style={{
        height: 56, background: '#0f1629', borderBottom: '1px solid #1e2d4a',
        display: 'flex', alignItems: 'center', padding: '0 20px',
        gap: 20, flexShrink: 0, zIndex: 40,
      }}
    >
      <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
        <div
          style={{
            width: 32, height: 32, borderRadius: 8, display: 'flex', alignItems: 'center', justifyContent: 'center',
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
            <Link key={href} href={href} style={{
              color: active ? '#00d4ff' : '#6b7a99', fontSize: 13, textDecoration: 'none',
              padding: '4px 12px', borderRadius: 6,
              background: active ? 'rgba(0,212,255,0.08)' : 'transparent',
              fontWeight: active ? 600 : 400, transition: 'all 0.15s',
            }}>
              {label}
            </Link>
          )
        })}
      </nav>

      <div style={{ marginLeft: 'auto' }}>
        <Link href="/dashboard" style={{ color: '#6b7a99', fontSize: 12, textDecoration: 'none', display: 'flex', alignItems: 'center', gap: 4 }}>
          <ArrowLeft size={14} /> Back to SOC
        </Link>
      </div>
    </header>
  )
}

// ── Stats Bar ─────────────────────────────────────────────────────────────────

function StatsBar({ stats }: { stats: TicketStats | null }) {
  if (!stats) return null
  const chips = [
    { label: 'Open', value: stats.open, color: '#6b7a99', bg: 'rgba(107,122,153,0.1)' },
    { label: 'In Progress', value: (stats.acknowledged || 0) + (stats.in_progress || 0), color: '#00d4ff', bg: 'rgba(0,212,255,0.1)' },
    { label: 'Resolved', value: stats.resolved, color: '#00ff9d', bg: 'rgba(0,255,157,0.1)' },
    { label: 'SLA Breached', value: stats.sla_breached, color: stats.sla_breached > 0 ? '#ff3b6b' : '#6b7a99', bg: stats.sla_breached > 0 ? 'rgba(255,59,107,0.1)' : 'rgba(107,122,153,0.08)' },
    { label: 'Critical', value: stats.by_severity?.CRITICAL || 0, color: '#ff3b6b', bg: 'rgba(255,59,107,0.08)' },
  ]
  return (
    <div style={{ display: 'flex', gap: 10, padding: '10px 16px', borderBottom: '1px solid #1e2d4a', flexShrink: 0, background: '#0f1629' }}>
      {chips.map((c) => (
        <div key={c.label} style={{ display: 'flex', alignItems: 'center', gap: 8, background: c.bg, border: `1px solid ${c.color}33`, borderRadius: 8, padding: '6px 14px' }}>
          <span style={{ color: c.color, fontSize: 18, fontWeight: 700, fontFamily: 'monospace' }}>{c.value}</span>
          <span style={{ color: '#6b7a99', fontSize: 11 }}>{c.label}</span>
        </div>
      ))}
      <div style={{ marginLeft: 'auto', display: 'flex', alignItems: 'center' }}>
        <span style={{ color: '#1e2d4a', fontSize: 10 }}>Auto-refreshes every 30s</span>
      </div>
    </div>
  )
}

// ── Filter Panel ──────────────────────────────────────────────────────────────

interface Filters {
  status: string
  severity: string
  type: string
  slaOnly: boolean
}

function FilterPanel({ filters, onChange }: { filters: Filters; onChange: (f: Filters) => void }) {
  const sel = (key: keyof Filters, val: string | boolean) => onChange({ ...filters, [key]: val })

  const SelectRow = ({ label, field, options }: { label: string; field: keyof Filters; options: { value: string; label: string }[] }) => (
    <div style={{ marginBottom: 14 }}>
      <p style={{ color: '#6b7a99', fontSize: 10, fontWeight: 700, textTransform: 'uppercase', letterSpacing: '0.08em', marginBottom: 6 }}>{label}</p>
      <div style={{ display: 'flex', flexDirection: 'column', gap: 3 }}>
        {options.map((o) => (
          <button
            key={o.value}
            onClick={() => sel(field, o.value)}
            style={{
              background: (filters[field] as string) === o.value ? 'rgba(0,212,255,0.1)' : 'transparent',
              border: `1px solid ${(filters[field] as string) === o.value ? 'rgba(0,212,255,0.3)' : 'transparent'}`,
              color: (filters[field] as string) === o.value ? '#00d4ff' : '#6b7a99',
              borderRadius: 5, padding: '5px 10px', cursor: 'pointer',
              textAlign: 'left', fontSize: 12, transition: 'all 0.1s',
            }}
          >
            {o.label}
          </button>
        ))}
      </div>
    </div>
  )

  return (
    <div style={{ width: 200, flexShrink: 0, background: '#0f1629', borderRight: '1px solid #1e2d4a', padding: 16, overflowY: 'auto' }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: 6, marginBottom: 16 }}>
        <Filter size={13} color="#6b7a99" />
        <span style={{ color: '#6b7a99', fontSize: 10, fontWeight: 700, textTransform: 'uppercase', letterSpacing: '0.1em' }}>Filters</span>
      </div>

      <SelectRow label="Status" field="status" options={[
        { value: '', label: 'All' },
        { value: 'open', label: 'Open' },
        { value: 'in_progress', label: 'In Progress' },
        { value: 'resolved', label: 'Resolved' },
        { value: 'escalated', label: 'Escalated' },
      ]} />

      <SelectRow label="Severity" field="severity" options={[
        { value: '', label: 'All' },
        { value: 'CRITICAL', label: 'Critical' },
        { value: 'HIGH', label: 'High' },
        { value: 'MEDIUM', label: 'Medium' },
        { value: 'LOW', label: 'Low' },
      ]} />

      <SelectRow label="Type" field="type" options={[
        { value: '', label: 'All' },
        { value: 'web', label: 'Web' },
        { value: 'network', label: 'Network' },
        { value: 'llm', label: 'LLM' },
        { value: 'cloud', label: 'Cloud' },
        { value: 'api', label: 'API' },
      ]} />

      <div style={{ marginTop: 8 }}>
        <button
          onClick={() => sel('slaOnly', !filters.slaOnly)}
          style={{
            width: '100%', display: 'flex', alignItems: 'center', gap: 8,
            background: filters.slaOnly ? 'rgba(255,59,107,0.1)' : 'transparent',
            border: `1px solid ${filters.slaOnly ? 'rgba(255,59,107,0.3)' : '#1e2d4a'}`,
            borderRadius: 6, padding: '7px 10px', cursor: 'pointer', transition: 'all 0.1s',
          }}
        >
          <div style={{
            width: 14, height: 14, borderRadius: 3, border: `2px solid ${filters.slaOnly ? '#ff3b6b' : '#1e2d4a'}`,
            background: filters.slaOnly ? '#ff3b6b' : 'transparent', flexShrink: 0,
            display: 'flex', alignItems: 'center', justifyContent: 'center',
          }}>
            {filters.slaOnly && <span style={{ color: '#fff', fontSize: 9, fontWeight: 700 }}>✓</span>}
          </div>
          <span style={{ color: filters.slaOnly ? '#ff3b6b' : '#6b7a99', fontSize: 12 }}>SLA Breach Only</span>
        </button>
      </div>
    </div>
  )
}

// ── Ticket List Item ──────────────────────────────────────────────────────────

function TicketItem({ ticket, selected, onClick }: { ticket: Ticket; selected: boolean; onClick: () => void }) {
  const sevColor = SEV_COLOR[ticket.severity] || '#6b7a99'

  return (
    <button
      onClick={onClick}
      style={{
        width: '100%', textAlign: 'left', cursor: 'pointer', transition: 'all 0.1s',
        background: selected ? 'rgba(0,212,255,0.05)' : 'transparent',
        border: `1px solid ${selected ? 'rgba(0,212,255,0.2)' : '#1e2d4a'}`,
        borderLeft: `3px solid ${sevColor}`,
        borderRadius: 6, padding: '10px 14px', marginBottom: 6,
        ...(ticket.sla_breached ? { animation: 'sentinelPulse 2s ease-in-out infinite' } : {}),
      }}
    >
      <div style={{ display: 'flex', alignItems: 'flex-start', gap: 10 }}>
        <div style={{ flex: 1, minWidth: 0 }}>
          {/* Row 1: number + severity + title */}
          <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 4 }}>
            <span style={{ color: '#6b7a99', fontSize: 10, fontFamily: 'monospace', flexShrink: 0 }}>
              TICK-{String(ticket.ticket_number).padStart(4, '0')}
            </span>
            <span style={{
              fontSize: 9, fontWeight: 700, flexShrink: 0,
              color: sevColor, background: `${sevColor}18`, border: `1px solid ${sevColor}44`,
              borderRadius: 3, padding: '1px 5px',
            }}>
              {ticket.severity}
            </span>
            {ticket.sla_breached && (
              <span style={{ fontSize: 9, color: '#ff3b6b', fontWeight: 700 }}>⚠ SLA</span>
            )}
          </div>

          {/* Row 2: title */}
          <p style={{ color: '#e8eaf0', fontSize: 13, fontWeight: 600, margin: '0 0 6px', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
            {ticket.title}
          </p>

          {/* Row 3: analyst + SLA + source */}
          <div style={{ display: 'flex', alignItems: 'center', gap: 10, flexWrap: 'wrap' }}>
            <span style={{ color: ticket.assigned_analyst_name ? '#6b7a99' : '#1e2d4a', fontSize: 11 }}>
              → {ticket.assigned_analyst_name || 'Unassigned'}
            </span>
            <SLATimer deadline={ticket.sla_deadline} breached={ticket.sla_breached} size="sm" />
            <span style={{
              fontSize: 9, color: '#6b7a99', background: '#1a2540',
              border: '1px solid #1e2d4a', borderRadius: 3, padding: '1px 6px',
            }}>
              {ticket.source_type}
            </span>
            <span style={{
              fontSize: 9, padding: '1px 6px', borderRadius: 3,
              color: STATUS_COLOR[ticket.status] || '#6b7a99',
              background: `${STATUS_COLOR[ticket.status] || '#6b7a99'}18`,
              border: `1px solid ${STATUS_COLOR[ticket.status] || '#6b7a99'}44`,
            }}>
              {ticket.status.replace('_', ' ')}
            </span>
          </div>
        </div>
        <ChevronRight size={14} color={selected ? '#00d4ff' : '#1e2d4a'} style={{ flexShrink: 0, marginTop: 4 }} />
      </div>
    </button>
  )
}

// ── Ticket Detail Panel ───────────────────────────────────────────────────────

function ResolveModal({ ticket, analysts, onClose, onResolve }: {
  ticket: Ticket
  analysts: Analyst[]
  onClose: () => void
  onResolve: (notes: string, type: string) => void
}) {
  const [notes, setNotes] = useState('')
  const [type, setType] = useState('true_positive')

  return (
    <div style={{
      position: 'fixed', inset: 0, zIndex: 1000,
      background: 'rgba(0,0,0,0.7)', display: 'flex', alignItems: 'center', justifyContent: 'center',
    }}>
      <div style={{ background: '#141d35', border: '1px solid #1e2d4a', borderRadius: 12, padding: 24, width: 440, maxWidth: '90vw' }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 20 }}>
          <h3 style={{ color: '#e8eaf0', fontSize: 16, fontWeight: 700, margin: 0 }}>Resolve Ticket</h3>
          <button onClick={onClose} style={{ background: 'none', border: 'none', cursor: 'pointer', color: '#6b7a99' }}>
            <X size={18} />
          </button>
        </div>
        <div style={{ marginBottom: 16 }}>
          <label style={{ color: '#6b7a99', fontSize: 11, fontWeight: 700, textTransform: 'uppercase', letterSpacing: '0.08em', display: 'block', marginBottom: 6 }}>
            Resolution Type
          </label>
          <select value={type} onChange={(e) => setType(e.target.value)} style={{
            width: '100%', background: '#1a2540', border: '1px solid #1e2d4a',
            color: '#e8eaf0', borderRadius: 6, padding: '8px 12px', fontSize: 13, outline: 'none',
          }}>
            <option value="true_positive">True Positive</option>
            <option value="false_positive">False Positive</option>
            <option value="contained">Contained</option>
            <option value="mitigated">Mitigated</option>
          </select>
        </div>
        <div style={{ marginBottom: 20 }}>
          <label style={{ color: '#6b7a99', fontSize: 11, fontWeight: 700, textTransform: 'uppercase', letterSpacing: '0.08em', display: 'block', marginBottom: 6 }}>
            Resolution Notes
          </label>
          <textarea
            value={notes}
            onChange={(e) => setNotes(e.target.value)}
            placeholder="Describe the resolution…"
            rows={4}
            style={{
              width: '100%', background: '#1a2540', border: '1px solid #1e2d4a',
              color: '#e8eaf0', borderRadius: 6, padding: '8px 12px', fontSize: 13,
              outline: 'none', resize: 'vertical', fontFamily: 'inherit', boxSizing: 'border-box',
            }}
          />
        </div>
        <div style={{ display: 'flex', gap: 10, justifyContent: 'flex-end' }}>
          <button onClick={onClose} style={{ background: 'transparent', border: '1px solid #1e2d4a', color: '#6b7a99', borderRadius: 6, padding: '8px 16px', cursor: 'pointer', fontSize: 13 }}>
            Cancel
          </button>
          <button
            onClick={() => onResolve(notes, type)}
            disabled={!notes.trim()}
            style={{
              background: notes.trim() ? 'rgba(0,255,157,0.15)' : '#1a2540',
              border: `1px solid ${notes.trim() ? 'rgba(0,255,157,0.4)' : '#1e2d4a'}`,
              color: notes.trim() ? '#00ff9d' : '#6b7a99', borderRadius: 6,
              padding: '8px 20px', cursor: notes.trim() ? 'pointer' : 'default', fontSize: 13, fontWeight: 600,
            }}
          >
            Resolve
          </button>
        </div>
      </div>
    </div>
  )
}

function EscalateModal({ onClose, onEscalate }: { onClose: () => void; onEscalate: (reason: string) => void }) {
  const [reason, setReason] = useState('')
  return (
    <div style={{ position: 'fixed', inset: 0, zIndex: 1000, background: 'rgba(0,0,0,0.7)', display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
      <div style={{ background: '#141d35', border: '1px solid #1e2d4a', borderRadius: 12, padding: 24, width: 400, maxWidth: '90vw' }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 20 }}>
          <h3 style={{ color: '#ffb800', fontSize: 16, fontWeight: 700, margin: 0 }}>Escalate Ticket</h3>
          <button onClick={onClose} style={{ background: 'none', border: 'none', cursor: 'pointer', color: '#6b7a99' }}><X size={18} /></button>
        </div>
        <textarea
          value={reason}
          onChange={(e) => setReason(e.target.value)}
          placeholder="Reason for escalation…"
          rows={4}
          style={{
            width: '100%', background: '#1a2540', border: '1px solid #1e2d4a',
            color: '#e8eaf0', borderRadius: 6, padding: '8px 12px', fontSize: 13,
            outline: 'none', resize: 'vertical', fontFamily: 'inherit', marginBottom: 16, boxSizing: 'border-box',
          }}
        />
        <div style={{ display: 'flex', gap: 10, justifyContent: 'flex-end' }}>
          <button onClick={onClose} style={{ background: 'transparent', border: '1px solid #1e2d4a', color: '#6b7a99', borderRadius: 6, padding: '8px 16px', cursor: 'pointer', fontSize: 13 }}>Cancel</button>
          <button
            onClick={() => onEscalate(reason)}
            disabled={!reason.trim()}
            style={{
              background: reason.trim() ? 'rgba(255,184,0,0.15)' : '#1a2540',
              border: `1px solid ${reason.trim() ? 'rgba(255,184,0,0.4)' : '#1e2d4a'}`,
              color: reason.trim() ? '#ffb800' : '#6b7a99', borderRadius: 6,
              padding: '8px 20px', cursor: reason.trim() ? 'pointer' : 'default', fontSize: 13, fontWeight: 600,
            }}
          >
            Escalate
          </button>
        </div>
      </div>
    </div>
  )
}

function TicketDetailPanel({
  ticket,
  analysts,
  onClose,
  onTicketUpdate,
}: {
  ticket: Ticket
  analysts: Analyst[]
  onClose: () => void
  onTicketUpdate: (t: Ticket) => void
}) {
  const [loading, setLoading] = useState<string | null>(null)
  const [showResolve, setShowResolve] = useState(false)
  const [showEscalate, setShowEscalate] = useState(false)
  const [comment, setComment] = useState('')
  const [assigningId, setAssigningId] = useState('')

  const sevColor = SEV_COLOR[ticket.severity] || '#6b7a99'

  // Use first online analyst as "current user" for actions (simplified)
  const activeAnalyst = analysts.find((a) => a.availability === 'online') || analysts[0]

  const act = async (action: () => Promise<Ticket>, label: string) => {
    setLoading(label)
    try {
      const updated = await action()
      onTicketUpdate(updated)
      showToast(`${label} successful`, 'success')
    } catch {
      showToast(`Failed: ${label}`, 'error')
    } finally {
      setLoading(null)
    }
  }

  const handleAck = () => act(
    () => ticketsApi.acknowledge(ticket.id, activeAnalyst?.id || ''),
    'Acknowledge'
  )

  const handleResolve = (notes: string, type: string) => {
    setShowResolve(false)
    act(() => ticketsApi.resolve(ticket.id, activeAnalyst?.id || '', notes, type), 'Resolve')
  }

  const handleEscalate = (reason: string) => {
    setShowEscalate(false)
    act(() => ticketsApi.escalate(ticket.id, reason), 'Escalate')
  }

  const handleAssign = async (analystId: string) => {
    if (!analystId) return
    setLoading('Assign')
    try {
      const updated = await ticketsApi.assign(ticket.id, analystId)
      onTicketUpdate(updated)
      showToast(`Ticket reassigned`, 'success')
    } catch {
      showToast('Failed to reassign', 'error')
    } finally {
      setLoading(null)
    }
  }

  const handleComment = async () => {
    if (!comment.trim()) return
    setLoading('Comment')
    try {
      await ticketsApi.comment(ticket.id, activeAnalyst?.name || 'Analyst', comment)
      setComment('')
      // Refetch ticket to get updated activities
      const updated = await ticketsApi.get(ticket.id)
      onTicketUpdate(updated)
      showToast('Comment added', 'success')
    } catch {
      showToast('Failed to add comment', 'error')
    } finally {
      setLoading(null)
    }
  }

  const isDisabled = (label: string) => loading !== null && loading !== label

  return (
    <>
      <div
        style={{
          width: 400, flexShrink: 0, background: '#0f1629',
          borderLeft: '1px solid #1e2d4a', display: 'flex', flexDirection: 'column',
          overflow: 'hidden', height: '100%',
        }}
      >
        {/* Header */}
        <div style={{ padding: '14px 16px', borderBottom: '1px solid #1e2d4a', flexShrink: 0 }}>
          <div style={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between', gap: 10 }}>
            <div style={{ flex: 1, minWidth: 0 }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 4 }}>
                <span style={{ color: '#6b7a99', fontSize: 11, fontFamily: 'monospace' }}>
                  TICK-{String(ticket.ticket_number).padStart(4, '0')}
                </span>
                <span style={{ fontSize: 10, fontWeight: 700, color: sevColor, background: `${sevColor}18`, border: `1px solid ${sevColor}44`, borderRadius: 3, padding: '1px 6px' }}>
                  {ticket.severity}
                </span>
                <span style={{ fontSize: 10, color: STATUS_COLOR[ticket.status] || '#6b7a99', background: `${STATUS_COLOR[ticket.status] || '#6b7a99'}18`, border: `1px solid ${STATUS_COLOR[ticket.status] || '#6b7a99'}44`, borderRadius: 3, padding: '1px 6px' }}>
                  {ticket.status.replace('_', ' ')}
                </span>
              </div>
              <h3 style={{ color: '#e8eaf0', fontSize: 14, fontWeight: 700, margin: 0, lineHeight: 1.3 }}>{ticket.title}</h3>
            </div>
            <button onClick={onClose} style={{ background: 'none', border: 'none', cursor: 'pointer', color: '#6b7a99', flexShrink: 0, padding: 4 }}>
              <X size={16} />
            </button>
          </div>
        </div>

        <div style={{ flex: 1, overflowY: 'auto', padding: '14px 16px' }}>
          {/* SLA + Meta */}
          <div style={{ background: '#141d35', border: '1px solid #1e2d4a', borderRadius: 8, padding: '10px 14px', marginBottom: 14 }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 6 }}>
              <span style={{ color: '#6b7a99', fontSize: 11 }}>SLA Remaining</span>
              <SLATimer deadline={ticket.sla_deadline} breached={ticket.sla_breached} size="md" />
            </div>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 4 }}>
              <span style={{ color: '#6b7a99', fontSize: 11 }}>Assigned To</span>
              <span style={{ color: '#e8eaf0', fontSize: 12, fontWeight: 600 }}>
                {ticket.assigned_analyst_name || 'Unassigned'}
              </span>
            </div>
            {ticket.agent_confidence != null && (
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 4 }}>
                <span style={{ color: '#6b7a99', fontSize: 11 }}>Agent Confidence</span>
                <span style={{ color: '#00d4ff', fontSize: 12, fontWeight: 600 }}>{Math.round(ticket.agent_confidence * 100)}%</span>
              </div>
            )}
            {ticket.escalation_count > 0 && (
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                <span style={{ color: '#6b7a99', fontSize: 11 }}>Escalations</span>
                <span style={{ color: '#ff6b35', fontSize: 12, fontWeight: 600 }}>{ticket.escalation_count}</span>
              </div>
            )}
          </div>

          {/* Description */}
          <div style={{ marginBottom: 14 }}>
            <p style={{ color: '#6b7a99', fontSize: 10, fontWeight: 700, textTransform: 'uppercase', letterSpacing: '0.08em', marginBottom: 6 }}>Description</p>
            <p style={{ color: '#a0aec0', fontSize: 12, lineHeight: 1.6, margin: 0 }}>{ticket.description}</p>
          </div>

          {/* Actions */}
          <div style={{ marginBottom: 14 }}>
            <p style={{ color: '#6b7a99', fontSize: 10, fontWeight: 700, textTransform: 'uppercase', letterSpacing: '0.08em', marginBottom: 8 }}>Actions</p>

            <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap', marginBottom: 8 }}>
              {ticket.status === 'open' || ticket.status === 'in_progress' ? (
                <button
                  onClick={handleAck}
                  disabled={loading !== null}
                  style={{
                    background: 'rgba(0,212,255,0.1)', border: '1px solid rgba(0,212,255,0.3)',
                    color: '#00d4ff', borderRadius: 6, padding: '6px 14px', cursor: loading !== null ? 'default' : 'pointer',
                    fontSize: 12, fontWeight: 600, opacity: isDisabled('Acknowledge') ? 0.4 : 1,
                  }}
                >
                  {loading === 'Acknowledge' ? '…' : 'Acknowledge'}
                </button>
              ) : null}

              {ticket.status !== 'resolved' && ticket.status !== 'closed' && (
                <>
                  <button
                    onClick={() => setShowResolve(true)}
                    disabled={loading !== null}
                    style={{
                      background: 'rgba(0,255,157,0.1)', border: '1px solid rgba(0,255,157,0.3)',
                      color: '#00ff9d', borderRadius: 6, padding: '6px 14px', cursor: loading !== null ? 'default' : 'pointer',
                      fontSize: 12, fontWeight: 600, opacity: isDisabled('Resolve') ? 0.4 : 1,
                    }}
                  >
                    {loading === 'Resolve' ? '…' : 'Resolve'}
                  </button>
                  <button
                    onClick={() => setShowEscalate(true)}
                    disabled={loading !== null}
                    style={{
                      background: 'rgba(255,184,0,0.1)', border: '1px solid rgba(255,184,0,0.3)',
                      color: '#ffb800', borderRadius: 6, padding: '6px 14px', cursor: loading !== null ? 'default' : 'pointer',
                      fontSize: 12, fontWeight: 600, opacity: isDisabled('Escalate') ? 0.4 : 1,
                    }}
                  >
                    {loading === 'Escalate' ? '…' : 'Escalate'}
                  </button>
                </>
              )}
            </div>

            {/* Reassign */}
            {ticket.status !== 'resolved' && ticket.status !== 'closed' && analysts.length > 0 && (
              <div style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
                <select
                  value={assigningId}
                  onChange={(e) => setAssigningId(e.target.value)}
                  style={{
                    flex: 1, background: '#1a2540', border: '1px solid #1e2d4a',
                    color: assigningId ? '#e8eaf0' : '#6b7a99', borderRadius: 6,
                    padding: '6px 10px', fontSize: 12, outline: 'none',
                  }}
                >
                  <option value="">Reassign to analyst…</option>
                  {analysts.filter((a) => a.availability !== 'offline').map((a) => (
                    <option key={a.id} value={a.id}>
                      {a.name} (T{a.tier}) — {a.current_ticket_count}/{a.max_tickets}
                    </option>
                  ))}
                </select>
                <button
                  onClick={() => { handleAssign(assigningId); setAssigningId('') }}
                  disabled={!assigningId || loading !== null}
                  style={{
                    background: assigningId ? 'rgba(0,212,255,0.1)' : '#1a2540',
                    border: `1px solid ${assigningId ? 'rgba(0,212,255,0.3)' : '#1e2d4a'}`,
                    color: assigningId ? '#00d4ff' : '#6b7a99', borderRadius: 6,
                    padding: '6px 12px', cursor: assigningId ? 'pointer' : 'default', fontSize: 12,
                  }}
                >
                  {loading === 'Assign' ? '…' : 'Assign'}
                </button>
              </div>
            )}
          </div>

          {/* Comment box */}
          <div style={{ marginBottom: 16 }}>
            <p style={{ color: '#6b7a99', fontSize: 10, fontWeight: 700, textTransform: 'uppercase', letterSpacing: '0.08em', marginBottom: 8 }}>Add Comment</p>
            <div style={{ display: 'flex', gap: 8 }}>
              <textarea
                value={comment}
                onChange={(e) => setComment(e.target.value)}
                placeholder="Write a comment…"
                rows={2}
                style={{
                  flex: 1, background: '#141d35', border: '1px solid #1e2d4a',
                  color: '#e8eaf0', borderRadius: 6, padding: '8px 10px', fontSize: 12,
                  outline: 'none', resize: 'none', fontFamily: 'inherit',
                }}
              />
              <button
                onClick={handleComment}
                disabled={!comment.trim() || loading !== null}
                style={{
                  background: comment.trim() ? 'rgba(0,212,255,0.1)' : '#1a2540',
                  border: `1px solid ${comment.trim() ? 'rgba(0,212,255,0.3)' : '#1e2d4a'}`,
                  color: comment.trim() ? '#00d4ff' : '#6b7a99',
                  borderRadius: 6, padding: '0 12px', cursor: comment.trim() ? 'pointer' : 'default',
                }}
              >
                <Send size={14} />
              </button>
            </div>
          </div>

          {/* Activity timeline */}
          <div>
            <p style={{ color: '#6b7a99', fontSize: 10, fontWeight: 700, textTransform: 'uppercase', letterSpacing: '0.08em', marginBottom: 10 }}>
              Activity Timeline ({ticket.activities?.length || 0})
            </p>
            {(ticket.activities || []).length === 0 ? (
              <p style={{ color: '#1e2d4a', fontSize: 11 }}>No activity yet</p>
            ) : (
              <div style={{ position: 'relative' }}>
                <div style={{ position: 'absolute', left: 8, top: 0, bottom: 0, width: 1, background: '#1e2d4a' }} />
                {[...(ticket.activities || [])].reverse().map((act) => (
                  <div key={act.id} style={{ display: 'flex', gap: 14, marginBottom: 12, position: 'relative' }}>
                    <div style={{
                      width: 16, height: 16, borderRadius: '50%', flexShrink: 0,
                      background: '#141d35', border: '2px solid #1e2d4a',
                      display: 'flex', alignItems: 'center', justifyContent: 'center',
                      fontSize: 8, zIndex: 1,
                    }}>
                      {ACTIVITY_ICONS[act.action] || '●'}
                    </div>
                    <div style={{ flex: 1, paddingTop: 1 }}>
                      <p style={{ color: '#e8eaf0', fontSize: 11, margin: '0 0 2px' }}>
                        <span style={{ fontWeight: 600 }}>{act.action}</span>
                        {act.actor_name && (
                          <span style={{ color: '#6b7a99' }}> by {act.actor_name}</span>
                        )}
                      </p>
                      {act.comment && (
                        <p style={{ color: '#a0aec0', fontSize: 11, margin: '0 0 2px', fontStyle: 'italic' }}>"{act.comment}"</p>
                      )}
                      <p style={{ color: '#1e2d4a', fontSize: 10, margin: 0 }}>{formatRelative(act.created_at)}</p>
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>
      </div>

      {showResolve && (
        <ResolveModal
          ticket={ticket}
          analysts={analysts}
          onClose={() => setShowResolve(false)}
          onResolve={handleResolve}
        />
      )}
      {showEscalate && (
        <EscalateModal
          onClose={() => setShowEscalate(false)}
          onEscalate={handleEscalate}
        />
      )}
    </>
  )
}

// ── Inner Page (uses useSearchParams) ─────────────────────────────────────────

function TicketsInner() {
  const searchParams = useSearchParams()
  const preselected = searchParams.get('selected')

  const [tickets, setTickets] = useState<Ticket[]>([])
  const [stats, setStats] = useState<TicketStats | null>(null)
  const [analysts, setAnalysts] = useState<Analyst[]>([])
  const [selectedId, setSelectedId] = useState<string | null>(preselected)
  const [loading, setLoading] = useState(true)
  const [filters, setFilters] = useState<Filters>({ status: '', severity: '', type: '', slaOnly: false })

  const loadTickets = useCallback(async () => {
    try {
      const t = await ticketsApi.list()
      setTickets(t)
    } catch {}
  }, [])

  const loadStats = useCallback(async () => {
    try {
      const s = await ticketsApi.getStats()
      setStats(s)
    } catch {}
  }, [])

  useEffect(() => {
    const init = async () => {
      try {
        const [t, s, a] = await Promise.allSettled([
          ticketsApi.list(),
          ticketsApi.getStats(),
          analystsApi.list(),
        ])
        if (t.status === 'fulfilled') setTickets(t.value)
        if (s.status === 'fulfilled') setStats(s.value)
        if (a.status === 'fulfilled') setAnalysts(a.value)
      } finally {
        setLoading(false)
      }
    }
    init()

    // Auto-refresh stats every 30s
    const statsInterval = setInterval(async () => {
      await loadStats()
    }, 30_000)

    return () => clearInterval(statsInterval)
  }, [loadStats])

  // WebSocket handlers
  useWebSocket('ticket_created', useCallback((data: unknown) => {
    const t = data as Ticket
    setTickets((prev) => [t, ...prev])
    showToast(`New ${t.severity} ticket — TICK-${String(t.ticket_number).padStart(4, '0')}`, 'warning')
    loadStats()
  }, [loadStats]))

  useWebSocket('ticket_assigned', useCallback((data: unknown) => {
    const t = data as Ticket
    setTickets((prev) => prev.map((x) => x.id === t.id ? t : x))
    showToast(`TICK-${String(t.ticket_number).padStart(4, '0')} assigned to ${t.assigned_analyst_name}`, 'info')
  }, []))

  useWebSocket('sla_breach', useCallback((data: unknown) => {
    const t = data as Ticket
    setTickets((prev) => prev.map((x) => x.id === t.id ? { ...x, sla_breached: true } : x))
    showToast(`⚠ SLA BREACH: TICK-${String(t.ticket_number).padStart(4, '0')} (${t.severity}) — ${t.assigned_analyst_name || 'Unassigned'}`, 'error')
  }, []))

  useWebSocket('ticket_resolved', useCallback((data: unknown) => {
    const t = data as Ticket
    setTickets((prev) => prev.map((x) => x.id === t.id ? t : x))
    showToast(`✅ TICK-${String(t.ticket_number).padStart(4, '0')} resolved by ${t.assigned_analyst_name}`, 'success')
    loadStats()
  }, [loadStats]))

  useWebSocket('analyst_update', useCallback((data: unknown) => {
    const a = data as Analyst
    setAnalysts((prev) => prev.map((x) => x.id === a.id ? a : x))
  }, []))

  const handleTicketUpdate = useCallback((updated: Ticket) => {
    setTickets((prev) => prev.map((t) => t.id === updated.id ? updated : t))
    loadStats()
  }, [loadStats])

  // Client-side filtering
  const filtered = tickets.filter((t) => {
    if (filters.status && t.status !== filters.status) return false
    if (filters.severity && t.severity !== filters.severity) return false
    if (filters.type && t.ticket_type !== filters.type) return false
    if (filters.slaOnly && !t.sla_breached) return false
    return true
  })

  const selectedTicket = tickets.find((t) => t.id === selectedId) ?? null

  return (
    <div style={{ display: 'flex', flexDirection: 'column', height: '100vh', background: '#0a0e1a' }}>
      <NavBar />
      <StatsBar stats={stats} />

      {loading ? (
        <div style={{ flex: 1, display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
          <p style={{ color: '#6b7a99', fontSize: 14 }}>Loading tickets…</p>
        </div>
      ) : (
        <div style={{ flex: 1, display: 'flex', overflow: 'hidden' }}>
          <FilterPanel filters={filters} onChange={setFilters} />

          {/* Ticket list */}
          <div
            style={{
              flex: 1, overflowY: 'auto', padding: '12px 14px',
              minWidth: 0, transition: 'all 0.2s',
            }}
          >
            {filtered.length === 0 ? (
              <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', height: '100%' }}>
                <p style={{ color: '#1e2d4a', fontSize: 14 }}>No tickets match filters</p>
              </div>
            ) : (
              filtered.map((t) => (
                <TicketItem
                  key={t.id}
                  ticket={t}
                  selected={t.id === selectedId}
                  onClick={() => setSelectedId(t.id === selectedId ? null : t.id)}
                />
              ))
            )}
          </div>

          {/* Detail panel */}
          {selectedTicket && (
            <TicketDetailPanel
              ticket={selectedTicket}
              analysts={analysts}
              onClose={() => setSelectedId(null)}
              onTicketUpdate={handleTicketUpdate}
            />
          )}
        </div>
      )}
    </div>
  )
}

// ── Page ──────────────────────────────────────────────────────────────────────

export default function TicketsPage() {
  return (
    <Suspense fallback={
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', height: '100vh', background: '#0a0e1a' }}>
        <p style={{ color: '#6b7a99' }}>Loading…</p>
      </div>
    }>
      <TicketsInner />
    </Suspense>
  )
}
