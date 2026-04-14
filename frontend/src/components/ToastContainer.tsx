'use client'

import { useEffect, useState } from 'react'
import { registerToastHandler } from '@/lib/toast'
import type { Toast } from '@/lib/toast'

const TYPE_COLORS: Record<string, string> = {
  success: '#00ff9d',
  error: '#ff3b6b',
  warning: '#ffb800',
  info: '#00d4ff',
}

const TYPE_BG: Record<string, string> = {
  success: 'rgba(0,255,157,0.1)',
  error: 'rgba(255,59,107,0.1)',
  warning: 'rgba(255,184,0,0.1)',
  info: 'rgba(0,212,255,0.1)',
}

export default function ToastContainer() {
  const [toasts, setToasts] = useState<Toast[]>([])

  useEffect(() => {
    registerToastHandler((toast) => {
      setToasts((prev) => [toast, ...prev].slice(0, 3))
      setTimeout(() => {
        setToasts((prev) => prev.filter((t) => t.id !== toast.id))
      }, 5000)
    })
  }, [])

  if (toasts.length === 0) return null

  return (
    <div
      style={{
        position: 'fixed',
        bottom: 24,
        right: 24,
        zIndex: 9999,
        display: 'flex',
        flexDirection: 'column',
        gap: 8,
        pointerEvents: 'none',
      }}
    >
      {toasts.map((toast) => (
        <div
          key={toast.id}
          style={{
            background: '#141d35',
            border: `1px solid ${TYPE_COLORS[toast.type] || '#1e2d4a'}`,
            borderLeft: `3px solid ${TYPE_COLORS[toast.type] || '#1e2d4a'}`,
            borderRadius: 8,
            padding: '10px 16px',
            maxWidth: 340,
            boxShadow: '0 4px 20px rgba(0,0,0,0.4)',
            backgroundColor: TYPE_BG[toast.type] || '#141d35',
          }}
        >
          <p style={{ color: '#e8eaf0', fontSize: 13, margin: 0, lineHeight: 1.4 }}>
            {toast.message}
          </p>
        </div>
      ))}
    </div>
  )
}
