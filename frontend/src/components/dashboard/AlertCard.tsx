'use client'

import { motion } from 'framer-motion'
import { SeverityBadge } from './SeverityBadge'
import { RelativeTime } from './RelativeTime'
import type { Alert, Severity } from '@/types'

interface Props {
  alert: Partial<Alert>
  index?: number
}

export function AlertCard({ alert, index = 0 }: Props) {
  return (
    <motion.div
      initial={{ opacity: 0, x: -12 }}
      animate={{ opacity: 1, x: 0 }}
      transition={{ delay: index * 0.04 }}
      className="flex items-start gap-3 px-4 py-3 bg-surface-700 border border-surface-500 rounded-lg hover:border-slate-600 transition-colors"
    >
      <div className="flex-1 min-w-0">
        <div className="flex items-center gap-2 mb-1">
          <SeverityBadge severity={(alert.severity as Severity) || 'low'} pulse />
          {alert.mitre_technique && (
            <span className="text-[10px] font-mono text-blue-400 bg-blue-500/10 px-1.5 py-0.5 rounded">
              {alert.mitre_technique}
            </span>
          )}
        </div>
        <p className="text-sm text-slate-300 font-medium truncate">{alert.rule_name}</p>
        {(alert.source_ip || alert.dest_ip) && (
          <p className="text-xs font-mono text-slate-500 mt-0.5">
            {alert.source_ip && <span>{alert.source_ip}</span>}
            {alert.source_ip && alert.dest_ip && <span className="mx-1 text-slate-600">→</span>}
            {alert.dest_ip && <span>{alert.dest_ip}</span>}
          </p>
        )}
      </div>
      <RelativeTime timestamp={alert.created_at} className="text-[10px] text-slate-600 whitespace-nowrap mt-0.5" />
    </motion.div>
  )
}
