'use client'

import { motion, AnimatePresence } from 'framer-motion'
import { Wifi, WifiOff } from 'lucide-react'

interface Props {
  connected: boolean
}

export function ConnectionStatus({ connected }: Props) {
  return (
    <AnimatePresence mode="wait">
      {connected ? (
        <motion.div
          key="connected"
          initial={{ opacity: 0, scale: 0.9 }}
          animate={{ opacity: 1, scale: 1 }}
          exit={{ opacity: 0, scale: 0.9 }}
          className="flex items-center gap-2 px-3 py-1.5 rounded-full border"
          style={{ background: 'rgba(0,255,157,0.08)', borderColor: 'rgba(0,255,157,0.3)' }}
        >
          <span
            className="w-2 h-2 rounded-full live-dot"
            style={{ background: '#00ff9d' }}
          />
          <Wifi className="w-3.5 h-3.5" style={{ color: '#00ff9d' }} />
          <span className="text-xs font-semibold" style={{ color: '#00ff9d' }}>
            LIVE
          </span>
        </motion.div>
      ) : (
        <motion.div
          key="disconnected"
          initial={{ opacity: 0, scale: 0.9 }}
          animate={{ opacity: 1, scale: 1 }}
          exit={{ opacity: 0, scale: 0.9 }}
          className="flex items-center gap-2 px-3 py-1.5 rounded-full border"
          style={{ background: 'rgba(107,122,153,0.1)', borderColor: 'rgba(107,122,153,0.3)' }}
        >
          <span className="w-2 h-2 rounded-full bg-gray-500" />
          <WifiOff className="w-3.5 h-3.5 text-gray-500" />
          <span className="text-xs font-semibold text-gray-500">OFFLINE</span>
        </motion.div>
      )}
    </AnimatePresence>
  )
}
