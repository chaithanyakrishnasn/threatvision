import type { Metadata } from 'next'
import './globals.css'
import ToastContainer from '@/components/ToastContainer'

export const metadata: Metadata = {
  title: 'SentinelAI — AI-Powered SOC Platform',
  description: 'AI-driven threat detection, simulation, and incident response platform',
  icons: { icon: '/favicon.ico' },
}

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en" className="dark">
      <body className="min-h-screen" style={{ background: '#0a0e1a', color: '#e8eaf0' }}>
        <style>{`
          @keyframes sentinelPulse {
            0%, 100% { opacity: 1; }
            50% { opacity: 0.4; }
          }
        `}</style>
        <div className="scan-line" />
        {children}
        <ToastContainer />
      </body>
    </html>
  )
}
