import type { Metadata } from 'next'
import './globals.css'

export const metadata: Metadata = {
  title: 'ThreatVision — AI-Powered SOC Platform',
  description: 'AI-driven threat detection, simulation, and incident response platform',
  icons: { icon: '/favicon.ico' },
}

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en" className="dark">
      <body className="min-h-screen" style={{ background: '#0a0e1a', color: '#e8eaf0' }}>
        <div className="scan-line" />
        {children}
      </body>
    </html>
  )
}
