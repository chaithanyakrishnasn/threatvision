'use client'

interface LiveEvent {
  sev?: string
  severity?: string
  msg?: string
  threat_type?: string
  source_ip?: string
  dest_ip?: string
  bytes_sent?: number
  ts?: number
}

function formatBytes(bytes: number = 0) {
  if (!bytes) return '0 B'
  const k = 1024
  const sizes = ['B', 'KB', 'MB', 'GB', 'TB']
  const i = Math.floor(Math.log(bytes) / Math.log(k))
  return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i]
}

interface LiveEventsPanelProps {
  events: LiveEvent[]
}

export function LiveEventsPanel({ events }: LiveEventsPanelProps) {
  return (
    <div style={{
      background: '#0f1629',
      border: '1px solid #1e2d4a',
      borderRadius: '8px',
      height: '100%',
      display: 'flex',
      flexDirection: 'column',
      overflow: 'hidden',
    }}>
      <div style={{
        padding: '10px 14px',
        borderBottom: '1px solid #1e2d4a',
        flexShrink: 0,
        display: 'flex',
        alignItems: 'center',
        gap: '8px',
      }}>
        <span style={{
          width: '8px',
          height: '8px',
          borderRadius: '50%',
          background: '#00ff9d',
          display: 'inline-block',
          animation: 'pulse 2s infinite',
          flexShrink: 0,
        }} />
        <span style={{ color: '#6b7a99', fontSize: '12px', fontWeight: 500, textTransform: 'uppercase', letterSpacing: '0.08em' }}>
          Live Events
        </span>
      </div>

      <div style={{
        flex: 1,
        overflowY: 'auto',
        minHeight: 0,
        padding: '6px',
      }}>
        {events.length === 0 ? (
          <div style={{ color: '#6b7a99', fontSize: '12px', padding: '12px', textAlign: 'center' }}>
            Waiting for events...
          </div>
        ) : (
          events.map((event, i) => {
            const sev = (event.sev || event.severity || 'LOW').toUpperCase()
            const isExfil = event.threat_type === 'data_exfiltration'
            const color =
              isExfil             ? '#ff003c' :
              sev === 'CRITICAL' ? '#ff3b6b' :
              sev === 'HIGH'     ? '#ff8c00' :
              sev === 'MEDIUM'   ? '#ffb800' :
                                   '#00ff9d'
            
            const prefix = isExfil ? '[EXFIL]' : `[${sev.slice(0, 4)}]`
            
            let displayText = event.msg ||
              `${(event.threat_type || 'event').replace(/_/g, ' ')} from ${event.source_ip || '?'}`
            
            if (isExfil && event.dest_ip) {
              displayText = `Exfil to ${event.dest_ip}`
              if (event.bytes_sent) {
                displayText += ` (${formatBytes(event.bytes_sent)})`
              }
            }

            return (
              <div
                key={`${event.ts ?? i}-${i}`}
                style={{
                  borderLeft: `2px solid ${color}`,
                  padding: '5px 10px',
                  marginBottom: '3px',
                  background: isExfil ? 'rgba(255,0,60,0.05)' : '#141d35',
                  borderRadius: '0 4px 4px 0',
                  fontSize: '11px',
                  fontFamily: 'monospace',
                  display: 'flex',
                  gap: '6px',
                  alignItems: 'flex-start',
                }}
              >
                <span style={{ color, fontWeight: 700, flexShrink: 0 }}>
                  {prefix}
                </span>
                <span style={{ color: isExfil ? '#ff3b6b' : '#b0bcd4', fontWeight: isExfil ? 600 : 400 }}>{displayText}</span>
              </div>
            )
          })
        )}
      </div>
    </div>
  )
}
