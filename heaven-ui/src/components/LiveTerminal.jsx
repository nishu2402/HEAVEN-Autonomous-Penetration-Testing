import { useEffect, useRef, useState } from 'react'

const SEV_COLOR = {
  critical: '#FF003C', high: '#FF6B00', medium: '#FFB800',
  low: '#00D4FF', info: '#888',
}

export default function LiveTerminal({ scanId }) {
  const [lines, setLines] = useState([])
  const [connected, setConnected] = useState(false)
  const [progress, setProgress] = useState(0)
  const bottomRef = useRef()
  const wsRef = useRef()

  useEffect(() => {
    if (!scanId) return
    const token = localStorage.getItem('heaven_token') || ''
    const ws = new WebSocket(
      `ws://${window.location.hostname}:8443/api/ws/scan/${scanId}?token=${token}`
    )
    wsRef.current = ws

    ws.onopen = () => setConnected(true)
    ws.onclose = () => setConnected(false)
    ws.onmessage = (e) => {
      try {
        const msg = JSON.parse(e.data)
        if (msg.type === 'progress') {
          setProgress(msg.data?.progress || 0)
          setLines(l => [...l.slice(-499), {
            type: 'log',
            text: `[${new Date().toLocaleTimeString()}] ${msg.data?.current_task || ''}`,
          }])
        } else if (msg.type === 'finding') {
          const f = msg.data
          setLines(l => [...l.slice(-499), { type: 'finding', data: f }])
        } else if (msg.type === 'log') {
          setLines(l => [...l.slice(-499), { type: 'log', text: msg.data }])
        }
      } catch {}
    }
    return () => ws.close()
  }, [scanId])

  useEffect(() => {
    bottomRef.current?.scrollIntoView({ behavior: 'smooth' })
  }, [lines])

  return (
    <div style={{ height: '100%', display: 'flex', flexDirection: 'column',
                  fontFamily: 'monospace', fontSize: '11px' }}>
      <div style={{ padding: '6px 8px', borderBottom: '1px solid rgba(0,255,65,0.2)',
                    display: 'flex', alignItems: 'center', gap: '8px' }}>
        <span style={{ color: connected ? '#00FF41' : '#FF003C', fontSize: '8px' }}>
          {connected ? '● LIVE' : '○ IDLE'}
        </span>
        <div style={{ flex: 1, height: '3px', background: 'rgba(0,255,65,0.1)' }}>
          <div style={{ width: `${progress}%`, height: '100%',
                        background: '#00FF41', transition: 'width 0.5s' }} />
        </div>
        <span style={{ color: '#666' }}>{Math.round(progress)}%</span>
      </div>

      <div style={{ flex: 1, overflowY: 'auto', padding: '8px' }}>
        {!scanId && (
          <span style={{ color: '#1a4a1a' }}>
            AWAITING TARGET<span className="blink">_</span>
          </span>
        )}
        {lines.map((line, i) => (
          <div key={i} style={{ marginBottom: '1px' }}>
            {line.type === 'finding' ? (
              <span>
                <span style={{ color: '#666' }}>
                  [{new Date().toLocaleTimeString()}]{' '}
                </span>
                <span style={{ color: SEV_COLOR[line.data?.severity] || '#00FF41' }}>
                  [{line.data?.severity?.toUpperCase()}]{' '}
                </span>
                <span style={{ color: '#00D4FF' }}>{line.data?.vuln_type} </span>
                <span style={{ color: '#888' }}>| {line.data?.target} | </span>
                <span>conf:{(line.data?.confidence || 0).toFixed(2)}</span>
              </span>
            ) : (
              <span style={{ color: '#1a4a1a' }}>{line.text}</span>
            )}
          </div>
        ))}
        <div ref={bottomRef} />
      </div>
    </div>
  )
}
