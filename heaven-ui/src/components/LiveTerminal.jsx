import { useEffect, useRef, useState } from 'react'
import { openLogStream, getToken } from '../api'

const DEMO_LINES = [
  { type: 'info',    text: 'HEAVEN initialized — operator-driven mode' },
  { type: 'success', text: 'Bayesian prioritiser loaded' },
  { type: 'info',    text: 'Evasion engine: NORMAL profile' },
  { type: 'success', text: 'Security headers middleware active' },
  { type: 'success', text: 'API server ready on :8443' },
  { type: 'dim',     text: '─'.repeat(42) },
  { type: 'info',    text: 'Awaiting scan target...' },
  { type: 'dim',     text: 'heaven scan -u https://target --i-have-authorization' },
]

function classify(line) {
  const l = line.toLowerCase()
  if (l.includes('error') || l.includes('fail') || l.includes('critical')) return 'error'
  if (l.includes('warn') || l.includes('skip')) return 'warn'
  if (l.includes('found') || l.includes('complet') || l.includes('success')) return 'success'
  if (l.includes('[*]') || l.includes('info') || l.includes('scan')) return 'info'
  return 'dim'
}

export default function LiveTerminal({ scanId }) {
  const [lines, setLines] = useState(DEMO_LINES)
  const [connected, setConnected] = useState(false)
  const bottomRef = useRef(null)

  useEffect(() => {
    if (!scanId || !getToken()) return
    const ws = openLogStream((msg) => {
      try {
        const data = JSON.parse(msg)
        const text = data.message || data.msg || data.log || String(msg)
        setLines(prev => [...prev.slice(-200), { type: classify(text), text }])
      } catch {
        setLines(prev => [...prev.slice(-200), { type: classify(msg), text: msg }])
      }
    })
    if (ws) {
      ws.onopen = () => setConnected(true)
      ws.onclose = () => setConnected(false)
      ws.onerror = () => setConnected(false)
    }
    return () => { ws?.close(); setConnected(false) }
  }, [scanId])

  useEffect(() => {
    bottomRef.current?.scrollIntoView({ behavior: 'smooth' })
  }, [lines])

  return (
    <div className="terminal-pane">
      <div className="terminal-header">
        <span>
          {connected
            ? <><span className="blink" style={{ color: '#00FF41' }}>●</span> LIVE</>
            : scanId ? '◌ CONNECTING' : '○ IDLE'
          }
          {scanId && (
            <span style={{ marginLeft: 8, color: 'rgba(0,255,65,0.3)' }}>
              {scanId.slice(0, 8)}
            </span>
          )}
        </span>
        <span>{lines.length} lines</span>
      </div>

      <div className="terminal-body">
        {lines.map((line, i) => (
          <div key={i} className={`terminal-line ${line.type}`}>
            {line.text}
          </div>
        ))}
        <div ref={bottomRef} />
      </div>
    </div>
  )
}
