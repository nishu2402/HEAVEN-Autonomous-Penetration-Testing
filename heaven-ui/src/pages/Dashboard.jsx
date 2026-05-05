import { useEffect, useState } from 'react'
import { motion } from 'framer-motion'
import NetworkTopology3D from '../components/NetworkTopology3D'
import LiveTerminal from '../components/LiveTerminal'
import { Engagement } from '../api'

const FADE_UP = { hidden: { opacity: 0, y: 20 }, show: { opacity: 1, y: 0 } }

function StatCard({ label, value, color, delay }) {
  return (
    <motion.div className="card" variants={FADE_UP} transition={{ delay }}
                style={{ textAlign: 'center', borderColor: color + '44' }}>
      <div className="card-title">{label}</div>
      <div style={{ fontSize: '2.5rem', color, fontWeight: 700,
                    textShadow: `0 0 20px ${color}44` }}>
        {value ?? '—'}
      </div>
    </motion.div>
  )
}

export default function Dashboard() {
  const [data, setData] = useState(null)
  const [clock, setClock] = useState(new Date().toLocaleTimeString())
  const [activeScanId, setActiveScanId] = useState(
    localStorage.getItem('heaven_active_scan') || ''
  )

  useEffect(() => {
    const fetch = () => Engagement.summary().then(setData).catch(() => {})
    fetch()
    const t = setInterval(fetch, 5000)
    return () => clearInterval(t)
  }, [])

  useEffect(() => {
    const t = setInterval(() => setClock(new Date().toLocaleTimeString()), 1000)
    return () => clearInterval(t)
  }, [])

  const stats = data?.stats || {}
  const hosts = data?.assets || []

  return (
    <div style={{ display: 'grid', gridTemplateColumns: '1fr 380px',
                  gridTemplateRows: 'auto 1fr', height: '100vh',
                  gap: '1px', background: 'rgba(0,255,65,0.1)' }}>

      {/* Top bar */}
      <div style={{ gridColumn: '1/-1', display: 'flex', alignItems: 'center',
                    padding: '8px 16px', background: '#000',
                    borderBottom: '1px solid rgba(0,255,65,0.2)' }}>
        <span style={{ color: '#00FF41', letterSpacing: '0.2em', fontSize: '14px' }}>
          H E A V E N
        </span>
        <span style={{ flex: 1, textAlign: 'center', color: '#666', fontSize: '11px' }}>
          {clock}
        </span>
        <span style={{ color: '#666', fontSize: '11px' }}>
          {activeScanId ? (
            <><span style={{ color: '#00FF41', fontSize: '8px' }} className="blink">●</span>
            {' '}{activeScanId.slice(0, 8)}</>
          ) : 'IDLE'}
        </span>
      </div>

      {/* Left column */}
      <div style={{ background: '#000', display: 'flex', flexDirection: 'column', overflow: 'hidden' }}>
        <div style={{ flex: '0 0 45vh' }}>
          <NetworkTopology3D hosts={hosts} />
        </div>

        <motion.div style={{ flex: 1, padding: '12px', display: 'grid',
                             gridTemplateColumns: 'repeat(4,1fr)', gap: '8px' }}
                    initial="hidden" animate="show"
                    variants={{ show: { transition: { staggerChildren: 0.1 } } }}>
          <StatCard label="Critical" value={stats.by_severity?.critical}
                    color="#FF003C" delay={0} />
          <StatCard label="High" value={stats.by_severity?.high}
                    color="#FF6B00" delay={0.1} />
          <StatCard label="Medium" value={stats.by_severity?.medium}
                    color="#FFB800" delay={0.2} />
          <StatCard label="Assets" value={stats.scope_targets}
                    color="#00D4FF" delay={0.3} />
        </motion.div>
      </div>

      {/* Right column: terminal */}
      <div style={{ background: '#000', borderLeft: '1px solid rgba(0,255,65,0.15)',
                    display: 'flex', flexDirection: 'column' }}>
        <div style={{ padding: '8px 12px', borderBottom: '1px solid rgba(0,255,65,0.1)',
                      fontSize: '10px', color: '#666', letterSpacing: '0.1em' }}>
          LIVE TELEMETRY
        </div>
        <div style={{ flex: 1 }}>
          <LiveTerminal scanId={activeScanId} />
        </div>
      </div>
    </div>
  )
}
