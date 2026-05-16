import { useEffect, useState } from 'react'
import { motion } from 'framer-motion'
import NetworkTopology3D from '../components/NetworkTopology3D'
import LiveTerminal from '../components/LiveTerminal'
import { Engagement, Dashboard as DashApi } from '../api'

const SEV_COLORS = {
  critical: '#FF003C', high: '#FF6B00', medium: '#FFB800', low: '#00D4FF',
}

function StatCard({ label, value, color, sub }) {
  return (
    <motion.div
      className="stat-card"
      style={{ color }}
      initial={{ opacity: 0, y: 8 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.3 }}
    >
      <div className="stat-label">{label}</div>
      <div className="stat-value" style={{ color, textShadow: `0 0 20px ${color}55` }}>
        {value ?? '—'}
      </div>
      {sub && <div style={{ fontSize: 10, color: 'rgba(0,255,65,0.62)', marginTop: 4 }}>{sub}</div>}
    </motion.div>
  )
}

export default function Dashboard() {
  const [eng, setEng] = useState(null)
  const [dash, setDash] = useState(null)
  const [activeScanId] = useState(localStorage.getItem('heaven_active_scan') || '')

  useEffect(() => {
    const load = () => {
      Engagement.summary().then(setEng).catch(() => {})
      DashApi.get().then(setDash).catch(() => {})
    }
    load()
    const t = setInterval(load, 8000)
    return () => clearInterval(t)
  }, [])

  const stats = eng?.stats || {}
  const hosts = dash?.assets || []
  const noEng = !eng || eng.no_engagement

  const critCount = stats.by_severity?.critical ?? 0
  const highCount = stats.by_severity?.high ?? 0
  const medCount  = stats.by_severity?.medium ?? 0
  const totalFindings = stats.total_findings ?? 0

  return (
    <div className="dashboard-grid">
      {/* Left: 3D + stat cards */}
      <div className="dashboard-left">
        {/* 3D Topology */}
        <div style={{ position: 'relative', overflow: 'hidden' }}>
          <NetworkTopology3D hosts={hosts} isDemo={noEng} />

          {/* Overlay info */}
          {noEng && (
            <div style={{
              position: 'absolute', inset: 0, display: 'flex', alignItems: 'center',
              justifyContent: 'center', pointerEvents: 'none',
            }}>
              <div style={{
                background: 'rgba(0,0,0,0.75)',
                border: '1px solid rgba(0,212,255,0.3)',
                padding: '12px 20px',
                textAlign: 'center',
                backdropFilter: 'blur(4px)',
              }}>
                <div style={{ color: '#00D4FF', fontSize: 12, letterSpacing: '0.1em', marginBottom: 4 }}>
                  NO ACTIVE ENGAGEMENT
                </div>
                <div style={{ color: 'rgba(0,255,65,0.72)', fontSize: 11 }}>
                  heaven engage init &lt;name&gt;
                </div>
              </div>
            </div>
          )}
        </div>

        {/* Stat cards */}
        <div className="stat-grid">
          <StatCard
            label="Critical" value={critCount} color={SEV_COLORS.critical}
            sub={critCount > 0 ? 'NEEDS ATTENTION' : 'CLEAR'}
          />
          <StatCard
            label="High" value={highCount} color={SEV_COLORS.high}
          />
          <StatCard
            label="Medium" value={medCount} color={SEV_COLORS.medium}
          />
          <StatCard
            label="Targets" value={stats.scope_targets ?? 0} color="#00FF41"
            sub={`${stats.scans_run ?? 0} scan${stats.scans_run !== 1 ? 's' : ''}`}
          />
        </div>
      </div>

      {/* Right: terminal + info */}
      <div className="dashboard-right">
        {/* Engagement mini-summary */}
        <div style={{
          padding: '10px 14px',
          borderBottom: '1px solid rgba(0,255,65,0.1)',
          fontSize: 11,
        }}>
          {noEng ? (
            <div style={{ color: 'rgba(0,255,65,0.72)', fontSize: 12 }}>
              <div style={{ marginBottom: 6, color: '#00D4FF', letterSpacing: '0.1em', fontSize: 11 }}>QUICK START</div>
              <div style={{ lineHeight: 1.8 }}>
                <div>$ heaven engage init my-eng</div>
                <div>$ heaven scope add 10.0.0.0/24 --kind cidr</div>
                <div>$ heaven scan -t 10.0.0.1 --i-have-authorization</div>
              </div>
            </div>
          ) : (
            <div>
              <div style={{ color: 'rgba(0,255,65,0.68)', fontSize: 10, letterSpacing: '0.1em', marginBottom: 4 }}>
                ENGAGEMENT
              </div>
              <div style={{ color: '#00FF41', fontWeight: 700, marginBottom: 2 }}>
                {eng.engagement?.name}
              </div>
              <div style={{ color: 'rgba(0,255,65,0.72)', fontSize: 11 }}>
                {totalFindings} findings · {stats.scope_targets} targets in scope
              </div>
              <div style={{ marginTop: 8, display: 'flex', gap: 8 }}>
                {Object.entries(SEV_COLORS).map(([s, c]) => (
                  <span key={s} style={{ fontSize: 11, color: c }}>
                    {stats.by_severity?.[s] ?? 0} {s.charAt(0).toUpperCase()}
                  </span>
                ))}
              </div>
            </div>
          )}
        </div>

        {/* Live terminal */}
        <LiveTerminal scanId={activeScanId} />
      </div>
    </div>
  )
}
