import { useEffect, useState, lazy, Suspense } from 'react'
import { motion } from 'framer-motion'
import { useNavigate } from 'react-router-dom'
import LiveTerminal from '../components/LiveTerminal'
import { Engagement, Dashboard as DashApi } from '../api'

// three.js + r3f + drei are heavy (~600 KB). Load them only when the dashboard
// mounts, not in the app's first paint — keeps login/findings/etc. lightweight.
const NetworkTopology3D = lazy(() => import('../components/NetworkTopology3D'))

function TopologyFallback() {
  return (
    <div className="topology-container topology-loading">
      <span className="route-spinner" />
      <span>Initializing 3D topology…</span>
    </div>
  )
}

const SEV = {
  critical: { color: '#FF4D6A', label: 'Critical' },
  high:     { color: '#FF8A3D', label: 'High' },
  medium:   { color: '#FFC53D', label: 'Medium' },
  low:      { color: '#38BDF8', label: 'Low' },
  info:     { color: '#8593AD', label: 'Info' },
}

function StatCard({ label, value, color, sub, delay = 0 }) {
  return (
    <motion.div
      className="stat-card"
      style={{ color }}
      initial={{ opacity: 0, y: 12 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.4, ease: [0.22, 1, 0.36, 1], delay }}
    >
      <div className="stat-label">{label}</div>
      <div className="stat-value" style={{ color }}>{value ?? '—'}</div>
      {sub && <div className="stat-sub">{sub}</div>}
    </motion.div>
  )
}

function SeverityBars({ bySeverity, total }) {
  const order = ['critical', 'high', 'medium', 'low', 'info']
  return (
    <div className="flex-col gap-md" style={{ padding: '16px' }}>
      <div className="card-title" style={{ marginBottom: 4 }}>Severity distribution</div>
      {order.map((s) => {
        const n = bySeverity?.[s] ?? 0
        const pct = total > 0 ? Math.round((n / total) * 100) : 0
        return (
          <div key={s}>
            <div className="flex items-center justify-between" style={{ fontSize: 12, marginBottom: 5 }}>
              <span style={{ color: SEV[s].color, fontWeight: 600 }}>{SEV[s].label}</span>
              <span className="mono" style={{ color: 'var(--text-2)' }}>{n}</span>
            </div>
            <div className="progress-bar">
              <motion.div
                className="progress-fill"
                style={{ background: SEV[s].color, boxShadow: `0 0 10px ${SEV[s].color}66` }}
                initial={{ width: 0 }}
                animate={{ width: `${pct}%` }}
                transition={{ duration: 0.6, ease: 'easeOut' }}
              />
            </div>
          </div>
        )
      })}
    </div>
  )
}

export default function Dashboard() {
  const [eng, setEng] = useState(null)
  const [dash, setDash] = useState(null)
  const [activeScanId] = useState(localStorage.getItem('heaven_active_scan') || '')
  const navigate = useNavigate()

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
  const bySev = stats.by_severity || {}
  const totalFindings = stats.total_findings ?? 0

  return (
    <div className="dashboard-grid">
      {/* Left: topology + stats */}
      <div className="dashboard-left">
        <div style={{ position: 'relative', overflow: 'hidden' }}>
          <Suspense fallback={<TopologyFallback />}>
            <NetworkTopology3D hosts={hosts} />
          </Suspense>
          {noEng && (
            <div style={{
              position: 'absolute', inset: 0, display: 'flex', alignItems: 'center',
              justifyContent: 'center', pointerEvents: 'none',
            }}>
              <div className="card-glass" style={{
                padding: '20px 28px', textAlign: 'center', borderRadius: 'var(--radius-lg)',
                pointerEvents: 'auto',
              }}>
                <div style={{ color: 'var(--text-0)', fontSize: 15, fontWeight: 700, marginBottom: 6 }}>
                  No active engagement
                </div>
                <div style={{ color: 'var(--text-2)', fontSize: 12.5, marginBottom: 14 }}>
                  Launch a scan to map your target surface — no terminal required.
                </div>
                <button className="btn btn-primary" style={{ pointerEvents: 'auto' }}
                        onClick={() => navigate('/scans')}>
                  Launch a scan →
                </button>
              </div>
            </div>
          )}
        </div>

        <div className="stat-grid">
          <StatCard label="Critical" value={bySev.critical ?? 0} color={SEV.critical.color}
                    sub={(bySev.critical ?? 0) > 0 ? 'Needs attention' : 'All clear'} delay={0.02} />
          <StatCard label="High" value={bySev.high ?? 0} color={SEV.high.color} delay={0.06} />
          <StatCard label="Total findings" value={totalFindings} color="#6D7CFF" delay={0.10}
                    sub={`${stats.scans_run ?? 0} scan${stats.scans_run !== 1 ? 's' : ''} run`} />
          <StatCard label="Targets" value={stats.scope_targets ?? 0} color="#34E5A3" delay={0.14}
                    sub="In scope" />
        </div>
      </div>

      {/* Right rail */}
      <div className="dashboard-right">
        <div style={{ padding: '16px 18px', borderBottom: '1px solid var(--border)' }}>
          {noEng ? (
            <div>
              <div className="card-title" style={{ marginBottom: 10 }}>Quick start</div>
              <div style={{ color: 'var(--text-1)', fontSize: 12.5, lineHeight: 1.6, marginBottom: 12 }}>
                Launch your first scan to populate the dashboard — findings, severity
                breakdown and topology fill in automatically.
              </div>
              <button className="btn btn-primary" onClick={() => navigate('/scans')}>
                Launch a scan →
              </button>
              <div className="dim" style={{ fontSize: 11, marginTop: 12 }}>
                Prefer the terminal? <code>heaven scan -t 10.0.0.1 --i-have-authorization</code>
              </div>
            </div>
          ) : (
            <div>
              <div className="stat-label" style={{ marginBottom: 6 }}>Engagement</div>
              <div style={{ color: 'var(--text-0)', fontWeight: 700, fontSize: 16, marginBottom: 4 }}>
                {eng.engagement?.name}
              </div>
              <div style={{ color: 'var(--text-1)', fontSize: 12.5 }}>
                {totalFindings} findings · {stats.scope_targets} targets in scope
              </div>
            </div>
          )}
        </div>

        {!noEng && totalFindings > 0 && (
          <div style={{ borderBottom: '1px solid var(--border)' }}>
            <SeverityBars bySeverity={bySev} total={totalFindings} />
          </div>
        )}

        <LiveTerminal scanId={activeScanId} />
      </div>
    </div>
  )
}
