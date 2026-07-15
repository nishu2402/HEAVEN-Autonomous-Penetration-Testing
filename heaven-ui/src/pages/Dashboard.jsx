import { useEffect, useState, lazy, Suspense } from 'react'
import { motion } from 'framer-motion'
import { useNavigate } from 'react-router-dom'
import LiveTerminal from '../components/LiveTerminal'
import FirstRunGuide from '../components/FirstRunGuide'
import { Engagement, Dashboard as DashApi, Demo, Engagements, Scans } from '../api'
import { useToast } from '../components/Toast.jsx'
import HelpTip from '../components/HelpTip.jsx'
import { SCAN_MODES, ANALYSIS_TOOLS } from '../scanModes.js'

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

function StatCard({ label, value, color, sub, delay = 0, help }) {
  return (
    <motion.div
      className="stat-card"
      style={{ color }}
      initial={{ opacity: 0, y: 12 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.4, ease: [0.22, 1, 0.36, 1], delay }}
    >
      <div className="stat-label">{label}{help && <HelpTip term={help} />}</div>
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
  // The live terminal streams the scan that is ACTUALLY running (if any),
  // derived from the scans list — not a stale localStorage pointer that older
  // builds left behind and never cleared, which made the terminal falsely show
  // "CONNECTING" and open a log socket on every fresh open.
  const [liveScanId, setLiveScanId] = useState('')
  const [seeding, setSeeding] = useState(false)
  const [topFindings, setTopFindings] = useState([])
  const [engList, setEngList] = useState([])
  const [busyEng, setBusyEng] = useState('')   // engagement name being switched/deleted
  const navigate = useNavigate()
  const toast = useToast()

  // Returns the engagement-list promise so callers can await the switcher
  // refresh (switch/delete) before clearing their busy state.
  const refresh = () => {
    Engagement.summary().then(setEng).catch(() => {})
    DashApi.get().then(setDash).catch(() => {})
    Engagement.topFindings(5).then(d => setTopFindings(d.findings || [])).catch(() => {})
    // Only stream a scan that is genuinely running right now.
    Scans.list(20).then(d => {
      const running = (d.scans || []).find(s => s.status === 'running')
      setLiveScanId(running ? (running.scan_id || running.id || '') : '')
    }).catch(() => {})
    return Engagements.list().then(d => setEngList(d.engagements || [])).catch(() => {})
  }

  // Switch which engagement the whole app is viewing (dashboard, findings, reports).
  const switchEngagement = async (name) => {
    if (!name || busyEng) return
    if (engList.find((e) => e.active)?.name === name) return   // already viewing
    setBusyEng(name)
    try {
      await Engagements.setActive(name)
      await refresh()
      toast.success(`Now viewing “${name}”`)
    } catch (e) {
      toast.error(e.message || 'Could not switch engagement')
    } finally {
      setBusyEng('')
    }
  }

  // Permanently delete an engagement. The server repoints the active engagement
  // when you delete the one you're viewing, so we just refresh afterwards.
  const deleteEngagement = async (name) => {
    if (busyEng) return
    const target = engList.find((e) => e.name === name)
    const detail = target?.findings
      ? `${target.findings} finding${target.findings !== 1 ? 's' : ''}`
      : 'no findings'
    if (!window.confirm(
      `Delete engagement “${name}” (${detail})? This permanently removes its ` +
      `scans and findings and cannot be undone.`
    )) return
    setBusyEng(name)
    try {
      await Engagements.remove(name)
      await refresh()
      toast.success(`Deleted “${name}”`)
    } catch (e) {
      toast.error(e.message || 'Could not delete engagement')
    } finally {
      setBusyEng('')
    }
  }

  // One-click cleanup for the common "stray empty engagements pile up" case.
  const clearEmpties = async () => {
    const empties = engList.filter((e) => !e.findings && !e.scans).map((e) => e.name)
    if (empties.length === 0 || busyEng) return
    if (!window.confirm(
      `Remove ${empties.length} empty engagement${empties.length !== 1 ? 's' : ''} ` +
      `(${empties.join(', ')})? Only engagements with no scans and no findings are removed.`
    )) return
    setBusyEng('__empties__')
    try {
      for (const name of empties) {
        try { await Engagements.remove(name) } catch { /* skip one that fails */ }
      }
      await refresh()
      toast.success(`Removed ${empties.length} empty engagement${empties.length !== 1 ? 's' : ''}`)
    } finally {
      setBusyEng('')
    }
  }

  useEffect(() => {
    // Clear a stale scan pointer from older builds so the terminal starts IDLE
    // and only lights up for a real, currently-running scan.
    try { localStorage.removeItem('heaven_active_scan') } catch { /* no storage */ }
    refresh()
    const t = setInterval(refresh, 8000)
    // The active engagement can change from the Header chip or another tab
    // without a route change. Re-fetch immediately so the topology, stats and
    // "hosts mapped" reflect the newly-selected engagement at once instead of
    // waiting for the next 8s poll.
    const onEngChange = () => refresh()
    window.addEventListener('heaven:engagement-changed', onEngChange)
    return () => {
      clearInterval(t)
      window.removeEventListener('heaven:engagement-changed', onEngChange)
    }
  }, [])

  const loadSampleData = async () => {
    setSeeding(true)
    try {
      const r = await Demo.seed()
      toast.success(`Loaded ${r.findings} sample findings — explore away`)
      refresh()
    } catch (e) {
      toast.error(e.message || 'Could not load sample data')
    } finally {
      setSeeding(false)
    }
  }

  const stats = eng?.stats || {}
  const hosts = dash?.assets || []
  const noEng = !eng || eng.no_engagement
  const bySev = stats.by_severity || {}
  const totalFindings = stats.total_findings ?? 0

  return (
    <div className="dashboard-grid">
      <FirstRunGuide />
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
                    sub={(bySev.critical ?? 0) > 0 ? 'Needs attention' : 'All clear'} delay={0.02}
                    help="severity" />
          <StatCard label="High" value={bySev.high ?? 0} color={SEV.high.color} delay={0.06} />
          <StatCard label="Total findings" value={totalFindings} color="#6D7CFF" delay={0.10}
                    sub={`${stats.scans_run ?? 0} scan${stats.scans_run !== 1 ? 's' : ''} run`}
                    help="risk_score" />
          <StatCard label="Targets" value={stats.scope_targets ?? 0} color="#34E5A3" delay={0.14}
                    sub="In scope" />
        </div>

        {/* Quick-launch: every scan surface + analysis tool, one click away.
            Scan modes deep-link into the launcher with the mode preselected;
            FULL is highlighted (and appears once). Fed by scanModes.js so this
            grid and the Scans launcher can never disagree. */}
        <div className="launch-panel">
          <div className="launch-head">
            <span className="stat-label" style={{ marginBottom: 0 }}>Launch a scan</span>
            <button type="button" className="launch-all" onClick={() => navigate('/scans')}>
              Open scan console →
            </button>
          </div>
          <div className="launch-grid">
            {SCAN_MODES.map((m) => (
              <button
                key={m.value}
                type="button"
                className={'launch-tile' + (m.value === 'full' ? ' is-primary' : '')}
                title={m.desc}
                onClick={() => navigate(`/scans?mode=${m.value}`)}
              >
                <span className="launch-tile-icon">{m.icon}</span>
                <span className="launch-tile-name">{m.short}</span>
              </button>
            ))}
            {ANALYSIS_TOOLS.map((t) => (
              <button
                key={t.to}
                type="button"
                className="launch-tile is-tool"
                title={t.desc}
                onClick={() => navigate(t.to)}
              >
                <span className="launch-tile-icon">{t.icon}</span>
                <span className="launch-tile-name">{t.short}</span>
              </button>
            ))}
          </div>
        </div>
      </div>

      {/* Right rail */}
      <div className="dashboard-right">
        <div style={{ padding: '16px 18px', borderBottom: '1px solid var(--border)' }}>
          {engList.length > 1 && (
            <div style={{ marginBottom: 14 }}>
              <div className="stat-label" style={{ marginBottom: 6 }}>Viewing engagement</div>
              <div className="eng-switch-list">
                {engList.map((e) => {
                  const busy = busyEng === e.name
                  return (
                    <div key={e.name} className={'eng-switch-row' + (e.active ? ' is-active' : '')}>
                      <button
                        type="button"
                        className="eng-switch-pick"
                        disabled={!!busyEng}
                        onClick={() => switchEngagement(e.name)}
                        title={e.active ? 'Currently viewing' : `Switch to “${e.name}”`}
                      >
                        <span className="eng-switch-dot" />
                        <span className="eng-switch-name">{e.display_name}</span>
                        {e.name === 'demo' && <span className="eng-switch-tag">sample</span>}
                        <span className="eng-switch-count">
                          {e.findings
                            ? `${e.findings} finding${e.findings !== 1 ? 's' : ''}`
                            : 'empty'}
                        </span>
                      </button>
                      <button
                        type="button"
                        className="eng-switch-del"
                        disabled={!!busyEng}
                        onClick={() => deleteEngagement(e.name)}
                        title={`Delete “${e.name}” permanently`}
                        aria-label={`Delete engagement ${e.name}`}
                      >
                        {busy ? '…' : '🗑'}
                      </button>
                    </div>
                  )
                })}
              </div>
              {engList.filter((e) => !e.findings && !e.scans).length > 1 && (
                <button
                  type="button"
                  className="eng-switch-clear"
                  disabled={!!busyEng}
                  onClick={clearEmpties}
                >
                  Remove {engList.filter((e) => !e.findings && !e.scans).length} empty engagements
                </button>
              )}
            </div>
          )}
          {noEng ? (
            <div>
              <div className="card-title" style={{ marginBottom: 10 }}>Quick start</div>
              <div style={{ color: 'var(--text-1)', fontSize: 12.5, lineHeight: 1.6, marginBottom: 12 }}>
                Launch your first scan to populate the dashboard — findings, severity
                breakdown and topology fill in automatically.
              </div>
              <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap' }}>
                <button className="btn btn-primary" onClick={() => navigate('/scans')}>
                  Launch a scan →
                </button>
                <button className="btn" onClick={loadSampleData} disabled={seeding}>
                  {seeding ? 'Loading…' : 'Load sample data'}
                </button>
              </div>
              <div className="dim" style={{ fontSize: 11, marginTop: 12 }}>
                Just exploring? <b>Load sample data</b> fills every page with a realistic
                example engagement — nothing is scanned.
              </div>
              <div className="dim" style={{ fontSize: 11, marginTop: 8 }}>
                Prefer the terminal? <code>heaven demo</code> (sample) ·
                <code>heaven scan -t 10.0.0.1 --i-have-authorization</code>
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

        {!noEng && topFindings.length > 0 && (
          <div style={{ padding: '14px 18px', borderBottom: '1px solid var(--border)' }}>
            <div className="stat-label" style={{ marginBottom: 6 }}>
              Fix this first<HelpTip term="risk_score" />
            </div>
            <div className="dim" style={{ fontSize: 11.5, marginBottom: 10, lineHeight: 1.5 }}>
              {(bySev.critical ?? 0)} critical · {(bySev.high ?? 0)} high across{' '}
              {stats.scope_targets ?? 0} target{(stats.scope_targets ?? 0) !== 1 ? 's' : ''}.
              {topFindings[0] && (
                <> Top risk: <span style={{ color: 'var(--text-0)' }}>{topFindings[0].title}</span>{' '}
                ({Number(topFindings[0].risk_score || 0).toFixed(0)}).</>
              )}
            </div>
            <div style={{ display: 'grid', gap: 8 }}>
              {topFindings.map((f) => (
                <button
                  key={f.id}
                  onClick={() => navigate(`/findings/${f.id}`)}
                  style={{
                    textAlign: 'left', background: 'rgba(255,255,255,0.02)',
                    border: '1px solid var(--border)', borderRadius: 'var(--radius-md)',
                    padding: '9px 11px', cursor: 'pointer', color: 'var(--text-0)',
                    fontFamily: 'var(--font-ui)',
                  }}
                  onMouseEnter={(e) => (e.currentTarget.style.borderColor = 'var(--border-strong)')}
                  onMouseLeave={(e) => (e.currentTarget.style.borderColor = 'var(--border)')}
                >
                  <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                    <span style={{ width: 8, height: 8, borderRadius: '50%', flexShrink: 0,
                                   background: SEV[f.severity]?.color || 'var(--text-2)' }} />
                    <span style={{ fontSize: 12.5, fontWeight: 600, flex: 1, overflow: 'hidden',
                                   textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{f.title}</span>
                    <span className="mono" style={{ fontSize: 11, color: 'var(--text-2)' }}>
                      {Number(f.risk_score || 0).toFixed(1)}
                    </span>
                  </div>
                  {f.remediation && (
                    <div className="dim" style={{ fontSize: 11, marginTop: 3, lineHeight: 1.45,
                                                  overflow: 'hidden', textOverflow: 'ellipsis',
                                                  display: '-webkit-box', WebkitLineClamp: 2,
                                                  WebkitBoxOrient: 'vertical' }}>
                      {f.remediation}
                    </div>
                  )}
                </button>
              ))}
            </div>
          </div>
        )}

        <LiveTerminal scanId={liveScanId} />
      </div>
    </div>
  )
}
