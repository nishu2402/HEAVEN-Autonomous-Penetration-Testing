import { useEffect, useState } from 'react'
import { motion } from 'framer-motion'
import { Engagement } from '../api'

const PHASES = [
  { name: 'Recon',       icon: '🔍', keys: ['scan', 'enum', 'recon', 'fingerprint', 'osint', 'shodan'] },
  { name: 'Weaponize',   icon: '🔧', keys: ['exploit_dev', 'payload', 'zeroday'] },
  { name: 'Delivery',    icon: '📨', keys: ['phishing', 'upload', 'injection', 'sqli', 'xss'] },
  { name: 'Exploit',     icon: '💥', keys: ['rce', 'ssrf', 'lfi', 'xxe', 'idor', 'ssti', 'jwt'] },
  { name: 'Install',     icon: '🔩', keys: ['backdoor', 'persistence', 'shell', 'cron'] },
  { name: 'C2',          icon: '📡', keys: ['c2', 'beacon', 'tunnel', 'dns'] },
  { name: 'Impact',      icon: '🎯', keys: ['exfil', 'ransomware', 'wipe', 'denial', 'takeover'] },
]

function findPhase(vuln_type) {
  const vt = (vuln_type || '').toLowerCase()
  for (let i = 0; i < PHASES.length; i++) {
    if (PHASES[i].keys.some(k => vt.includes(k))) return i
  }
  return 3 // default → exploitation
}

const SEV_COLORS = {
  critical: '#FF003C', high: '#FF6B00', medium: '#FFB800', low: '#00D4FF', info: '#666',
}

export default function KillChain() {
  const [findings, setFindings] = useState([])
  const [noEng, setNoEng] = useState(false)
  const [selected, setSelected] = useState(null)

  useEffect(() => {
    Engagement.findings({ limit: 1000, status: '' })
      .then(d => {
        if (d.no_engagement) { setNoEng(true); return }
        setFindings(d.findings || [])
      })
      .catch(() => setNoEng(true))
  }, [])

  // Bucket findings by phase
  const phases = PHASES.map((p, i) => ({
    ...p,
    index: i,
    findings: findings.filter(f => findPhase(f.vuln_type) === i),
  }))

  const totalScore = phases.filter(p => p.findings.length > 0).length
  const maxScore   = PHASES.length
  const pct        = Math.round((totalScore / maxScore) * 100)

  // Attack path: phases that have findings, sorted
  const attackPath = phases.filter(p => p.findings.length > 0)

  return (
    <div className="page">
      {/* Header */}
      <div className="card">
        <div className="card-title">Cyber Kill Chain Coverage</div>
        <div style={{ display: 'flex', alignItems: 'center', gap: 24, flexWrap: 'wrap' }}>
          <div>
            <div style={{ fontSize: 48, fontWeight: 700, color: pct > 60 ? '#FF003C' : pct > 30 ? '#FFB800' : '#00FF41',
                          textShadow: `0 0 30px currentColor`, lineHeight: 1 }}>
              {pct}
            </div>
            <div style={{ fontSize: 11, color: 'rgba(0,255,65,0.68)', letterSpacing: '0.1em' }}>
              COVERAGE SCORE
            </div>
          </div>
          <div style={{ flex: 1 }}>
            <div style={{ marginBottom: 6, fontSize: 12, color: 'rgba(0,255,65,0.72)' }}>
              {totalScore}/{maxScore} phases · {findings.length} finding{findings.length !== 1 ? 's' : ''}
            </div>
            <div className="progress-bar" style={{ height: 6 }}>
              <div className="progress-fill"
                   style={{
                     width: `${pct}%`,
                     background: pct > 60 ? '#FF003C' : pct > 30 ? '#FFB800' : '#00FF41',
                   }} />
            </div>
            <div style={{ marginTop: 6, fontSize: 11, color: 'rgba(0,255,65,0.65)' }}>
              {pct > 60 ? '⚠ HIGH COVERAGE — attacker has a clear path' :
               pct > 30 ? '⚡ PARTIAL COVERAGE — gaps exist' :
               '✓ LOW COVERAGE — limited attack surface observed'}
            </div>
          </div>
        </div>
      </div>

      {noEng && (
        <div className="onboarding-banner">
          <div className="onboarding-icon">⛓</div>
          <div>
            <div className="onboarding-title">No Engagement Data</div>
            <div className="onboarding-body">
              Set HEAVEN_ENGAGEMENT and run a scan to populate the kill chain.
            </div>
          </div>
        </div>
      )}

      {/* Phase grid */}
      <div className="killchain-grid">
        {phases.map((phase, i) => {
          const hasFindings = phase.findings.length > 0
          const topSev = phase.findings[0]?.severity || 'info'
          const color  = hasFindings ? (SEV_COLORS[topSev] || '#00FF41') : 'rgba(0,255,65,0.42)'
          return (
            <motion.div
              key={i}
              className={`phase-card ${hasFindings ? 'has-findings' : 'no-findings'}`}
              initial={{ opacity: 0, y: 12 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ delay: i * 0.05 }}
              style={{ cursor: hasFindings ? 'pointer' : 'default', borderBottomColor: color }}
              onClick={() => hasFindings && setSelected(selected === i ? null : i)}
            >
              <div className="phase-num">PHASE {i + 1}</div>
              <div style={{ fontSize: 20, marginBottom: 6 }}>{phase.icon}</div>
              <div className="phase-name">{phase.name}</div>
              <div className={`phase-count ${hasFindings ? '' : 'zero'}`} style={{ color }}>
                {phase.findings.length}
              </div>
              {hasFindings && (
                <div style={{ marginTop: 4, fontSize: 10, color, opacity: 0.85 }}>
                  {topSev.toUpperCase()}
                </div>
              )}
            </motion.div>
          )
        })}
      </div>

      {/* Finding detail for selected phase */}
      {selected !== null && phases[selected].findings.length > 0 && (
        <motion.div className="card" initial={{ opacity: 0 }} animate={{ opacity: 1 }}>
          <div className="card-title">
            Phase {selected + 1}: {phases[selected].name} · {phases[selected].findings.length} finding{phases[selected].findings.length !== 1 ? 's' : ''}
          </div>
          <table className="findings-table">
            <thead>
              <tr><th>Sev</th><th>Type</th><th>Target</th><th>Conf</th><th>Status</th></tr>
            </thead>
            <tbody>
              {phases[selected].findings.map(f => (
                <tr key={f.id}>
                  <td><span className={`sev-pill sev-${f.severity}`}>{f.severity}</span></td>
                  <td><code style={{ fontSize: 11 }}>{f.vuln_type}</code></td>
                  <td className="ellipsis" title={f.target}>{f.target}</td>
                  <td>{Number(f.confidence).toFixed(2)}</td>
                  <td><span className={`status-pill status-${f.status}`}>{f.status}</span></td>
                </tr>
              ))}
            </tbody>
          </table>
        </motion.div>
      )}

      {/* Attack path */}
      {attackPath.length > 0 && (
        <div className="card">
          <div className="card-title">Chained Attack Path</div>
          <div style={{ display: 'flex', alignItems: 'center', gap: 0, flexWrap: 'wrap' }}>
            {attackPath.map((phase, i) => {
              const topSev = phase.findings[0]?.severity || 'info'
              const color = SEV_COLORS[topSev] || '#00FF41'
              return (
                <div key={i} style={{ display: 'flex', alignItems: 'center' }}>
                  <motion.div
                    initial={{ opacity: 0, scale: 0.8 }}
                    animate={{ opacity: 1, scale: 1 }}
                    transition={{ delay: i * 0.1 }}
                    style={{
                      border: `1px solid ${color}`,
                      padding: '6px 12px',
                      fontSize: 11,
                      color,
                      background: `${color}11`,
                    }}
                  >
                    <div style={{ fontSize: 10, opacity: 0.75, marginBottom: 2 }}>
                      [{phase.name.toUpperCase()}]
                    </div>
                    <div>{phase.findings[0]?.title || phase.findings[0]?.vuln_type}</div>
                    <div style={{ fontSize: 10, opacity: 0.68, marginTop: 2 }}>
                      {phase.findings[0]?.target}
                    </div>
                  </motion.div>
                  {i < attackPath.length - 1 && (
                    <span style={{ color: 'rgba(0,255,65,0.68)', fontSize: 16, padding: '0 4px' }}>→</span>
                  )}
                </div>
              )
            })}
          </div>
        </div>
      )}
    </div>
  )
}
