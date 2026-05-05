import { useEffect, useState } from 'react'
import { Engagement } from '../api'

const PHASES = [
  'Reconnaissance', 'Weaponization', 'Delivery',
  'Exploitation', 'Installation', 'Command & Control', 'Impact'
]

const VULN_TYPE_MAP = {
  reconnaissance: ['scan', 'enum', 'recon', 'fingerprint'],
  weaponization: ['exploit_dev', 'payload'],
  delivery: ['phishing', 'upload', 'injection'],
  exploitation: ['sqli', 'xss', 'rce', 'ssrf', 'lfi', 'xxe', 'idor'],
  installation: ['backdoor', 'persistence', 'shell'],
  'command_control': ['c2', 'beacon', 'tunnel'],
  impact: ['exfil', 'ransomware', 'wipe'],
}

export default function KillChain() {
  const [findings, setFindings] = useState([])
  const [selected, setSelected] = useState(null)

  useEffect(() => {
    Engagement.findings?.().then(setFindings).catch(() => {})
  }, [])

  const byPhase = PHASES.map((phase) => {
    const key = phase.toLowerCase().replace(/[^a-z]/g, '_').replace(/_+/g, '_')
    const keywords = VULN_TYPE_MAP[key] || []
    const hits = findings.filter(f =>
      keywords.some(k => (f.vuln_type || '').toLowerCase().includes(k))
    )
    return { phase, hits }
  })

  return (
    <div style={{ padding: '16px', fontFamily: 'monospace' }}>
      <div style={{ color: '#666', fontSize: '10px', letterSpacing: '0.2em',
                    marginBottom: '16px' }}>
        LOCKHEED MARTIN CYBER KILL CHAIN
      </div>

      <div style={{ display: 'flex', gap: '4px', marginBottom: '24px' }}>
        {byPhase.map(({ phase, hits }, i) => {
          const active = hits.length > 0
          const sel = selected === phase
          return (
            <div key={phase} onClick={() => setSelected(sel ? null : phase)}
                 style={{
                   flex: 1, padding: '12px 4px', textAlign: 'center',
                   border: `1px solid ${active ? '#00FF41' : 'rgba(0,255,65,0.15)'}`,
                   background: sel ? 'rgba(0,255,65,0.08)' : 'transparent',
                   cursor: 'pointer',
                   boxShadow: active ? '0 0 10px rgba(0,255,65,0.2)' : 'none',
                   transition: 'all 0.2s',
                 }}>
              <div style={{ fontSize: '9px', color: '#666', marginBottom: '4px' }}>
                {String(i + 1).padStart(2, '0')}
              </div>
              <div style={{ fontSize: '10px', color: active ? '#00FF41' : '#1a4a1a',
                           lineHeight: 1.3 }}>
                {phase}
              </div>
              {hits.length > 0 && (
                <div style={{ marginTop: '8px', fontSize: '18px',
                             color: '#FF003C', fontWeight: 700 }}>
                  {hits.length}
                </div>
              )}
            </div>
          )
        })}
      </div>

      {selected && (() => {
        const phaseData = byPhase.find(p => p.phase === selected)
        return (
          <div className="card">
            <div className="card-title">{selected} — {phaseData.hits.length} findings</div>
            {phaseData.hits.length === 0 ? (
              <div style={{ color: '#1a4a1a' }}>No findings in this phase</div>
            ) : phaseData.hits.map((f, i) => (
              <div key={i} style={{ padding: '6px 0',
                                    borderBottom: '1px solid rgba(0,255,65,0.08)' }}>
                <span className={`sev-${f.severity}`}>[{f.severity?.toUpperCase()}]</span>
                {' '}{f.title || f.vuln_type}
                {' '}<span style={{ color: '#666' }}>@ {f.target}</span>
              </div>
            ))}
          </div>
        )
      })()}
    </div>
  )
}
