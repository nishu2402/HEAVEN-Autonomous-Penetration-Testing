// HEAVEN — Knowledge Graph viewer
// Mirrors `heaven knowledge stats` + `heaven knowledge rank`.

import React, { useEffect, useState } from "react";
import { Knowledge } from "../api";

export default function KnowledgePage() {
  const [stats, setStats] = useState(null);
  const [error, setError] = useState(null);

  // Rank form
  const [profileOs, setProfileOs] = useState("linux");
  const [webTech, setWebTech] = useState("php");
  const [ports, setPorts] = useState("22,80,443");
  const [ranking, setRanking] = useState(null);
  const [rankLoading, setRankLoading] = useState(false);

  useEffect(() => {
    Knowledge.stats().then(setStats).catch((e) => setError(e.message));
  }, []);

  async function loadRank() {
    setRankLoading(true);
    try {
      const r = await Knowledge.rank({ os: profileOs, web_tech: webTech, ports });
      setRanking(r);
    } catch (e) {
      setError(e.message);
    } finally {
      setRankLoading(false);
    }
  }

  return (
    <div className="page">
      <div className="card">
        <h2 style={{ color: "#7B2FBE", marginTop: 0 }}>🧠 Knowledge Graph</h2>
        <p className="dim" style={{ fontSize: 12 }}>
          Cross-engagement memory: (target_profile, technique, outcome)
          tuples stored in <code>~/.heaven/knowledge.db</code>. Used by the
          autonomous planner to bias next-step selection toward techniques
          that have worked on similar targets before.
        </p>

        {error && <div className="error">{error}</div>}

        {stats && (
          <div style={{ display: "grid", gridTemplateColumns: "repeat(3, 1fr)", gap: 12 }}>
            <Stat label="Target profiles"  value={stats.profiles}  color="#00D4FF" />
            <Stat label="Total attempts"   value={stats.attempts}  color="#FFB800" />
            <Stat label="Successes"        value={stats.successes} color="#00FF41" />
          </div>
        )}
      </div>

      {stats && stats.top_techniques?.length > 0 && (
        <div className="card" style={{ marginTop: 12 }}>
          <div className="card-title">Top techniques by success count</div>
          <table style={{ width: "100%", fontSize: 12 }}>
            <thead><tr style={{ color: "#00D4FF" }}>
              <th align="left">Technique</th>
              <th align="right">Successes</th>
              <th align="right">Attempts</th>
              <th align="right">Rate</th>
            </tr></thead>
            <tbody>
              {stats.top_techniques.map((t) => {
                const rate = t.attempts ? t.successes / t.attempts : 0;
                return (
                  <tr key={t.technique}>
                    <td>{t.technique}</td>
                    <td align="right" style={{ color: "#00FF41" }}>{t.successes}</td>
                    <td align="right">{t.attempts}</td>
                    <td align="right">{(rate * 100).toFixed(0)}%</td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      )}

      <div className="card" style={{ marginTop: 12 }}>
        <div className="card-title">Query rankings for a target profile</div>
        <div className="dim" style={{ fontSize: 12, marginBottom: 8 }}>
          Returns Beta-smoothed posterior success-rate per technique for a
          target with this fingerprint. The planner uses the same query at
          plan-time.
        </div>
        <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr 1fr auto", gap: 8, marginBottom: 10 }}>
          <input value={profileOs} onChange={(e) => setProfileOs(e.target.value)}
                 placeholder="OS (linux/windows)" style={{ fontSize: 12 }} />
          <input value={webTech} onChange={(e) => setWebTech(e.target.value)}
                 placeholder="web_tech (php,wordpress)" style={{ fontSize: 12 }} />
          <input value={ports} onChange={(e) => setPorts(e.target.value)}
                 placeholder="ports (22,80,443)" style={{ fontSize: 12 }} />
          <button className="btn-small" onClick={loadRank} disabled={rankLoading}>
            {rankLoading ? "…" : "Rank"}
          </button>
        </div>
        {ranking && (
          <>
            <div className="dim" style={{ fontSize: 11, marginBottom: 8 }}>
              Fingerprint: <code>{ranking.fingerprint}</code>
            </div>
            {ranking.rankings.length === 0
              ? <div className="dim">No data yet — run more scans first.</div>
              : ranking.rankings.map((r) => (
                <div key={r.technique} style={{ marginBottom: 4 }}>
                  <span style={{ display: "inline-block", width: 220 }}>{r.technique}</span>
                  <span style={{ color: "#00FF41" }}>
                    {(r.posterior_success_rate * 100).toFixed(0)}%
                  </span>
                  <span className="dim" style={{ marginLeft: 8 }}>
                    n={r.evidence_count}
                  </span>
                </div>
              ))
            }
          </>
        )}
      </div>
    </div>
  );
}

function Stat({ label, value, color }) {
  return (
    <div style={{ padding: 12, background: "rgba(0,0,0,0.3)",
                  border: `1px solid ${color}33`, borderRadius: 2 }}>
      <div className="dim" style={{ fontSize: 11, marginBottom: 4 }}>{label}</div>
      <div style={{ fontSize: 28, fontWeight: 700, color }}>{value}</div>
    </div>
  );
}
