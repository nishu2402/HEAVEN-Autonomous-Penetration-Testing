// HEAVEN — Coverage self-grading viewer
// Mirrors `heaven coverage` from the CLI.

import React, { useState, useEffect } from "react";
import { Coverage, Engagement, Priors } from "../api";

const GRADE_COLOR = {
  A: "var(--text-0)", B: "var(--cyan)", C: "var(--med)", D: "var(--high)", F: "var(--crit)",
};

export default function CoveragePage() {
  const [engagement, setEngagement] = useState("");
  const [useLLM, setUseLLM] = useState(true);
  const [report, setReport] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);

  useEffect(() => {
    Engagement.summary()
      .then((d) => { if (d?.engagement?.name) setEngagement(d.engagement.name); })
      .catch(() => {});
  }, []);

  async function load() {
    setLoading(true);
    setError(null);
    try {
      const r = await Coverage.get({ engagement, use_llm: useLLM });
      setReport(r);
    } catch (e) {
      setError(e.message);
    } finally {
      setLoading(false);
    }
  }

  async function trainPriors() {
    try {
      const r = await Priors.train();
      alert(`Trained on ${r.engagement_dbs} engagement DB(s)\n` +
            `Findings ingested: ${r.finding_count}\n` +
            `Service priors updated: ${r.service_priors_updated}\n` +
            `Output: ${r.output}`);
    } catch (e) {
      alert(`Train priors failed: ${e.message}`);
    }
  }

  return (
    <div className="page">
      <div className="card">
        <h2 style={{ color: "var(--text-0)", marginTop: 0 }}>📊 Coverage Self-Grading</h2>
        <p className="dim" style={{ fontSize: 12 }}>
          Rule-based OWASP coverage + scope hit-rate + auth/auto-prove/post-ex
          flags, with optional LLM-driven gap analysis.
        </p>

        <div style={{ display: "flex", gap: 12, alignItems: "center", marginBottom: 12 }}>
          <input type="text" value={engagement}
                 onChange={(e) => setEngagement(e.target.value)}
                 placeholder="engagement name (default: active)"
                 style={{ flex: 1, fontSize: 12 }} />
          <label style={{ display: "flex", alignItems: "center", gap: 6 }}>
            <input type="checkbox" checked={useLLM}
                   onChange={(e) => setUseLLM(e.target.checked)} />
            <span style={{ fontSize: 12 }}>Use LLM gap analysis</span>
          </label>
          <button className="btn" disabled={loading} onClick={load}>
            {loading ? "Grading…" : "Grade"}
          </button>
          <button className="btn-small" onClick={trainPriors}
                  title="Aggregate engagement findings into empirical Bayesian priors">
            Train priors
          </button>
        </div>

        {error && <div className="error">{error}</div>}
      </div>

      {report && (
        <>
          <div className="card" style={{ marginTop: 12 }}>
            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start" }}>
              <div>
                <h3 style={{ marginTop: 0 }}>Engagement: {report.engagement || "(unnamed)"}</h3>
                <div className="dim" style={{ fontSize: 12 }}>
                  {report.scanned_target_count}/{report.scope_target_count} targets
                  · {report.total_findings} findings ·
                  authenticated: {report.authenticated ? "✓" : "✗"} ·
                  auto-prove: {report.auto_prove_run ? "✓" : "✗"} ·
                  post-ex chained: {report.postex_chained ? "✓" : "✗"}
                </div>
              </div>
              <div style={{
                fontSize: 64, fontWeight: 800, lineHeight: 1,
                color: GRADE_COLOR[report.grade] || "#888",
              }}>{report.grade}</div>
            </div>
            <div style={{ marginTop: 10 }}>
              <div className="dim" style={{ fontSize: 11 }}>Scope coverage</div>
              <div style={{ background: "var(--border)", height: 12, borderRadius: 2 }}>
                <div style={{
                  width: `${report.scope_coverage_pct}%`, height: "100%",
                  background: "var(--text-0)",
                }} />
              </div>
              <div className="dim" style={{ fontSize: 11, marginTop: 8 }}>OWASP Top 10 coverage</div>
              <div style={{ background: "var(--border-accent)", height: 12, borderRadius: 2 }}>
                <div style={{
                  width: `${report.owasp_coverage_pct}%`, height: "100%",
                  background: "var(--cyan)",
                }} />
              </div>
            </div>
          </div>

          <div className="card" style={{ marginTop: 12 }}>
            <div className="card-title">OWASP Top 10 — per-category coverage</div>
            <table style={{ width: "100%", fontSize: 12 }}>
              <tbody>
                {(report.owasp_top10 || []).map((c) => (
                  <tr key={c.code}>
                    <td style={{ width: 80 }}><code>{c.code}</code></td>
                    <td>{c.name}</td>
                    <td align="right" style={{ width: 60 }}>{c.findings}</td>
                    <td style={{ width: 30, color: c.covered ? "var(--text-0)" : "var(--crit)" }}>
                      {c.covered ? "✓" : "✗"}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>

          {(report.recommendations || []).length > 0 && (
            <div className="card" style={{ marginTop: 12 }}>
              <div className="card-title">Recommendations</div>
              <ul style={{ paddingLeft: 16, lineHeight: 1.8 }}>
                {report.recommendations.map((r, i) => (
                  <li key={i} style={{ fontSize: 12 }}>{r}</li>
                ))}
              </ul>
            </div>
          )}

          {(report.untested_scope_targets || []).length > 0 && (
            <div className="card" style={{ marginTop: 12 }}>
              <div className="card-title">Untested scope targets</div>
              {report.untested_scope_targets.map((t, i) => (
                <div key={i} style={{ fontFamily: "monospace", fontSize: 12 }}>{t}</div>
              ))}
            </div>
          )}

          {report.llm_gap_summary && (
            <div className="card" style={{ marginTop: 12 }}>
              <div className="card-title">LLM gap analysis</div>
              <pre style={{
                whiteSpace: "pre-wrap", fontSize: 12, fontFamily: "monospace",
                background: "rgba(0,0,0,0.4)", padding: 10, border: "1px solid var(--border)",
              }}>{report.llm_gap_summary}</pre>
            </div>
          )}
        </>
      )}
    </div>
  );
}
