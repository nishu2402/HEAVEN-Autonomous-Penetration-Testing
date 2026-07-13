// HEAVEN — Coverage self-grading viewer
// Mirrors `heaven coverage` from the CLI.

import React, { useState, useEffect } from "react";
import { Link } from "react-router-dom";
import { Coverage, Engagement, Priors } from "../api";
import { useJob } from "../context/Jobs.jsx";
import { useToast } from "../components/Toast.jsx";
import { SkeletonCard } from "../components/Skeleton.jsx";
import { GRADE_COLOR } from "../theme";

export default function CoveragePage() {
  const [engagement, setEngagement] = useState("");
  const [useLLM, setUseLLM] = useState(true);
  // Tracked globally: LLM gap analysis can take a while, so grading survives
  // navigating away and back.
  const { loading, result: report, error, start } = useJob("coverage");
  const toast = useToast();

  useEffect(() => {
    Engagement.summary()
      .then((d) => { if (d?.engagement?.name) setEngagement(d.engagement.name); })
      .catch(() => {});
  }, []);

  function load() {
    start({ label: "Coverage grading", kind: "coverage", path: "/coverage" },
          () => Coverage.get({ engagement, use_llm: useLLM }));
  }

  async function trainPriors() {
    try {
      const r = await Priors.train();
      toast.success(
        "Priors trained",
        `${r.engagement_dbs} DB(s) · ${r.finding_count} findings · ` +
        `${r.service_priors_updated} service priors updated`,
      );
    } catch (e) {
      toast.error("Train priors failed", e.message);
    }
  }

  return (
    <div className="page">
      <div className="card">
        <h2 style={{ color: "var(--text-0)", marginTop: 0 }}>📊 Coverage Self-Grading</h2>
        <p className="page-lead">
          Rule-based OWASP coverage + scope hit-rate + auth/auto-prove/post-ex
          flags, with optional LLM-driven gap analysis.
        </p>

        <div style={{ display: "flex", gap: 10, alignItems: "center", marginBottom: 12, flexWrap: "wrap" }}>
          <input className="form-input" type="text" value={engagement}
                 onChange={(e) => setEngagement(e.target.value)}
                 placeholder="engagement name (default: active)"
                 style={{ flex: 1, minWidth: 200 }} />
          <label className="consent-row" style={{ margin: 0 }}>
            <input type="checkbox" checked={useLLM}
                   onChange={(e) => setUseLLM(e.target.checked)} />
            <span>Use LLM gap analysis</span>
          </label>
          <button className="btn btn-primary" disabled={loading} onClick={load}>
            {loading ? "Grading…" : "Grade"}
          </button>
          <button className="btn" onClick={trainPriors}
                  title="Aggregate engagement findings into empirical Bayesian priors">
            Train priors
          </button>
        </div>

        {error && <div className="error">{error}</div>}
      </div>

      {loading && !report && (
        <div style={{ marginTop: 12 }}><SkeletonCard lines={5} /></div>
      )}

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
                color: GRADE_COLOR[report.grade] || "var(--info)",
              }}>{report.grade}</div>
            </div>
            <div style={{ marginTop: 10 }}>
              <div className="dim" style={{ fontSize: 11 }}>Scope coverage</div>
              <div style={{ background: "var(--border)", height: 12, borderRadius: "var(--radius-sm)", overflow: "hidden" }}>
                <div style={{
                  width: `${report.scope_coverage_pct}%`, height: "100%",
                  background: "var(--brand)",
                }} />
              </div>
              <div className="dim" style={{ fontSize: 11, marginTop: 8 }}>OWASP Top 10 coverage</div>
              <div style={{ background: "var(--border)", height: 12, borderRadius: "var(--radius-sm)", overflow: "hidden" }}>
                <div style={{
                  width: `${report.owasp_coverage_pct}%`, height: "100%",
                  background: "var(--cyan)",
                }} />
              </div>
            </div>
          </div>

          <div className="card" style={{ marginTop: 12 }}>
            <div className="card-title">OWASP Top 10 — per-category coverage</div>
            <table className="data-table">
              <tbody>
                {(report.owasp_top10 || []).map((c) => (
                  <tr key={c.code}>
                    <td style={{ width: 80 }}><code>{c.code}</code></td>
                    <td>{c.name}</td>
                    <td className="num" style={{ width: 60 }}>{c.findings}</td>
                    <td style={{ width: 30, color: c.covered ? "var(--brand)" : "var(--crit)" }}>
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
              <pre className="cli-block">{report.llm_gap_summary}</pre>
            </div>
          )}

          {(report.total_findings ?? 0) > 0 && (
            <Link to="/findings" className="btn-small" style={{ marginTop: 4 }}>
              Open findings in triage →
            </Link>
          )}
        </>
      )}
    </div>
  );
}
