// HEAVEN — Autonomous Loop launcher + result viewer
//
// Mirrors `heaven autonomous` from the CLI. For long runs the CLI is
// recommended (it streams progress); this UI is best for short demo runs
// (max_iterations ≤ 5, time_budget ≤ 10 min) since the API call is
// synchronous.

import React, { useState } from "react";
import { Autonomous, Engagement } from "../api";

export default function AutonomousPage() {
  const [engagement, setEngagement] = useState("");
  const [targetsText, setTargetsText] = useState("");
  const [maxIter, setMaxIter] = useState(5);
  const [budget, setBudget] = useState(600);
  const [objective, setObjective] = useState("");
  const [useLLM, setUseLLM] = useState(true);
  const [authorized, setAuthorized] = useState(false);
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState(null);
  const [error, setError] = useState(null);

  React.useEffect(() => {
    // Default the engagement to the active one
    Engagement.summary()
      .then((d) => { if (d?.engagement?.name) setEngagement(d.engagement.name); })
      .catch(() => {});
  }, []);

  async function run() {
    setError(null);
    setResult(null);
    if (!authorized) {
      setError("You must confirm written authorization before running.");
      return;
    }
    const targets = targetsText.split(/[\n,]+/).map(t => t.trim()).filter(Boolean);
    if (!targets.length) {
      setError("Enter at least one target.");
      return;
    }
    const body = {
      engagement: engagement || undefined,
      ips: targets.filter(t => !t.startsWith("http")),
      urls: targets.filter(t => t.startsWith("http")),
      max_iterations: parseInt(maxIter, 10),
      time_budget_s: parseInt(budget, 10),
      objective,
      use_llm: useLLM,
    };
    setLoading(true);
    try {
      const r = await Autonomous.run(body);
      setResult(r);
    } catch (e) {
      setError(e.message);
    } finally {
      setLoading(false);
    }
  }

  return (
    <div className="page">
      <div className="card">
        <h2 style={{ color: "#FF073A", marginTop: 0 }}>⚙ Autonomous Loop</h2>
        <p className="dim" style={{ fontSize: 12 }}>
          Iterative observe → plan → act loop. The LLM-driven planner picks
          the next action each iteration; falls back to a deterministic
          rule-based playbook when no <code>ANTHROPIC/OPENAI/GEMINI</code> key
          is set. For runs longer than ~5 min, prefer the CLI:
          <code style={{ display: "block", marginTop: 4 }}>
            heaven autonomous -t &lt;target&gt; --engagement &lt;name&gt; --max-iterations 8 --i-have-authorization
          </code>
        </p>

        <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 12, marginBottom: 12 }}>
          <div style={{ gridColumn: "1 / -1" }}>
            <label className="form-label">Targets (URLs or IPs, one per line)</label>
            <textarea
              value={targetsText} rows={3}
              placeholder={"10.0.0.5\nhttps://app.example.com"}
              onChange={(e) => setTargetsText(e.target.value)}
              style={{ width: "100%", fontFamily: "monospace", fontSize: 12 }}
            />
          </div>
          <div>
            <label className="form-label">Engagement</label>
            <input type="text" value={engagement}
                   onChange={(e) => setEngagement(e.target.value)}
                   style={{ width: "100%", fontSize: 12 }}
                   placeholder="active engagement name" />
          </div>
          <div>
            <label className="form-label">Objective (optional)</label>
            <input type="text" value={objective}
                   onChange={(e) => setObjective(e.target.value)}
                   style={{ width: "100%", fontSize: 12 }}
                   placeholder="rce on internal host" />
          </div>
          <div>
            <label className="form-label">Max iterations</label>
            <input type="number" min={1} max={20} value={maxIter}
                   onChange={(e) => setMaxIter(e.target.value)}
                   style={{ width: "100%", fontSize: 12 }} />
          </div>
          <div>
            <label className="form-label">Time budget (seconds)</label>
            <input type="number" min={60} max={3600} value={budget}
                   onChange={(e) => setBudget(e.target.value)}
                   style={{ width: "100%", fontSize: 12 }} />
          </div>
        </div>

        <label style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 10 }}>
          <input type="checkbox" checked={useLLM}
                 onChange={(e) => setUseLLM(e.target.checked)} />
          <span>Use LLM planner (falls back to rule-based when no API key set)</span>
        </label>
        <label style={{ display: "flex", alignItems: "flex-start", gap: 10,
                        color: authorized ? "#00FF41" : "#FFB800", marginBottom: 12 }}>
          <input type="checkbox" checked={authorized}
                 onChange={(e) => setAuthorized(e.target.checked)} />
          <span>I confirm written authorization for every target listed.</span>
        </label>

        <button className="btn" disabled={loading || !authorized} onClick={run}>
          {loading ? "Running…" : "Launch autonomous run"}
        </button>

        {error && <div className="error" style={{ marginTop: 12 }}>{error}</div>}
      </div>

      {result && (
        <div className="card" style={{ marginTop: 12 }}>
          <h3 style={{ color: "#00FF41" }}>
            Run summary — <span style={{ color: "#00D4FF" }}>{result.stop_reason}</span>
          </h3>
          <div className="dim" style={{ fontSize: 12 }}>
            Iterations: {result.iterations_run} · Duration: {result.duration_s.toFixed(0)}s ·
            Findings: {result.total_findings} (critical: {result.total_critical}, high: {result.total_high})
          </div>
          {result.objective_met && (
            <div style={{ color: "#00FF41", marginTop: 8 }}>
              ✓ Objective met: {result.objective}
            </div>
          )}
          <table style={{ width: "100%", marginTop: 12, fontSize: 12 }}>
            <thead><tr style={{ color: "#00D4FF" }}>
              <th align="left">#</th><th align="left">Action</th>
              <th align="left">Target</th><th align="right">+Find</th>
              <th align="right">Reward</th><th align="left">Rationale</th>
            </tr></thead>
            <tbody>
              {(result.iterations || []).map((r) => (
                <tr key={r.n}>
                  <td>{r.n}</td>
                  <td>{r.action.kind}</td>
                  <td><code>{(r.action.target || "").slice(0, 32)}</code></td>
                  <td align="right">{r.new_findings}</td>
                  <td align="right">{r.reward.toFixed(2)}</td>
                  <td className="dim" style={{ fontSize: 11 }}>{r.action.rationale}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}
