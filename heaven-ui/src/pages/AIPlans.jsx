// HEAVEN — AI Plans page (Layer D / Gap 6)
//
// Lets the operator paste a list of findings (or use the active engagement
// store) and ask the LLM-backed planner to propose attack chains.
//
// Backend: POST /api/ai/plan/run  →  PlannerOutput { plans: [...] }

import React, { useState } from "react";
import { AI, SIEM, Engagement } from "../api";
import { SkeletonCard } from "../components/Skeleton.jsx";

export default function AIPlans() {
  const [findingsJson, setFindingsJson] = useState("");
  const [objective, setObjective]       = useState("");
  const [loading, setLoading]           = useState(false);
  const [output, setOutput]             = useState(null);
  const [error, setError]               = useState(null);
  const [siemStatus, setSiemStatus]     = useState(null);

  React.useEffect(() => {
    SIEM.status().then(setSiemStatus).catch(() => setSiemStatus(null));
  }, []);

  async function loadFromEngagement() {
    setError(null);
    try {
      const data = await Engagement.findings({ limit: 50 });
      const rows = (data?.findings || []).map((f) => ({
        id: f.id, target: f.target, vuln_type: f.vuln_type,
        severity: f.severity, confidence: f.confidence,
        evidence: f.evidence,
      }));
      setFindingsJson(JSON.stringify(rows, null, 2));
    } catch (e) {
      setError(e.message);
    }
  }

  async function plan() {
    setError(null);
    setOutput(null);
    setLoading(true);
    try {
      const parsed = JSON.parse(findingsJson || "[]");
      const out = await AI.plan(parsed, [], objective);
      setOutput(out);
    } catch (e) {
      setError(e.message);
    } finally {
      setLoading(false);
    }
  }

  return (
    <div className="page">
      <div className="card">
        <h2 style={{ color: "var(--text-0)", marginTop: 0 }}>✦ AI Attack-Chain Planner</h2>
        <p className="page-lead">
          Layer D — LLM proposes multi-step attack chains from a finding list.
          Requires <code>ANTHROPIC_API_KEY</code>, <code>OPENAI_API_KEY</code>, or{" "}
          <code>GEMINI_API_KEY</code> on the server. If none is set the endpoint
          returns <code>{`{"skipped": "LLM gateway unavailable"}`}</code>.
        </p>

        {siemStatus && (
          <div className="dim" style={{ fontSize: 11, marginBottom: 8 }}>
            SIEM backends active: {siemStatus.siem_backends_active.length
              ? siemStatus.siem_backends_active.join(", ")
              : "(none — set HEAVEN_SPLUNK_HEC_* or HEAVEN_ELASTIC_* env vars)"}
          </div>
        )}

        <div style={{ marginBottom: 8 }}>
          <button className="btn-small" onClick={loadFromEngagement}>
            Load findings from active engagement
          </button>
        </div>

        <textarea
          className="form-input mono-input"
          value={findingsJson}
          onChange={(e) => setFindingsJson(e.target.value)}
          rows={12}
          spellCheck={false}
          placeholder='[{"target":"http://x","vuln_type":"ssrf","severity":"high","evidence":{}}]'
        />

        <div style={{ marginTop: 10, marginBottom: 10 }}>
          <input
            className="form-input"
            type="text"
            value={objective}
            onChange={(e) => setObjective(e.target.value)}
            placeholder="Optional objective hint (e.g. 'aim for AD compromise')"
          />
        </div>

        <button className="btn btn-primary" disabled={loading} onClick={plan}>
          {loading ? "Planning…" : "Plan attack chains"}
        </button>

        {error && (
          <div className="error" style={{ marginTop: 12 }}>
            {error}
          </div>
        )}
      </div>

      {loading && (
        <div style={{ marginTop: 12 }}><SkeletonCard lines={4} /></div>
      )}

      {output && (
        <div className="card" style={{ marginTop: 12 }}>
          <h3 style={{ color: "var(--cyan)" }}>Planner output</h3>
          {output.skipped && (
            <div className="dim">Skipped: {output.skipped}</div>
          )}
          {output.no_chain_possible && (
            <div className="dim">{output.reasoning || "No chain possible from these findings."}</div>
          )}
          {(output.plans || []).map((p, i) => (
            <div key={i} style={{ marginBottom: 16, paddingBottom: 12, borderBottom: "1px solid var(--border)" }}>
              <div style={{ color: "var(--text-0)", fontWeight: 700 }}>{p.name}</div>
              <div className="dim" style={{ fontSize: 11 }}>
                Objective: {p.objective} · Risk: {p.risk_to_target} · Est. success: {Math.round((p.estimated_success || 0) * 100)}%
              </div>
              <ol style={{ marginTop: 6 }}>
                {(p.steps || []).map((s) => (
                  <li key={s.order}>
                    <code>{s.technique_id}</code> on <code>{s.target_host}</code>: {s.description}
                    {" "}<span className="dim">({Math.round((s.confidence || 0) * 100)}%)</span>
                  </li>
                ))}
              </ol>
              {p.mitre_tactics && p.mitre_tactics.length > 0 && (
                <div className="dim" style={{ fontSize: 11 }}>MITRE tactics: {p.mitre_tactics.join(", ")}</div>
              )}
              {p.reasoning && (
                <div className="dim" style={{ fontSize: 11, marginTop: 4 }}>
                  Reasoning: {p.reasoning}
                </div>
              )}
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
