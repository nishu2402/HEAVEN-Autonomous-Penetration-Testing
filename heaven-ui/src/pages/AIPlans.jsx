// HEAVEN — AI Attack-Chain Planner page.
//
// Lets the operator paste a list of findings (or use the active engagement
// store) and ask the LLM-backed planner to propose attack chains.
//
// Backend: POST /api/ai/plan/run  →  PlannerOutput { plans: [...] }

import React, { useState } from "react";
import { AI, SIEM, Engagement } from "../api";
import { useJob } from "../context/Jobs.jsx";
import { SkeletonCard } from "../components/Skeleton.jsx";
import Markdown from "../components/Markdown.jsx";

export default function AIPlans() {
  const [findingsJson, setFindingsJson] = useState("");
  const [objective, setObjective]       = useState("");
  // Tracked globally so an LLM planning run survives page navigation.
  const { loading, result: output, error: jobError, start } = useJob("aiplans");
  const [error, setError]               = useState(null);   // load / validation
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

  function plan() {
    setError(null);
    let parsed;
    try {
      parsed = JSON.parse(findingsJson || "[]");
    } catch (e) {
      setError(`Findings JSON is invalid: ${e.message}`);
      return;
    }
    start({ label: "AI attack planner", kind: "aiplans", path: "/ai-plans" },
          () => AI.plan(parsed, [], objective));
  }

  return (
    <div className="page">
      <div className="card">
        <h2 style={{ color: "var(--text-0)", marginTop: 0 }}>✦ AI Attack-Chain Planner</h2>
        <p className="page-lead">
          Proposes multi-step attack chains from a list of findings. HEAVEN
          builds a plan on its own — adding an AI provider key
          (<code>ANTHROPIC_API_KEY</code>, <code>OPENAI_API_KEY</code> or{" "}
          <code>GEMINI_API_KEY</code>) on the server enriches that reasoning
          with an LLM.
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

        {(error || jobError) && (
          <div className="error" style={{ marginTop: 12 }}>
            {error || jobError}
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
            <div className="dim">
              AI enrichment is unavailable — add an AI provider key in Settings
              to enrich these plans with an LLM.
            </div>
          )}
          {output.no_chain_possible && (
            output.reasoning
              ? <Markdown>{output.reasoning}</Markdown>
              : <div className="dim">No chain possible from these findings.</div>
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
                <div style={{ marginTop: 4 }}>
                  <div className="dim" style={{ fontSize: 11, marginBottom: 2 }}>Reasoning</div>
                  <Markdown>{p.reasoning}</Markdown>
                </div>
              )}
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
